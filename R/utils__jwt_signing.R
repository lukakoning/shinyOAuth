# This file contains the outbound JWT signing helpers used for client
# assertions, signed authorization requests, and related signing decisions.
# Use them when shinyOAuth must create a JWT, choose a compatible signing
# algorithm, or normalize private-key input before signing.

# 1 Outbound JWT signing helpers ------------------------------------------

## 1.1 Client assertions ---------------------------------------------------

#' Build and sign OAuth client assertion (RFC 7523)
#'
#' Constructs a JWT with claims suitable for `client_secret_jwt` or
#' `private_key_jwt` token endpoint authentication and returns the compact
#' serialization. The JWT uses the client's configured credentials to sign
#' the assertion. Header will include alg and optional kid (when provided).
#'
#' Claims:
#'  - iss: client_id
#'  - sub: client_id
#'  - aud: token endpoint URL (passed as `aud`)
#'  - iat: current epoch seconds
#'  - exp: iat + ttl (default 120s; override with options(shinyOAuth.client_assertion_ttl))
#'  - jti: random unique identifier
#'
#' @keywords internal
#' @noRd
build_client_assertion <- function(client, aud) {
  S7::check_is_S7(client, class = OAuthClient)
  stopifnot(is_valid_string(aud))

  style <- normalize_token_auth_style(
    client@provider@token_auth_style %||% "header"
  )
  alg_cfg <- client@client_assertion_alg %||% NA_character_
  # Defense-in-depth: ensure scalar before indexing (validator should already
  # enforce this, but runtime callers may bypass validation).
  if (!is.character(alg_cfg) || length(alg_cfg) != 1L) {
    alg_cfg <- NA_character_ # nolint
  }
  alg_chr <- as.character(alg_cfg)
  alg <- canonicalize_jws_alg(alg_chr)
  # Resolve default algorithm with key-aware logic for private_key_jwt.
  # Previous behavior always fell back to RS256 which breaks EC/OKP keys.
  if (!nzchar(alg)) {
    if (identical(style, "client_secret_jwt")) {
      alg <- "HS256"
    } else if (identical(style, "private_key_jwt")) {
      # Pick a sensible default based on the private key type/curve.
      key0 <- normalize_private_key_input(client@client_private_key)
      alg <- choose_default_alg_for_private_key(key0)
    }
  }
  # TTL (seconds) for client assertion; default 2 minutes
  ttl <- suppressWarnings(as.integer(getOption(
    "shinyOAuth.client_assertion_ttl",
    120L
  )))
  if (!is.finite(ttl) || is.na(ttl)) {
    ttl <- 120L
  } else if (ttl < 60L) {
    ttl <- 60L
  } else if (ttl > 300L) {
    rlang::warn(
      c(
        "!" = "shinyOAuth.client_assertion_ttl above 300 seconds is not allowed; clamping to 300 seconds",
        "i" = paste0("Configured value: ", ttl)
      ),
      .frequency = "once",
      .frequency_id = "client-assertion-ttl-max"
    )
    ttl <- 300L
  }
  now <- floor(as.numeric(Sys.time()))
  claims <- list(
    iss = client@client_id,
    sub = client@client_id,
    aud = aud,
    iat = now,
    exp = now + ttl,
    jti = random_urlsafe(32)
  )

  # Header base; jose helpers set alg automatically for HS* (via size) but we
  # include explicit alg to be clear. Include kid if configured for private keys.
  header <- list(
    typ = "JWT",
    alg = alg
  )
  if (identical(style, "private_key_jwt")) {
    kid <- client@client_private_key_kid %||% NA_character_
    if (is.character(kid) && length(kid) == 1L && !is.na(kid) && nzchar(kid)) {
      header$kid <- kid
    }
  }

  if (identical(style, "client_secret_jwt")) {
    min_secret_bytes <- min_hmac_key_bytes(alg)
    size <- min_secret_bytes * 8L
    secret <- client@client_secret %||%
      err_config("client_secret missing for client_secret_jwt")
    if (nchar(secret, type = "bytes") < min_secret_bytes) {
      err_config(
        paste0(
          "client_secret_jwt with client_assertion_alg '",
          alg,
          "' requires client_secret >= ",
          min_secret_bytes,
          " bytes"
        )
      )
    }
    # Build a proper jwt_claim from named list via do.call
    clm <- do.call(jose::jwt_claim, claims)
    # jose will set alg based on size, but we also pass header to include typ
    jwt <- jose::jwt_encode_hmac(
      clm,
      secret = secret,
      header = header,
      size = size
    )
    return(jwt)
  }

  if (identical(style, "private_key_jwt")) {
    key <- normalize_private_key_input(client@client_private_key)
    clm <- do.call(jose::jwt_claim, claims)
    # Hard-fail impossible alg/key pairs before signing. jose::jwt_encode_sig()
    # can otherwise emit mismatched JOSE alg headers instead of rejecting them.
    if (!private_key_can_sign_jws_alg(key, alg, typ = "JWT")) {
      err_config(
        c(
          "x" = paste0(
            "client_assertion_alg '",
            alg,
            "' is incompatible with the provided private key"
          )
        ),
        context = list(
          phase = "build_client_assertion",
          alg = alg
        )
      )
    }
    jwt <- try(
      jose::jwt_encode_sig(clm, key = key, header = header),
      silent = TRUE
    )
    if (inherits(jwt, "try-error")) {
      err_config(
        c(
          "x" = "Failed to sign client assertion",
          "i" = paste0(
            "Tried alg '",
            alg,
            "' with the configured private key"
          )
        ),
        context = list(
          phase = "build_client_assertion",
          alg = alg
        )
      )
    }
    return(jwt)
  }

  err_config(
    c("x" = "build_client_assertion called for non-JWT auth style"),
    context = list(style = as.character(style))
  )
}

#' Resolve the audience (`aud`) value for a JWT client assertion.
#'
#' Uses an explicit client override when present, otherwise uses the exact URL
#' on the httr2 request (so any URL normalization/modification stays consistent
#' with the audience claim). Falls back to the provider token_url for non-httr2
#' request doubles used in tests.
#'
#' @keywords internal
#' @noRd
resolve_client_assertion_audience <- function(client, req) {
  S7::check_is_S7(client, class = OAuthClient)

  override <- client@client_assertion_audience %||% NA_character_
  # Defense-in-depth: ensure scalar before indexing.
  if (!is.character(override) || length(override) != 1L) {
    override <- NA_character_ # nolint
  }
  override_chr <- as.character(override)
  if (!is.na(override_chr) && nzchar(override_chr)) {
    return(override_chr)
  }

  if (inherits(req, "httr2_request")) {
    url0 <- req$url %||% NA_character_
    url_chr <- as.character(url0[[1]])
    if (!is.na(url_chr) && nzchar(url_chr)) {
      return(url_chr)
    }
  }

  client@provider@token_url
}

## 1.2 Signed authorization requests --------------------------------------

#' Resolve the signing algorithm for a signed authorization request.
#'
#' @keywords internal
#' @noRd
resolve_authorization_request_signing_alg <- function(client) {
  S7::check_is_S7(client, class = OAuthClient)

  alg_cfg <- client@authorization_request_signing_alg %||% NA_character_
  if (!is.character(alg_cfg) || length(alg_cfg) != 1L) {
    alg_cfg <- NA_character_
  }
  alg <- canonicalize_jws_alg(alg_cfg)

  allowed_hmac <- c("HS256", "HS384", "HS512")
  allowed_asym <- c(
    "RS256",
    "ES256",
    "ES384",
    "ES512"
  )

  if (!nzchar(alg)) {
    if (!is.null(client@client_private_key)) {
      key0 <- normalize_private_key_input(client@client_private_key)
      return(choose_default_alg_for_private_key(key0))
    }
    if (!is_valid_string(client@client_secret)) {
      err_config(
        "authorization_request_mode = 'request' requires client_private_key or client_secret"
      )
    }
    if (nchar(client@client_secret, type = "bytes") < 32) {
      err_config(
        paste(
          "authorization_request_mode = 'request' requires client_secret >= 32 bytes",
          "when no client_private_key is configured"
        )
      )
    }
    return("HS256")
  }

  if (identical(toupper(alg), "NONE")) {
    err_config("authorization_request_signing_alg = 'none' is not supported")
  }

  if (alg %in% allowed_hmac) {
    if (!is_valid_string(client@client_secret)) {
      err_config("HS* authorization_request_signing_alg requires client_secret")
    }
    if (nchar(client@client_secret, type = "bytes") < 32) {
      err_config(
        "HS* authorization_request_signing_alg requires client_secret >= 32 bytes"
      )
    }
    return(alg)
  }

  if (alg %in% allowed_asym) {
    if (is.null(client@client_private_key)) {
      err_config(
        "asymmetric authorization_request_signing_alg requires client_private_key"
      )
    }
    return(alg)
  }

  err_config(paste0(
    "Unsupported authorization_request_signing_alg: ",
    as.character(alg)
  ))
}

#' Resolve the audience (`aud`) value for a signed authorization request.
#'
#' @keywords internal
#' @noRd
resolve_authorization_request_audience <- function(client) {
  S7::check_is_S7(client, class = OAuthClient)

  override <- client@authorization_request_audience %||% NA_character_
  if (!is.character(override) || length(override) != 1L) {
    override <- NA_character_
  }
  override_chr <- as.character(override)
  if (!is.na(override_chr) && nzchar(override_chr)) {
    return(override_chr)
  }

  provider_issuer <- client@provider@issuer %||% NA_character_
  if (is_valid_string(provider_issuer)) {
    return(provider_issuer)
  }

  auth_url <- client@provider@auth_url %||% NA_character_
  if (is_valid_string(auth_url)) {
    return(auth_url)
  }

  err_config(
    "Could not resolve an audience for the signed authorization request"
  )
}

## 1.3 Signing algorithm and key helpers ----------------------------------

#' Canonicalize a JWS alg name for JOSE headers.
#'
#' @keywords internal
#' @noRd
canonicalize_jws_alg <- function(alg) {
  if (!is.character(alg) || length(alg) != 1L) {
    return("")
  }

  alg_chr <- trimws(as.character(alg)[[1]])
  if (is.na(alg_chr) || !nzchar(alg_chr)) {
    return("")
  }

  alg_upper <- toupper(alg_chr)
  if (identical(alg_upper, "EDDSA")) {
    return("EdDSA")
  }

  alg_upper
}

#' Return the minimum HMAC key length in bytes for a JWS alg.
#'
#' @keywords internal
#' @noRd
min_hmac_key_bytes <- function(alg) {
  alg <- canonicalize_jws_alg(alg)

  switch(
    alg,
    HS256 = 32L,
    HS384 = 48L,
    HS512 = 64L,
    err_config(paste0("Unsupported HMAC alg for key length check: ", alg))
  )
}

#' Check whether a private key can sign a JWT with a given alg.
#'
#' @keywords internal
#' @noRd
private_key_can_sign_jws_alg <- function(key, alg, typ = "JWT") {
  alg <- canonicalize_jws_alg(alg)

  if (inherits(key, "rsa")) {
    return(identical(alg, "RS256"))
  }

  if (inherits(key, "ecdsa")) {
    jwk <- try(
      jsonlite::fromJSON(jose::write_jwk(key), simplifyVector = TRUE),
      silent = TRUE
    )
    if (!inherits(jwk, "try-error") && is.list(jwk)) {
      crv <- jwk$crv %||% NA_character_
      if (identical(crv, "P-256")) {
        return(identical(alg, "ES256"))
      }
      if (identical(crv, "P-384")) {
        return(identical(alg, "ES384"))
      }
      if (identical(crv, "P-521")) {
        return(identical(alg, "ES512"))
      }
    }

    return(alg %in% c("ES256", "ES384", "ES512"))
  }

  if (inherits(key, "ed25519") || inherits(key, "ed448")) {
    return(FALSE)
  }

  clm <- jose::jwt_claim(jti = "compatibility-check", iat = 1L)
  hdr <- list(typ = typ, alg = alg)
  sig_try <- try(
    jose::jwt_encode_sig(clm, key = key, header = hdr),
    silent = TRUE
  )

  !inherits(sig_try, "try-error")
}

#' Encode a compact HMAC JWS while preserving a custom JOSE header.
#'
#' @keywords internal
#' @noRd
encode_hmac_jwt_with_header <- function(
  claims,
  secret,
  header,
  size,
  alg = NULL
) {
  if (!is.list(claims) || !length(claims)) {
    err_config("encode_hmac_jwt_with_header requires a non-empty claims list")
  }
  if (!is_valid_string(secret)) {
    err_config("encode_hmac_jwt_with_header requires a non-empty secret")
  }
  if (!is.list(header) || !length(header)) {
    err_config("encode_hmac_jwt_with_header requires a non-empty header list")
  }

  alg <- canonicalize_jws_alg(alg)
  if (!nzchar(alg)) {
    alg <- switch(
      as.character(size),
      `256` = "HS256",
      `384` = "HS384",
      `512` = "HS512",
      err_config(paste0(
        "Unsupported HMAC signing size for encode_hmac_jwt_with_header: ",
        as.character(size)
      ))
    )
  }

  min_secret_bytes <- min_hmac_key_bytes(alg)
  if (nchar(secret, type = "bytes") < min_secret_bytes) {
    err_config(paste0(
      alg,
      " requires client_secret >= ",
      min_secret_bytes,
      " bytes"
    ))
  }

  header_json <- jsonlite::toJSON(
    header,
    auto_unbox = TRUE,
    null = "null",
    digits = NA
  )
  payload_json <- jsonlite::toJSON(
    claims,
    auto_unbox = TRUE,
    null = "null",
    digits = NA
  )

  encoded_header <- base64url_encode(charToRaw(enc2utf8(header_json)))
  encoded_payload <- base64url_encode(charToRaw(enc2utf8(payload_json)))
  signing_input <- paste0(encoded_header, ".", encoded_payload)
  key_raw <- charToRaw(enc2utf8(secret))

  signature_raw <- switch(
    as.character(size),
    `256` = openssl::sha256(charToRaw(signing_input), key = key_raw),
    `384` = openssl::sha384(charToRaw(signing_input), key = key_raw),
    `512` = openssl::sha512(charToRaw(signing_input), key = key_raw),
    err_config(paste0(
      "Unsupported HMAC signing size for encode_hmac_jwt_with_header: ",
      as.character(size)
    ))
  )

  paste0(signing_input, ".", base64url_encode(signature_raw))
}

## 1.4 Authorization request object signing -------------------------------

#' Build and sign a JWT-secured authorization request (RFC 9101).
#'
#' @keywords internal
#' @noRd
build_authorization_request_object <- function(client, params) {
  S7::check_is_S7(client, class = OAuthClient)

  if (!is.list(params) || !length(params)) {
    err_config(
      "build_authorization_request_object requires a non-empty params list"
    )
  }

  param_names <- tolower(trimws(names(params) %||% character(0)))
  if (any(param_names %in% c("request", "request_uri"))) {
    err_config(
      "Authorization request parameters must not already include request or request_uri"
    )
  }

  alg <- resolve_authorization_request_signing_alg(client)
  aud <- resolve_authorization_request_audience(client)
  now <- floor(as.numeric(Sys.time()))
  ttl <- 120L

  claims_param <- params$claims %||% NULL
  if (
    is.character(claims_param) &&
      length(claims_param) == 1L &&
      nzchar(claims_param)
  ) {
    parsed_claims <- tryCatch(
      jsonlite::fromJSON(claims_param, simplifyVector = FALSE),
      error = function(...) NULL
    )
    if (is.list(parsed_claims)) {
      params$claims <- parsed_claims
    }
  }

  params[intersect(
    names(params) %||% character(0),
    c("iss", "aud", "iat", "exp", "jti")
  )] <- NULL

  claims <- compact_list(c(
    params,
    list(
      iss = client@client_id,
      aud = aud,
      iat = now,
      exp = now + ttl,
      jti = random_urlsafe(32)
    )
  ))

  header <- list(
    typ = "oauth-authz-req+jwt",
    alg = alg
  )

  if (!(alg %in% c("HS256", "HS384", "HS512"))) {
    kid <- client@client_private_key_kid %||% NA_character_
    if (is.character(kid) && length(kid) == 1L && !is.na(kid) && nzchar(kid)) {
      header$kid <- kid
    }
  }

  clm <- do.call(jose::jwt_claim, claims)

  if (alg %in% c("HS256", "HS384", "HS512")) {
    size <- min_hmac_key_bytes(alg) * 8L

    return(encode_hmac_jwt_with_header(
      claims = claims,
      secret = client@client_secret,
      header = header,
      size = size,
      alg = alg
    ))
  }

  key <- normalize_private_key_input(client@client_private_key)
  if (!private_key_can_sign_jws_alg(key, alg, typ = "oauth-authz-req+jwt")) {
    err_config(
      c(
        "x" = paste0(
          "authorization_request_signing_alg '",
          alg,
          "' is incompatible with the provided private key"
        )
      ),
      context = list(alg = alg)
    )
  }
  jwt <- try(
    jose::jwt_encode_sig(clm, key = key, header = header),
    silent = TRUE
  )
  if (inherits(jwt, "try-error")) {
    err_config(
      c(
        "x" = "Failed to sign authorization request object",
        "i" = paste0("Tried alg '", alg, "' with the configured private key")
      ),
      context = list(alg = alg)
    )
  }

  jwt
}

## 1.5 Private key normalization ------------------------------------------

#' Normalize a client private key input to an openssl::key
#'
#' Accepts either an openssl::key-like object or a PEM string. Password-protected
#' keys are not supported in this helper; supply an openssl::key unlocked in R
#' if needed.
#' @keywords internal
#' @noRd
normalize_private_key_input <- function(key, arg_name = "client_private_key") {
  if (inherits(key, "key") || inherits(key, "rsa") || inherits(key, "ecdsa")) {
    return(key)
  }
  if (is.character(key) && length(key) >= 1L) {
    pem <- paste(key, collapse = "\n")
    k <- try(openssl::read_key(pem), silent = TRUE)
    if (inherits(k, "try-error")) {
      err_config(paste0("Failed to parse ", arg_name, " PEM"))
    }
    return(k)
  }
  err_config(paste0(arg_name, " must be an openssl::key or PEM string"))
}

#' Choose a default JWT alg compatible with a given private key
#'
#' For RSA keys, prefer RS256. For EC keys, try ES256/384/512 to match P-256/384/521.
#' Other key types are not currently supported for outbound JWT signing and
#' fall back to a configuration error.
#' @keywords internal
#' @noRd
choose_default_alg_for_private_key <- function(key) {
  if (inherits(key, "rsa")) {
    return("RS256")
  }

  if (inherits(key, "ecdsa")) {
    for (alg in c("ES256", "ES384", "ES512")) {
      if (private_key_can_sign_jws_alg(key, alg, typ = "JWT")) {
        return(alg)
      }
    }
  }

  # Unknown key classes still go through the same compatibility guard so we do
  # not infer defaults from jose::jwt_encode_sig() accepting impossible pairs.
  for (alg in c("RS256", "ES256", "ES384", "ES512")) {
    if (private_key_can_sign_jws_alg(key, alg, typ = "JWT")) {
      return(canonicalize_jws_alg(alg))
    }
  }
  err_config(
    c(
      "x" = "Could not determine a compatible default outbound JWT signing algorithm for the provided private key",
      "i" = paste(
        "shinyOAuth currently supports RSA and ECDSA private keys for",
        "outbound client assertions, request objects, and DPoP proofs"
      ),
      "i" = "EdDSA remains supported for inbound ID token verification"
    )
  )
}
