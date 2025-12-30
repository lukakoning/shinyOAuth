#' Parse JWT payload (unsigned validation only)
#'
#' @keywords internal
#' @noRd
parse_jwt_payload <- function(jwt) {
  parts <- strsplit(jwt, "\\.")[[1]]
  if (length(parts) < 2) {
    err_parse("Invalid JWT format")
  }
  payload_raw <- base64url_decode(parts[2])
  # Normalize JSON parse failures to a consistent parse error class
  tryCatch(
    jsonlite::fromJSON(payload_raw, simplifyVector = TRUE),
    error = function(e) {
      err_parse(c(
        "Failed to parse JWT payload JSON",
        "i" = conditionMessage(e)
      ))
    }
  )
}

#' Internal: Parse JWT header (no validation)
#'
#' @keywords internal
#' @noRd
parse_jwt_header <- function(jwt) {
  parts <- strsplit(jwt, "\\.")[[1]]
  if (length(parts) < 2) {
    err_parse("Invalid JWT format")
  }
  header_raw <- base64url_decode(parts[1])
  # Normalize JSON parse failures to a consistent parse error class
  tryCatch(
    jsonlite::fromJSON(header_raw, simplifyVector = TRUE),
    error = function(e) {
      err_parse(c(
        "Failed to parse JWT header JSON",
        "i" = conditionMessage(e)
      ))
    }
  )
}

#' Internal: validate ID token
#'
#' This function validates an ID token, by checking its signature and claims.
#'
#' @keywords internal
#' @noRd
validate_id_token <- function(client, id_token, expected_nonce = NULL) {
  S7::check_is_S7(client, class = OAuthClient)
  stopifnot(is_valid_string(id_token))

  prov <- client@provider
  issuer <- prov@issuer
  allowed_algs <- toupper(
    prov@allowed_algs %||%
      c(
        "RS256",
        "RS384",
        "RS512",
        "PS256",
        "PS384",
        "PS512",
        "ES256",
        "ES384",
        "ES512",
        "EdDSA"
      )
  )
  leeway <- prov@leeway %||% getOption("shinyOAuth.leeway", 30)
  jwks_cache <- prov@jwks_cache
  pins <- prov@jwks_pins %||% character()
  pin_mode <- prov@jwks_pin_mode %||% "any"
  client_id <- client@client_id
  client_secret <- client@client_secret
  skip_signature <- isTRUE(allow_skip_signature())

  # Parse header to inspect alg/kid; map all parse failures to ID token errors
  header <- tryCatch(
    parse_jwt_header(id_token),
    error = function(e) {
      err_id_token(c(
        "Invalid ID token: cannot parse header",
        "i" = conditionMessage(e)
      ))
    }
  )
  # Defense-in-depth: if a typ header is present, require it to be exactly
  # "JWT" per RFC 7519. Many providers omit typ; that's fine. Unknown types
  # (e.g., JWE or vendor-specific values) are rejected to avoid accepting
  # unintended container types.
  typ <- header$typ %||% NULL
  if (!is.null(typ)) {
    if (
      !(is.character(typ) &&
        length(typ) == 1L &&
        identical(toupper(typ), "JWT"))
    ) {
      err_id_token(paste0(
        "JWT typ header invalid: expected 'JWT' when present, got ",
        as.character(typ)
      ))
    }
  }
  alg <- toupper(header$alg %||% err_id_token("JWT header missing alg"))
  kid <- header$kid %||% NULL
  if (!isTRUE(skip_signature) && !(alg %in% allowed_algs)) {
    err_id_token(paste0("JWT alg not allowed by provider: ", header$alg))
  }

  # Signature verification
  payload <- NULL
  if (!isTRUE(skip_signature)) {
    # All asymmetric algs are verified using the provider JWKS (RSA/EC/OKP)
    if (
      alg %in%
        c(
          "RS256",
          "RS384",
          "RS512",
          "PS256",
          "PS384",
          "PS512",
          "ES256",
          "ES384",
          "ES512",
          "EDDSA"
        )
    ) {
      jwks <- fetch_jwks(
        issuer,
        jwks_cache,
        pins = pins,
        pin_mode = pin_mode,
        provider = prov
      )
      verified <- FALSE
      # Determine candidate keys with safer kid handling
      if (!is.null(kid)) {
        # If header has kid, try only matching keys. If none match, refresh JWKS once and try again.
        kid_keys <- select_candidate_jwks(jwks, header_alg = alg, kid = kid)
        if (length(kid_keys) == 0L) {
          did_force_refresh <- FALSE
          if (isTRUE(jwks_force_refresh_allowed(
            issuer,
            jwks_cache,
            pins = pins,
            pin_mode = pin_mode,
            min_interval = 30
          ))) {
            did_force_refresh <- TRUE
            jwks <- fetch_jwks(
              issuer,
              jwks_cache,
              force_refresh = TRUE,
              pins = pins,
              pin_mode = pin_mode,
              provider = prov
            )
            kid_keys <- select_candidate_jwks(jwks, header_alg = alg, kid = kid)
          }
        }
        if (length(kid_keys) == 0L) {
          if (isTRUE(did_force_refresh)) {
            err_id_token("No JWKS key matches kid")
          } else {
            err_id_token("No JWKS key matches kid (JWKS refresh rate-limited)")
          }
        }
        keys <- kid_keys
      } else {
        # No kid: use usual candidate filtering (use='sig', alg preference)
        keys <- select_candidate_jwks(jwks, header_alg = alg, kid = NULL)
      }

      # Defense-in-depth: filter by key type/curve compatibility with alg
      jwk_compatible <- function(k, alg0) {
        kty <- toupper(k$kty %||% "")
        crv <- toupper(k$crv %||% "")
        switch(
          alg0,
          RS256 = kty == "RSA",
          RS384 = kty == "RSA",
          RS512 = kty == "RSA",
          PS256 = kty == "RSA",
          PS384 = kty == "RSA",
          PS512 = kty == "RSA",
          ES256 = (kty == "EC" && crv == "P-256"),
          ES384 = (kty == "EC" && crv == "P-384"),
          ES512 = (kty == "EC" && crv == "P-521"),
          EDDSA = (kty == "OKP" && crv %in% c("ED25519", "ED448")),
          FALSE
        )
      }
      keys <- Filter(function(k) jwk_compatible(k, alg), keys)

      # Treat JWK alg as a hard constraint when present to avoid misconfig
      keys <- Filter(
        function(k) {
          ka <- k$alg %||% NULL
          is.null(ka) || toupper(ka) == alg
        },
        keys
      )
      if (length(keys) == 0L) {
        err_id_token("No compatible JWKS keys for alg")
      }

      # Attempt verification only with the selected keys (no fallback to all when kid is present)
      for (jk in keys) {
        pub <- try(jwk_to_pubkey(jk), silent = TRUE)
        if (inherits(pub, "try-error")) {
          next
        }
        dec <- try(jose::jwt_decode_sig(id_token, pub), silent = TRUE)
        if (!inherits(dec, "try-error")) {
          payload <- dec
          verified <- TRUE
          break
        }
      }
      if (!isTRUE(verified)) err_id_token("ID token signature invalid")
    } else if (alg %in% c("HS256", "HS384", "HS512")) {
      # Gate HMAC verification behind an explicit, opt-in option
      allow_hs <- isTRUE(getOption("shinyOAuth.allow_hs", FALSE))

      if (!allow_hs) {
        err_id_token(c(
          "x" = "HS* requires `options(shinyOAuth.allow_hs = TRUE)`",
          "i" = paste0(
            "Enable only when your client_secret is strictly server-side, ",
            "is rotated regularly, and you accept the trade-offs of symmetric tokens"
          )
        ))
      }

      if (!is_valid_string(client_secret)) {
        err_input("HS* validation requires client_secret")
      }

      if (nchar(client_secret, type = "bytes") < 32) {
        err_input("HS* algorithms require client_secret >= 32 bytes")
      }

      # jose::jwt_decode_hmac autodetects HS256/384/512 from header
      dec <- try(jose::jwt_decode_hmac(id_token, client_secret), silent = TRUE)
      if (inherits(dec, "try-error")) {
        err_id_token("ID token HMAC invalid")
      }
      payload <- dec
    } else {
      err_id_token(paste0("Unsupported JWT alg: ", header$alg))
    }
  }
  if (is.null(payload)) {
    # Map payload parse failures to ID token errors for consistency
    payload <- tryCatch(
      parse_jwt_payload(id_token),
      error = function(e) {
        err_id_token(c(
          "Invalid ID token: cannot parse payload",
          "i" = conditionMessage(e)
        ))
      }
    )
  }

  # Claims checks
  # Normalize issuer comparison by trimming a single trailing slash on both
  # sides to be robust to providers that vary only by a terminal '/'.
  # We still require an exact, case-sensitive match after normalization.
  if (!is_valid_string(payload$iss)) {
    err_id_token("Issuer mismatch/invalid")
  }
  iss_expected <- rtrim_slash(issuer)
  iss_actual <- rtrim_slash(payload$iss)
  if (!identical(iss_actual, iss_expected)) {
    err_id_token("Issuer mismatch/invalid")
  }
  aud <- payload$aud
  # OIDC: aud MAY be a string or an array of strings. Accept length >= 1.
  if (
    !(is.character(aud) &&
      length(aud) >= 1 &&
      !anyNA(aud) &&
      all(nzchar(aud)))
  ) {
    err_id_token("Audience invalid")
  }
  if (!(client_id %in% aud)) {
    err_id_token("Audience does not include client_id")
  }
  if (!is_valid_string(payload$sub)) {
    err_id_token("ID token missing sub claim")
  }
  if (is.null(payload$exp)) {
    err_id_token("ID token missing exp claim")
  }
  # Validate temporal claims are single, finite numerics before arithmetic
  is_single_finite_number <- function(x) {
    is.numeric(x) && length(x) == 1 && is.finite(x) && !is.na(x)
  }
  if (!is_single_finite_number(payload$exp)) {
    err_id_token("exp claim must be a single finite number")
  }
  exp_val <- as.numeric(payload$exp)

  # Use integer seconds to minimize flakiness vs. boundary tests
  now <- floor(as.numeric(Sys.time()))
  lwe <- as.numeric(leeway %||% 0)
  if (!is.finite(lwe) || is.na(lwe) || length(lwe) != 1) {
    lwe <- 0
  }
  if (exp_val < (now - lwe)) {
    err_id_token("ID token expired")
  }
  # OIDC Core requires iat to be present on ID Tokens
  if (is.null(payload$iat)) {
    err_id_token("ID token missing iat claim")
  }
  if (!is_single_finite_number(payload$iat)) {
    err_id_token("iat claim must be a single finite number when present")
  }
  iat_val <- as.numeric(payload$iat)
  if ((iat_val - lwe) >= now) {
    err_id_token("ID token issued in the future")
  }
  if (!is.null(payload$nbf)) {
    if (!is_single_finite_number(payload$nbf)) {
      err_id_token("nbf claim must be a single finite number when present")
    }
    nbf_val <- as.numeric(payload$nbf)
    # Token is not yet valid when the not-before time is beyond allowed clock skew.
    # Use a >= comparison to avoid test flakiness around second boundaries.
    if (nbf_val >= (now + lwe)) {
      err_id_token("ID token not yet valid (nbf)")
    }
  }
  if (is_valid_string(expected_nonce)) {
    if (is.null(payload$nonce)) {
      err_id_token("ID token missing nonce claim")
    }
    if (!identical(payload$nonce, expected_nonce)) {
      err_id_token("ID token nonce mismatch")
    }
  }
  # Authorized party (azp) handling per OIDC Core §2: if aud has multiple
  # entries, azp MUST be present and equal to the client_id. If azp is present
  # in any case, it MUST equal client_id.
  if (!is.null(payload$azp)) {
    if (!identical(payload$azp, client_id)) {
      err_id_token("azp claim does not match client_id")
    }
  } else if (length(aud) > 1) {
    err_id_token("Multiple audiences but azp claim missing")
  }
  invisible(payload)
}

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

  style <- client@provider@token_auth_style %||% "header"
  alg_cfg <- client@client_assertion_alg %||% NA_character_
  alg_chr <- as.character(alg_cfg[[1]])
  alg <- toupper(ifelse(is.na(alg_chr), "", alg_chr))
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
  if (!is.finite(ttl) || is.na(ttl) || ttl < 60L) {
    ttl <- 120L
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
    if (is.character(kid) && length(kid) == 1L && nzchar(kid)) {
      header$kid <- kid
    }
  }

  if (identical(style, "client_secret_jwt")) {
    # Map HS* to jose size parameter
    size <- switch(
      alg,
      HS256 = 256,
      HS384 = 384,
      HS512 = 512,
      err_config(
        c(
          "x" = "Unsupported HMAC alg for client_secret_jwt",
          "!" = paste0("Got alg: ", as.character(alg)),
          "i" = "Supported values are HS256, HS384, HS512"
        ),
        context = list(
          phase = "build_client_assertion",
          style = "client_secret_jwt",
          alg = as.character(alg)
        )
      )
    )
    secret <- client@client_secret %||%
      err_config("client_secret missing for client_secret_jwt")
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
    # Validate alg compatibility with key by attempting a dry-run sign if an
    # explicit alg was provided (or selected by default logic). Surface a
    # configuration error with context instead of a cryptic jose error.
    clm <- do.call(jose::jwt_claim, claims)
    sig_try <- try(
      jose::jwt_encode_sig(clm, key = key, header = header),
      silent = TRUE
    )
    if (inherits(sig_try, "try-error")) {
      err_config(
        c(
          "x" = "client_assertion_alg is incompatible with the provided private key",
          "i" = paste0(
            "Tried alg '",
            header$alg,
            "' with your key but signing failed; ",
            "choose a compatible algorithm (e.g., RS256 for RSA, ES256/384/512 for EC, EdDSA for Ed25519)"
          )
        ),
        context = list(alg = header$alg)
      )
    }
    return(sig_try)
  }

  err_config(
    c("x" = "build_client_assertion called for non-JWT auth style"),
    context = list(style = as.character(style))
  )
}

#' Normalize a client private key input to an openssl::key
#'
#' Accepts either an openssl::key-like object or a PEM string. Password-protected
#' keys are not supported in this helper; supply an openssl::key unlocked in R
#' if needed.
#' @keywords internal
#' @noRd
normalize_private_key_input <- function(key) {
  if (inherits(key, "key") || inherits(key, "rsa") || inherits(key, "ecdsa")) {
    return(key)
  }
  if (is.character(key) && length(key) >= 1L) {
    pem <- paste(key, collapse = "\n")
    k <- try(openssl::read_key(text = pem), silent = TRUE)
    if (inherits(k, "try-error")) {
      err_config("Failed to parse client_private_key PEM")
    }
    return(k)
  }
  err_config("client_private_key must be an openssl::key or PEM string")
}

#' Choose a default JWT alg compatible with a given private key
#'
#' For RSA keys, prefer RS256. For EC keys, try ES256/384/512 to match P-256/384/521.
#' For OKP/Ed25519-like keys, try EdDSA. Falls back to an eager configuration
#' error when none of the candidates work, prompting the caller to set
#' client_assertion_alg explicitly.
#' @keywords internal
#' @noRd
choose_default_alg_for_private_key <- function(key) {
  # Try to infer from class first; if ambiguous, probe by attempting to sign
  # a minimal claim with candidate algorithms.
  candidates <- NULL
  if (inherits(key, "rsa")) {
    candidates <- c("RS256", "PS256")
  } else if (inherits(key, "ecdsa")) {
    candidates <- c("ES256", "ES384", "ES512")
  } else {
    # Unknown key class: try EdDSA first (Ed25519/Ed448), then common RSA/EC
    candidates <- c("EdDSA", "RS256", "ES256", "PS256", "ES384", "ES512")
  }
  clm <- jose::jwt_claim(jti = random_urlsafe(16), iat = as.integer(Sys.time()))
  for (alg in candidates) {
    hdr <- list(typ = "JWT", alg = alg)
    try_sig <- try(
      jose::jwt_encode_sig(clm, key = key, header = hdr),
      silent = TRUE
    )
    if (!inherits(try_sig, "try-error")) {
      return(alg)
    }
  }
  err_config(
    c(
      "x" = "Could not determine a compatible default client_assertion_alg for the provided private key",
      "i" = "Set OAuthClient@client_assertion_alg explicitly to a supported value"
    )
  )
}
