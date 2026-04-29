#' Internal DPoP helpers
#'
#' @keywords internal
#' @noRd
client_has_dpop <- function(client) {
  S7::check_is_S7(client, class = OAuthClient)
  !is.null(client@dpop_private_key)
}

#' @keywords internal
#' @noRd
is_dpop_token_type <- function(token_type) {
  if (!is.character(token_type) || length(token_type) != 1L) {
    return(FALSE)
  }
  identical(tolower(token_type[[1]] %||% ""), "dpop")
}

#' @keywords internal
#' @noRd
resolve_dpop_private_key <- function(client) {
  S7::check_is_S7(client, class = OAuthClient)

  if (!client_has_dpop(client)) {
    err_config("OAuthClient dpop_private_key is not configured")
  }

  normalize_private_key_input(
    client@dpop_private_key,
    arg_name = "dpop_private_key"
  )
}

#' @keywords internal
#' @noRd
resolve_dpop_alg <- function(client) {
  S7::check_is_S7(client, class = OAuthClient)

  alg_cfg <- client@dpop_signing_alg %||% NA_character_
  if (!is.character(alg_cfg) || length(alg_cfg) != 1L) {
    alg_cfg <- NA_character_
  }
  alg <- canonicalize_jws_alg(alg_cfg)
  if (nzchar(alg)) {
    return(alg)
  }

  choose_default_alg_for_private_key(resolve_dpop_private_key(client))
}

#' @keywords internal
#' @noRd
dpop_public_jwk <- function(key) {
  pub <- try(openssl::read_pubkey(openssl::write_pem(key)), silent = TRUE)
  if (inherits(pub, "try-error")) {
    err_config("Failed to derive public key from dpop_private_key")
  }

  jwk_json <- try(jose::jwk_write(pub), silent = TRUE)
  if (inherits(jwk_json, "try-error")) {
    err_config("Failed to serialize DPoP public key as JWK")
  }

  jwk <- try(
    jsonlite::fromJSON(jwk_json, simplifyVector = FALSE),
    silent = TRUE
  )
  if (inherits(jwk, "try-error") || !is.list(jwk)) {
    err_parse("Failed to parse serialized DPoP public JWK")
  }

  private_members <- intersect(
    names(jwk),
    c("d", "p", "q", "dp", "dq", "qi", "oth", "k")
  )
  if (length(private_members) > 0L) {
    err_config(
      "Serialized DPoP JWK unexpectedly contained private key material"
    )
  }

  jwk
}

#' @keywords internal
#' @noRd
dpop_target_uri <- function(url) {
  if (!is_valid_string(url)) {
    err_input("DPoP target URL must be a non-empty string")
  }

  parsed <- try(httr2::url_parse(url), silent = TRUE)
  if (inherits(parsed, "try-error")) {
    err_input("Failed to parse DPoP target URL")
  }

  parsed$query <- NULL
  parsed$fragment <- NULL
  httr2::url_build(parsed)
}

#' @keywords internal
#' @noRd
dpop_access_token_hash <- function(access_token) {
  stopifnot(is_valid_string(access_token))
  base64url_encode(openssl::sha256(charToRaw(enc2utf8(access_token))))
}

#' @keywords internal
#' @noRd
build_dpop_proof <- function(
  client,
  method,
  url,
  access_token = NULL,
  nonce = NULL
) {
  S7::check_is_S7(client, class = OAuthClient)

  key <- resolve_dpop_private_key(client)
  alg <- resolve_dpop_alg(client)
  if (!private_key_can_sign_jws_alg(key, alg, typ = "dpop+jwt")) {
    err_config(
      c(
        "x" = paste0(
          "dpop_signing_alg '",
          alg,
          "' is incompatible with the configured dpop_private_key"
        )
      ),
      context = list(alg = alg)
    )
  }
  header <- list(
    typ = "dpop+jwt",
    alg = alg,
    jwk = dpop_public_jwk(key)
  )

  kid <- client@dpop_private_key_kid %||% NA_character_
  if (is.character(kid) && length(kid) == 1L && !is.na(kid) && nzchar(kid)) {
    header$kid <- kid
  }

  claims <- list(
    jti = random_urlsafe(32),
    htm = toupper(as.character(method %||% "GET")[[1]]),
    htu = dpop_target_uri(as.character(url)[[1]]),
    iat = as.integer(floor(as.numeric(Sys.time())))
  )
  if (is_valid_string(access_token)) {
    claims$ath <- dpop_access_token_hash(access_token)
  }
  if (is_valid_string(nonce)) {
    claims$nonce <- nonce
  }

  clm <- do.call(jose::jwt_claim, claims)
  proof <- try(
    jose::jwt_encode_sig(clm, key = key, header = header),
    silent = TRUE
  )
  if (inherits(proof, "try-error")) {
    err_config(
      c(
        "x" = "Failed to sign DPoP proof",
        "i" = paste0(
          "Tried alg '",
          alg,
          "' with the configured dpop_private_key"
        )
      ),
      context = list(alg = alg)
    )
  }

  proof
}

#' @keywords internal
#' @noRd
req_add_dpop_proof <- function(
  req,
  client,
  access_token = NULL,
  nonce = NULL
) {
  if (!inherits(req, "httr2_request") || !client_has_dpop(client)) {
    return(req)
  }

  method <- req$method %||% "GET"
  url <- req$url %||% NA_character_
  if (!is_valid_string(url)) {
    err_config("Request URL missing while building DPoP proof")
  }

  httr2::req_headers(
    req,
    DPoP = build_dpop_proof(
      client,
      method = method,
      url = url,
      access_token = access_token,
      nonce = nonce
    )
  )
}

#' @keywords internal
#' @noRd
resp_get_dpop_nonce <- function(resp) {
  nonce <- try(httr2::resp_header(resp, "dpop-nonce"), silent = TRUE)
  if (inherits(nonce, "try-error") || !is_valid_string(nonce)) {
    return(NA_character_)
  }
  as.character(nonce)[1]
}

#' @keywords internal
#' @noRd
resp_is_dpop_nonce_challenge <- function(resp) {
  nonce <- resp_get_dpop_nonce(resp)
  if (!is_valid_string(nonce)) {
    return(FALSE)
  }

  body <- try(
    httr2::resp_body_json(resp, simplifyVector = TRUE),
    silent = TRUE
  )
  if (is.list(body)) {
    err <- body$error %||% NA_character_
    if (
      is.character(err) &&
        length(err) == 1L &&
        identical(err, "use_dpop_nonce")
    ) {
      return(TRUE)
    }
  }

  www_authenticate <- try(
    httr2::resp_header(resp, "www-authenticate"),
    silent = TRUE
  )
  !inherits(www_authenticate, "try-error") &&
    is_valid_string(www_authenticate) &&
    grepl(
      "use_dpop_nonce",
      www_authenticate,
      fixed = TRUE,
      ignore.case = TRUE
    )
}

#' @keywords internal
#' @noRd
req_with_dpop_retry <- function(
  req,
  client,
  access_token = NULL,
  idempotent = TRUE
) {
  if (!client_has_dpop(client)) {
    return(req_with_retry(req, idempotent = idempotent))
  }

  resp <- req_with_retry(
    req_add_dpop_proof(req, client, access_token = access_token),
    idempotent = idempotent
  )

  if (!resp_is_dpop_nonce_challenge(resp)) {
    return(resp)
  }

  nonce <- resp_get_dpop_nonce(resp)
  if (!is_valid_string(nonce)) {
    return(resp)
  }

  req_with_retry(
    req_add_dpop_proof(
      req,
      client,
      access_token = access_token,
      nonce = nonce
    ),
    idempotent = idempotent
  )
}
