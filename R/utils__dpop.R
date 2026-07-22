# This file contains helpers for DPoP proof creation, nonce challenges, and
# DPoP-aware request retries
# DPoP ties a token to a client key so a stolen token is harder to replay
# Used for creating DPoP proofs, handling DPoP nonce challenges, and retrying
# requests that need a fresh proof

# 1 DPoP helpers ---------------------------------------------------------------

## 1.1 Client and proof helpers ------------------------------------------------

#' Internal DPoP helpers
#'
#' Used when a client has configured DPoP proof-of-possession support.
#'
#' @param client OAuth client to inspect.
#' @return `TRUE` when the client has a configured DPoP private key; otherwise
#'   `FALSE`.
#' @keywords internal
#' @noRd
client_has_dpop <- function(client) {
  S7::check_is_S7(client, class = OAuthClient)
  !is.null(client@dpop_private_key)
}

# Cache DPoP nonces per issuing server, request class, and client key so later
# requests can reuse server-provided nonces across same-server endpoints without
# mixing token-endpoint and protected-resource nonce state. Bound the cache by
# age and entry count so long-lived apps do not accumulate unbounded state.
dpop_nonce_cache <- cachem::cache_mem(max_age = 300, max_n = 256, evict = "lru")
dpop_nonce_max_bytes <- 512L

#' Normalize a DPoP nonce value
#'
#' Used when DPoP nonces are read from headers, caches, or caller input.
#' RFC 9449 reuses the OAuth `scope-token` syntax (`1*NQCHAR`), so valid
#' values are ASCII visible characters excluding space, `"`, and `\\`.
#'
#' @param nonce Candidate DPoP nonce value.
#' @return A validated scalar nonce string, or `NA_character_` when invalid.
#' @keywords internal
#' @noRd
normalize_dpop_nonce <- function(nonce) {
  if (!is.character(nonce) || length(nonce) != 1L || is.na(nonce)) {
    return(NA_character_)
  }

  nonce <- as.character(nonce[[1]])
  if (!nzchar(nonce) || nchar(nonce, type = "bytes") > dpop_nonce_max_bytes) {
    return(NA_character_)
  }

  chars <- utf8ToInt(enc2utf8(nonce))
  if (!length(chars)) {
    return(NA_character_)
  }

  valid_chars <-
    chars == 0x21L |
    (chars >= 0x23L & chars <= 0x5BL) |
    (chars >= 0x5DL & chars <= 0x7EL)

  if (!all(valid_chars)) {
    return(NA_character_)
  }

  nonce
}

#' Build a DPoP nonce cache key
#'
#' Used when DPoP nonces are memoized between requests.
#'
#' @param client OAuth client carrying DPoP configuration.
#' @param url Request URL whose issuing server scopes the cached nonce.
#' @param request_kind Whether the nonce belongs to token-endpoint requests or
#'   protected-resource requests.
#' @return Cache key string, or `NA_character_` when no usable key can be
#'   derived.
#' @keywords internal
#' @noRd
dpop_nonce_cache_key <- function(
  client,
  url,
  request_kind = c("token", "resource")
) {
  if (
    !S7::S7_inherits(client, class = OAuthClient) || !client_has_dpop(client)
  ) {
    return(NA_character_)
  }
  if (!is_valid_string(url)) {
    return(NA_character_)
  }

  request_kind <- match.arg(request_kind)

  parsed <- try(httr2::url_parse(url), silent = TRUE)
  if (inherits(parsed, "try-error")) {
    return(NA_character_)
  }
  parsed[["query"]] <- NULL
  parsed[["fragment"]] <- NULL
  parsed[["path"]] <- "/"
  parsed[["scheme"]] <- tolower(parsed[["scheme"]] %||% "")
  parsed[["hostname"]] <- tolower(
    parsed[["hostname"]] %||% ""
  )

  port <- as.character(parsed[["port"]] %||% "")
  if (
    identical(parsed[["scheme"]], "https") &&
      identical(port, "443")
  ) {
    parsed[["port"]] <- NULL
  }
  if (identical(parsed[["scheme"]], "http") && identical(port, "80")) {
    parsed[["port"]] <- NULL
  }

  server_uri <- try(httr2::url_build(parsed), silent = TRUE)
  if (inherits(server_uri, "try-error") || !is_valid_string(server_uri)) {
    return(NA_character_)
  }

  client_id_key <- string_digest(client@client_id, key = NULL)
  dpop_jkt <- try(client_dpop_jkt(client), silent = TRUE)
  if (!is_valid_string(client_id_key) || inherits(dpop_jkt, "try-error")) {
    return(NA_character_)
  }
  if (!is_valid_string(dpop_jkt)) {
    return(NA_character_)
  }

  cache_input <- paste(
    server_uri,
    request_kind,
    client_id_key,
    dpop_jkt,
    sep = "::"
  )
  digest <- try(openssl::sha256(charToRaw(cache_input)), silent = TRUE)
  if (inherits(digest, "try-error")) {
    return(NA_character_)
  }

  paste0(sprintf("%02x", as.integer(digest)), collapse = "")
}

#' Read a cached DPoP nonce
#'
#' Used before building a DPoP proof when the caller did not supply a nonce.
#'
#' @param client OAuth client carrying DPoP configuration.
#' @param url Request URL whose issuing server scopes the cached nonce.
#' @param request_kind Whether the nonce belongs to token-endpoint requests or
#'   protected-resource requests.
#' @return Cached nonce string, or `NULL` when no usable cached nonce exists.
#' @keywords internal
#' @noRd
dpop_nonce_cache_get <- function(
  client,
  url,
  request_kind = c("token", "resource")
) {
  cache_key <- dpop_nonce_cache_key(client, url, request_kind = request_kind)
  if (!is_valid_string(cache_key)) {
    return(NULL)
  }
  if (!isTRUE(dpop_nonce_cache$exists(cache_key))) {
    return(NULL)
  }

  nonce <- dpop_nonce_cache$get(cache_key)
  nonce <- normalize_dpop_nonce(nonce)
  if (!is_valid_string(nonce)) {
    return(NULL)
  }

  nonce
}

#' Store a DPoP nonce in the cache
#'
#' Used after a DPoP-protected response provides a fresh nonce.
#'
#' @param client OAuth client carrying DPoP configuration.
#' @param url Request URL whose issuing server scopes the cached nonce.
#' @param request_kind Whether the nonce belongs to token-endpoint requests or
#'   protected-resource requests.
#' @param nonce DPoP nonce to cache.
#' @return Invisibly returns `nonce`.
#' @keywords internal
#' @noRd
dpop_nonce_cache_set <- function(
  client,
  url,
  nonce,
  request_kind = c("token", "resource")
) {
  cache_key <- dpop_nonce_cache_key(client, url, request_kind = request_kind)
  nonce <- normalize_dpop_nonce(nonce)
  if (!(is_valid_string(cache_key) && is_valid_string(nonce))) {
    return(invisible(nonce))
  }

  dpop_nonce_cache$set(cache_key, nonce)
  invisible(nonce)
}

#' Detect a DPoP token type
#'
#' Used after token responses are parsed.
#'
#' @param token_type Token type value returned by the provider.
#' @return `TRUE` when `token_type` denotes a DPoP-bound access token;
#'   otherwise `FALSE`.
#' @keywords internal
#' @noRd
is_dpop_token_type <- function(token_type) {
  if (!is.character(token_type) || length(token_type) != 1L) {
    return(FALSE)
  }
  identical(tolower(token_type[[1]] %||% ""), "dpop")
}

#' Resolve the configured DPoP private key
#'
#' Used before DPoP proofs are signed.
#'
#' @param client OAuth client carrying DPoP configuration.
#' @return Normalized private key object.
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

#' Compute the configured DPoP JWK thumbprint
#'
#' Used when DPoP-bound tokens must be rebound to the locally configured
#' private key.
#'
#' @param client OAuth client carrying DPoP configuration.
#' @return Base64url-encoded RFC 7638 thumbprint string.
#' @keywords internal
#' @noRd
client_dpop_jkt <- function(client) {
  S7::check_is_S7(client, class = OAuthClient)

  compute_jwk_thumbprint(
    dpop_public_jwk(resolve_dpop_private_key(client))
  )
}

#' Extract cnf.jkt from a token-like input
#'
#' Used when DPoP-bound access tokens must be rebound to a local key.
#'
#' @param token Optional [OAuthToken] object or raw access-token string.
#' @param access_token Optional raw access-token string.
#' @param cnf Optional explicit cnf claim data.
#' @return `cnf$jkt` as a scalar string, or `NA_character_` when absent.
#' @keywords internal
#' @noRd
token_cnf_jkt <- function(token = NULL, access_token = NULL, cnf = NULL) {
  if (S7::S7_inherits(token, class = OAuthToken)) {
    cnf <- token@cnf
    access_token <- token@access_token
  } else if (is_valid_string(token)) {
    access_token <- token
  }

  cnf <- resolve_token_cnf(
    cnf = cnf,
    access_token = access_token
  )
  dpop_jkt <- cnf[["jkt"]] %||% NA_character_
  if (!is_valid_string(dpop_jkt)) {
    return(NA_character_)
  }

  dpop_jkt
}

#' Detect whether DPoP cnf.jkt was observable on a token surface
#'
#' Used by strict DPoP validation to distinguish opaque access tokens that do
#' not expose confirmation data from JWT or introspection-based surfaces that
#' should reveal a `cnf$jkt` binding when one exists.
#'
#' @param access_token Optional raw access-token string.
#' @param cnf Optional explicit cnf claim data.
#' @param introspection_result Optional introspection payload.
#' @return `TRUE` when token confirmation data was observable; otherwise
#'   `FALSE`.
#' @keywords internal
#' @noRd
token_dpop_cnf_observable <- function(
  access_token = NULL,
  cnf = NULL,
  introspection_result = NULL
) {
  if (is.list(cnf) && length(cnf) > 0L) {
    return(TRUE)
  }

  if (is_valid_string(access_token)) {
    payload <- parse_jwt_payload_or_null(access_token)
    if (is.list(payload)) {
      return(TRUE)
    }
  }

  raw <- NULL
  if (is.list(introspection_result)) {
    raw <- introspection_result[["raw"]] %||% NULL
    if (is.data.frame(raw)) {
      raw <- as.list(raw)
    }
  }

  is.list(raw)
}

#' Require observable DPoP cnf.jkt in strict mode
#'
#' Used when `dpop_require_access_token = TRUE` so JWT access tokens and token
#' introspection results fail closed if they expose no `cnf$jkt` binding. When
#' `dpop_require_observed_cnf = TRUE`, opaque `DPoP` access tokens that expose
#' no local binding also fail closed.
#'
#' @param oauth_client Optional [OAuthClient] expected to own the DPoP key.
#' @param token Optional [OAuthToken] object.
#' @param access_token Optional raw access-token string.
#' @param cnf Optional explicit cnf claim data.
#' @param introspection_result Optional introspection payload.
#' @param error_context Whether failures should raise input or token errors.
#' @param phase Optional token-processing phase for token errors.
#' @return Invisibly returns `TRUE` on success.
#' @keywords internal
#' @noRd
validate_observed_dpop_cnf_required <- function(
  oauth_client,
  token = NULL,
  access_token = NULL,
  token_type = NULL,
  cnf = NULL,
  introspection_result = NULL,
  error_context = c("input", "token"),
  phase = NULL
) {
  error_context <- match.arg(error_context)

  if (S7::S7_inherits(token, class = OAuthToken)) {
    cnf <- token@cnf
    access_token <- token@access_token
    token_type <- token@token_type %||% token_type
  }

  if (!S7::S7_inherits(oauth_client, class = OAuthClient)) {
    return(invisible(TRUE))
  }

  require_observed_cnf <- isTRUE(oauth_client@dpop_require_observed_cnf)
  if (
    !(isTRUE(oauth_client@dpop_require_access_token) || require_observed_cnf)
  ) {
    return(invisible(TRUE))
  }
  if (
    require_observed_cnf && !is_dpop_token_type(token_type %||% NA_character_)
  ) {
    return(invisible(TRUE))
  }

  fail <- switch(
    error_context,
    input = function(message) err_input(message),
    token = function(message) {
      err_token(message, context = compact_list(list(phase = phase)))
    }
  )

  if (
    !token_dpop_cnf_observable(
      access_token = access_token,
      cnf = cnf,
      introspection_result = introspection_result
    )
  ) {
    if (require_observed_cnf) {
      fail(c(
        "x" = "Expected observable token cnf.jkt for a DPoP access token",
        "i" = paste(
          "dpop_require_observed_cnf = TRUE rejects DPoP access tokens",
          "unless cnf.jkt is visible in the token or introspection response."
        )
      ))
    }
    return(invisible(TRUE))
  }

  validate_token_cnf_consistency(
    access_token = access_token,
    cnf = cnf,
    introspection_result = introspection_result,
    error_context = error_context,
    phase = phase
  )

  resolved_cnf <- resolve_token_cnf(
    cnf = cnf,
    access_token = access_token,
    introspection_result = introspection_result
  )
  if (is_valid_string(resolved_cnf[["jkt"]] %||% NA_character_)) {
    return(invisible(TRUE))
  }

  fail(c(
    "x" = "Expected observable token cnf.jkt for a strict DPoP access token",
    "i" = paste(
      "Strict DPoP mode rejects JWT or introspection-backed access tokens",
      "that do not expose a local cnf.jkt binding."
    )
  ))
}

#' Validate DPoP-bound token binding against the configured key
#'
#' Used after token responses are parsed and before outbound DPoP proofs are
#' attached so mismatched local keys fail closed instead of relying on a later
#' server rejection.
#'
#' @param oauth_client Optional [OAuthClient] expected to own the DPoP key.
#' @param token Optional [OAuthToken] object or raw access-token string.
#' @param access_token Optional raw access-token string.
#' @param cnf Optional explicit cnf claim data.
#' @param error_context Whether binding failures should raise input or token
#'   errors.
#' @param phase Optional token-processing phase for token errors.
#' @return Invisibly returns `TRUE` on success. Otherwise this function raises
#'   an input or token error.
#' @keywords internal
#' @noRd
validate_token_dpop_binding <- function(
  oauth_client,
  token = NULL,
  access_token = NULL,
  cnf = NULL,
  error_context = c("input", "token"),
  phase = NULL
) {
  error_context <- match.arg(error_context)

  validate_token_cnf_consistency(
    token = token,
    access_token = access_token,
    cnf = cnf,
    error_context = error_context,
    phase = phase
  )

  expected_jkt <- token_cnf_jkt(
    token = token,
    access_token = access_token,
    cnf = cnf
  )
  if (!is_valid_string(expected_jkt)) {
    return(invisible(TRUE))
  }

  fail <- switch(
    error_context,
    input = function(message) err_input(message),
    token = function(message) {
      err_token(message, context = compact_list(list(phase = phase)))
    }
  )

  if (!S7::S7_inherits(oauth_client, class = OAuthClient)) {
    fail(
      "oauth_client must be an OAuthClient when using DPoP-bound access tokens"
    )
  }

  if (!client_has_dpop(oauth_client)) {
    fail(
      paste(
        "oauth_client with dpop_private_key is required when token cnf.jkt",
        "binds the access token"
      )
    )
  }

  actual_jkt <- client_dpop_jkt(oauth_client)
  if (!identical(actual_jkt, expected_jkt)) {
    fail(
      "oauth_client dpop_private_key does not match token cnf.jkt thumbprint"
    )
  }

  invisible(TRUE)
}

#' Resolve the DPoP signing algorithm
#'
#' Used by DPoP proof builders.
#'
#' @param client OAuth client carrying DPoP configuration.
#' @return Resolved JOSE algorithm string.
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

#' Build the public JWK used in a DPoP proof header
#'
#' Used when constructing a DPoP proof JWT header.
#'
#' @param key Private key used for DPoP signing.
#' @return Public JWK list suitable for the DPoP header.
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

#' Normalize a DPoP target URI
#'
#' Used when DPoP proof claims are assembled.
#'
#' @param url Request URL to normalize.
#' @return Absolute URL string without query string or fragment, normalized for
#'   scheme/host case and default HTTP(S) ports.
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

  parsed[["query"]] <- NULL
  parsed[["fragment"]] <- NULL
  parsed[["scheme"]] <- tolower(parsed[["scheme"]] %||% "")
  parsed[["hostname"]] <- tolower(
    parsed[["hostname"]] %||% ""
  )

  port <- as.character(parsed[["port"]] %||% "")
  if (
    identical(parsed[["scheme"]], "https") &&
      identical(port, "443")
  ) {
    parsed[["port"]] <- NULL
  }
  if (identical(parsed[["scheme"]], "http") && identical(port, "80")) {
    parsed[["port"]] <- NULL
  }

  httr2::url_build(parsed)
}

#' Compute the DPoP access-token hash
#'
#' Used when a DPoP proof binds an access token via `ath`.
#'
#' @param access_token Access-token string.
#' @return Base64url-encoded SHA-256 hash of the access token.
#' @keywords internal
#' @noRd
dpop_access_token_hash <- function(access_token) {
  if (!is_valid_string(access_token)) {
    err_input("DPoP access_token must be a non-empty string")
  }

  token_raw <- charToRaw(enc2utf8(access_token))
  if (any(token_raw > as.raw(0x7f))) {
    err_input("DPoP access_token must contain only ASCII characters")
  }

  base64url_encode(openssl::sha256(token_raw))
}

## 1.2 Proof building and retry helpers ----------------------------------------

#' Build a DPoP proof JWT
#'
#' Used before DPoP-protected requests are sent.
#'
#' @param client OAuth client carrying DPoP configuration.
#' @param method HTTP method.
#' @param url Target request URL.
#' @param access_token Optional access token bound into the proof.
#' @param nonce Optional nonce supplied by the server.
#' @return Signed DPoP proof JWT string.
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

  nonce_supplied <- !(is.null(nonce) ||
    (is.character(nonce) && length(nonce) == 1L && is.na(nonce)))
  nonce <- normalize_dpop_nonce(nonce)
  if (isTRUE(nonce_supplied) && !is_valid_string(nonce)) {
    err_input(
      paste(
        "DPoP nonce must be a single RFC 9449 nonce using visible ASCII",
        "without spaces, double quotes, or backslashes, and no more than",
        dpop_nonce_max_bytes,
        "bytes"
      )
    )
  }

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
    header[["kid"]] <- kid
  }

  claims <- list(
    jti = random_urlsafe(32),
    htm = toupper(as.character(method %||% "GET")[[1]]),
    htu = dpop_target_uri(as.character(url)[[1]]),
    iat = floor(as.numeric(Sys.time()))
  )
  if (is_valid_string(access_token)) {
    claims[["ath"]] <- dpop_access_token_hash(access_token)
  }
  if (is_valid_string(nonce)) {
    claims[["nonce"]] <- nonce
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

#' Add a DPoP proof header to a request
#'
#' Used by outbound request builders when DPoP is enabled.
#'
#' @param req httr2 request object.
#' @param client OAuth client carrying DPoP configuration.
#' @param access_token Optional access token bound into the proof.
#' @param nonce Optional nonce supplied by the server.
#' @return Updated request object.
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

  method <- req[["method"]] %||% "GET"
  url <- req[["url"]] %||% NA_character_
  if (!is_valid_string(url)) {
    err_config("Request URL missing while building DPoP proof")
  }
  if (!is_valid_string(nonce)) {
    request_kind <- if (is_valid_string(access_token)) "resource" else "token"
    nonce <- dpop_nonce_cache_get(
      client,
      url,
      request_kind = request_kind
    ) %||%
      NULL
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

#' Read a DPoP nonce from a response
#'
#' Used by DPoP retry helpers.
#'
#' @param resp httr2 response object.
#' @return DPoP nonce string, or `NA_character_` when no usable nonce is
#'   present.
#' @keywords internal
#' @noRd
resp_get_dpop_nonce <- function(resp) {
  nonce <- try(httr2::resp_header(resp, "dpop-nonce"), silent = TRUE)
  if (inherits(nonce, "try-error")) {
    return(NA_character_)
  }

  normalize_dpop_nonce(as.character(nonce)[1])
}

#' Parse HTTP authentication challenges
#'
#' Splits a `WWW-Authenticate` field without treating commas inside quoted
#' strings as challenge separators, then associates authentication parameters
#' with their scheme. This is intentionally small, but follows the challenge
#' and auth-param shape from RFC 9110 Section 11.2 closely enough to avoid
#' substring matching across schemes or parameter values.
#'
#' @param value A `WWW-Authenticate` field value.
#' @return A list of challenges, each containing `scheme` and named `params`.
#' @keywords internal
#' @noRd
parse_http_auth_challenges <- function(value) {
  if (!is_valid_string(value)) {
    return(list())
  }

  chars <- strsplit(value, "", fixed = TRUE)[[1]]
  parts <- character()
  current <- character()
  quoted <- FALSE
  escaped <- FALSE
  for (ch in chars) {
    if (escaped) {
      current <- c(current, ch)
      escaped <- FALSE
      next
    }
    if (quoted && identical(ch, "\\")) {
      current <- c(current, ch)
      escaped <- TRUE
      next
    }
    if (identical(ch, '"')) {
      quoted <- !quoted
      current <- c(current, ch)
      next
    }
    if (!quoted && identical(ch, ",")) {
      parts <- c(parts, paste0(current, collapse = ""))
      current <- character()
      next
    }
    current <- c(current, ch)
  }
  parts <- trimws(c(parts, paste0(current, collapse = "")))
  parts <- parts[nzchar(parts)]

  token_pattern <- "[!#$%&'*+.^_`|~0-9A-Za-z-]+"
  challenges <- list()
  current_challenge <- NULL
  for (part in parts) {
    scheme_match <- regexec(
      paste0("^(?i:((?:", token_pattern, ")))(?:[ \\t]+(.*))?$"),
      part,
      perl = TRUE
    )
    scheme_fields <- regmatches(part, scheme_match)[[1]]
    is_new_challenge <- length(scheme_fields) > 0L
    if (is_new_challenge && length(scheme_fields) >= 3L) {
      remainder <- trimws(scheme_fields[[3]])
      if (startsWith(remainder, "=")) {
        is_new_challenge <- FALSE
      }
    }

    if (is_new_challenge) {
      if (!is.null(current_challenge)) {
        challenges[[length(challenges) + 1L]] <- current_challenge
      }
      current_challenge <- list(
        scheme = scheme_fields[[2]],
        param_parts = character()
      )
      if (length(scheme_fields) >= 3L && nzchar(trimws(scheme_fields[[3]]))) {
        current_challenge$param_parts <- trimws(scheme_fields[[3]])
      }
    } else if (!is.null(current_challenge)) {
      current_challenge$param_parts <- c(current_challenge$param_parts, part)
    }
  }
  if (!is.null(current_challenge)) {
    challenges[[length(challenges) + 1L]] <- current_challenge
  }

  lapply(challenges, function(challenge) {
    params <- list()
    for (part in challenge$param_parts) {
      param_match <- regexec(
        paste0(
          "^(",
          token_pattern,
          ")\\s*=\\s*(?:\"((?:\\\\.|[^\"\\\\])*)\"|(",
          token_pattern,
          "))\\s*$"
        ),
        part,
        perl = TRUE
      )
      fields <- regmatches(part, param_match)[[1]]
      if (length(fields) == 0L) {
        next
      }
      param_value <- if (nzchar(fields[[3]])) {
        gsub("\\\\(.)", "\\1", fields[[3]], perl = TRUE)
      } else {
        fields[[4]]
      }
      params[[tolower(fields[[2]])]] <- param_value
    }
    list(scheme = challenge$scheme, params = params)
  })
}

#' Detect a DPoP nonce challenge
#'
#' Used after DPoP-protected requests return 4xx challenges.
#'
#' @param resp httr2 response object.
#' @return `TRUE` when the response challenges the caller to send a fresh DPoP
#'   nonce; otherwise `FALSE`.
#' @keywords internal
#' @noRd
resp_is_dpop_nonce_challenge <- function(resp) {
  nonce <- resp_get_dpop_nonce(resp)
  if (!is_valid_string(nonce)) {
    return(FALSE)
  }

  status <- try(httr2::resp_status(resp), silent = TRUE)
  if (inherits(status, "try-error") || !status %in% c(400L, 401L)) {
    return(FALSE)
  }

  if (identical(status, 400L)) {
    body <- try(
      httr2::resp_body_json(resp, simplifyVector = TRUE),
      silent = TRUE
    )
    if (is.list(body)) {
      err <- body[["error"]] %||% NA_character_
      if (
        is.character(err) &&
          length(err) == 1L &&
          identical(err, "use_dpop_nonce")
      ) {
        return(TRUE)
      }
    }
    return(FALSE)
  }

  www_authenticate <- try(
    httr2::resp_header(resp, "www-authenticate"),
    silent = TRUE
  )
  if (inherits(www_authenticate, "try-error")) {
    return(FALSE)
  }
  challenges <- parse_http_auth_challenges(www_authenticate)
  any(vapply(
    challenges,
    function(challenge) {
      identical(tolower(challenge[["scheme"]]), "dpop") &&
        identical(challenge[["params"]][["error"]] %||% NULL, "use_dpop_nonce")
    },
    logical(1)
  ))
}

#' Retry a DPoP-protected request once with a fresh nonce
#'
#' Used by outbound request helpers after a DPoP nonce challenge.
#'
#' @param req httr2 request object.
#' @param client OAuth client carrying DPoP configuration.
#' @param access_token Optional access token used when building the DPoP proof.
#' @param idempotent Whether generic transport/HTTP retries may run for the
#'   request. DPoP nonce challenges are replayed once with the server-provided
#'   nonce regardless, as required by RFC 9449.
#' @param nonce Optional nonce to use for the initial DPoP proof before any
#'   server challenge is received.
#' @return httr2 response object.
#' @keywords internal
#' @noRd
req_with_dpop_retry <- function(
  req,
  client,
  access_token = NULL,
  idempotent = TRUE,
  nonce = NULL
) {
  if (!client_has_dpop(client)) {
    return(req_with_retry(req, idempotent = idempotent))
  }

  url <- req[["url"]] %||% NA_character_
  request_kind <- if (is_valid_string(access_token)) "resource" else "token"
  prior_prepare_attempt <- req[["shinyOAuth_prepare_attempt"]] %||% NULL

  build_prepare_attempt <- function(nonce_value) {
    function(attempt_req, attempt) {
      if (is.function(prior_prepare_attempt)) {
        attempt_req <- prior_prepare_attempt(attempt_req, attempt)
      }

      req_add_dpop_proof(
        attempt_req,
        client,
        access_token = access_token,
        nonce = nonce_value
      )
    }
  }

  req_with_proof <- req_add_dpop_proof(
    req,
    client,
    access_token = access_token,
    nonce = nonce
  )
  req_with_proof[["shinyOAuth_prepare_attempt"]] <- build_prepare_attempt(nonce)

  resp <- req_with_retry(
    req_with_proof,
    idempotent = idempotent
  )

  nonce <- resp_get_dpop_nonce(resp)
  if (is_valid_string(nonce)) {
    dpop_nonce_cache_set(client, url, nonce, request_kind = request_kind)
  }

  if (!resp_is_dpop_nonce_challenge(resp)) {
    return(resp)
  }

  attr(resp, "shinyOAuth.otel_attributes") <- compact_list(c(
    attr(resp, "shinyOAuth.otel_attributes", exact = TRUE) %||% list(),
    list(
      oauth.dpop.nonce_challenge = TRUE,
      oauth.dpop.nonce_retry = FALSE
    )
  ))

  if (!is_valid_string(nonce)) {
    return(resp)
  }

  retry_req <- req_add_dpop_proof(
    req,
    client,
    access_token = access_token,
    nonce = nonce
  )
  retry_req[["shinyOAuth_prepare_attempt"]] <- build_prepare_attempt(nonce)

  resp <- req_with_retry(retry_req, idempotent = idempotent)

  next_nonce <- resp_get_dpop_nonce(resp)
  if (is_valid_string(next_nonce)) {
    dpop_nonce_cache_set(
      client,
      url,
      next_nonce,
      request_kind = request_kind
    )
  }

  attr(resp, "shinyOAuth.otel_attributes") <- compact_list(c(
    attr(resp, "shinyOAuth.otel_attributes", exact = TRUE) %||% list(),
    list(
      oauth.dpop.nonce_challenge = TRUE,
      oauth.dpop.nonce_retry = TRUE
    )
  ))

  resp
}
