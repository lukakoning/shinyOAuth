# This file contains the helpers for mutual TLS client authentication,
# certificate-bound access tokens, and mTLS endpoint selection
# Mutual TLS uses client certificates so the server can verify which client is
# making the request
# Used for choosing mTLS endpoints, attaching client certificates, and
# checking that a certificate-bound token matches the certificate

# 1 Mutual TLS helpers ---------------------------------------------------------

## 1.1 Policy constants and thumbprint cache -----------------------------------

# Constants and cache objects in this subsection keep mTLS policy decisions and
# certificate thumbprint lookups in one place.
#
# Token auth styles that mean "authenticate the client with mutual TLS".
MTLS_TOKEN_AUTH_STYLES <- c(
  "tls_client_auth",
  "self_signed_tls_client_auth"
)

# Cache mTLS certificate thumbprints so repeated requests avoid rereading the
# same certificate files.
mtls_thumbprint_cache_env <- new.env(parent = emptyenv())

#' Build a file signature for the mTLS thumbprint cache
#'
#' Used by mTLS thumbprint cache-key helpers.
#'
#' @param path Certificate or key file path.
#' @return Cacheable signature string, or `NA_character_`.
#' @keywords internal
#' @noRd
mtls_thumbprint_cache_file_signature <- function(path) {
  if (!is_valid_string(path)) {
    return(NA_character_)
  }

  normalized <- normalizePath(path, winslash = "/", mustWork = TRUE)
  info <- file.info(normalized)

  paste(
    normalized,
    as.character(info$size[[1]]),
    as.character(as.numeric(info$mtime[[1]])),
    as.character(as.numeric(info$ctime[[1]])),
    sep = "::"
  )
}

#' Build an mTLS thumbprint cache key
#'
#' Used when certificate thumbprints are memoized.
#'
#' @param cert_file Client certificate path.
#' @param key_file Optional private-key path.
#' @param key_password Optional key password.
#' @return Cache key string.
#' @keywords internal
#' @noRd
mtls_thumbprint_cache_key <- function(
  cert_file,
  key_file = NULL,
  key_password = NULL
) {
  paste(
    mtls_thumbprint_cache_file_signature(cert_file),
    mtls_thumbprint_cache_file_signature(key_file),
    string_digest(key_password %||% NA_character_, key = NULL),
    sep = "::"
  )
}

#' Read a cached mTLS thumbprint
#'
#' Used before recomputing certificate thumbprints.
#'
#' @param cache_key Cache entry key.
#' @return Cached thumbprint string, or `NULL`.
#' @keywords internal
#' @noRd
mtls_thumbprint_cache_get <- function(cache_key) {
  if (!is_valid_string(cache_key)) {
    return(NULL)
  }
  if (!exists(cache_key, envir = mtls_thumbprint_cache_env, inherits = FALSE)) {
    return(NULL)
  }

  get(cache_key, envir = mtls_thumbprint_cache_env, inherits = FALSE)
}

#' Store an mTLS thumbprint in the cache
#'
#' Used after certificate thumbprints are computed.
#'
#' @param cache_key Cache entry key.
#' @param thumbprint Thumbprint string to store.
#' @return Invisibly returns `thumbprint`.
#' @keywords internal
#' @noRd
mtls_thumbprint_cache_set <- function(cache_key, thumbprint) {
  if (!(is_valid_string(cache_key) && is_valid_string(thumbprint))) {
    return(invisible(thumbprint))
  }

  assign(cache_key, thumbprint, envir = mtls_thumbprint_cache_env)
  invisible(thumbprint)
}

## 1.2 Decide when mTLS applies ------------------------------------------------

#' Check whether a client has mTLS certificate material
#'
#' Used by mTLS endpoint, auth, and sender-constrained token helpers.
#'
#' @param oauth_client OAuthClient-like object.
#' @return `TRUE` when both certificate and private-key paths are configured;
#'   otherwise `FALSE`.
#' @keywords internal
#' @noRd
client_has_mtls_certificate <- function(oauth_client) {
  if (!S7::S7_inherits(oauth_client, class = OAuthClient)) {
    return(FALSE)
  }

  is_valid_string(oauth_client@tls_client_cert_file) &&
    is_valid_string(oauth_client@tls_client_key_file)
}

#' Check whether a client uses mTLS client authentication
#'
#' Used by authorization-server request builders.
#'
#' @param oauth_client OAuthClient-like object.
#' @return `TRUE` when the provider token auth style is one of the mTLS styles;
#'   otherwise `FALSE`.
#' @keywords internal
#' @noRd
client_uses_mtls_auth <- function(oauth_client) {
  if (!S7::S7_inherits(oauth_client, class = OAuthClient)) {
    return(FALSE)
  }

  token_auth_style <- normalize_token_auth_style(
    oauth_client@provider@token_auth_style %||% "header"
  )
  token_auth_style %in% MTLS_TOKEN_AUTH_STYLES
}

#' Check whether a client requests certificate-bound tokens
#'
#' Used by mTLS endpoint-selection helpers.
#'
#' @param oauth_client OAuthClient-like object.
#' @return `TRUE` when the client explicitly requests certificate-bound tokens,
#'   the provider advertises that capability, and the client can present a
#'   certificate; otherwise `FALSE`.
#' @keywords internal
#' @noRd
client_requests_certificate_bound_tokens <- function(oauth_client) {
  if (!S7::S7_inherits(oauth_client, class = OAuthClient)) {
    return(FALSE)
  }

  isTRUE(oauth_client@mtls_request_certificate_bound_access_tokens) &&
    isTRUE(oauth_client@provider@tls_client_certificate_bound_access_tokens) &&
    client_has_mtls_certificate(oauth_client)
}

#' Check whether a call should use mTLS endpoints
#'
#' Used before token, revocation, introspection, and PAR URLs are resolved.
#'
#' @param oauth_client OAuthClient instance.
#' @param token Optional token or token string.
#' @return `TRUE` when the request should use mTLS endpoints; otherwise `FALSE`.
#' @keywords internal
#' @noRd
client_uses_mtls_endpoint <- function(oauth_client, token = NULL) {
  client_uses_mtls_auth(oauth_client) ||
    client_requests_certificate_bound_tokens(oauth_client) ||
    (!is.null(token) &&
      token_requires_mtls_sender_constraint(token, oauth_client))
}

#' Resolve a provider endpoint URL
#'
#' Used by outbound request builders when mTLS aliases may apply.
#'
#' @param provider OAuthProvider instance.
#' @param endpoint Logical endpoint name.
#' @param prefer_mtls Whether mTLS aliases should be preferred.
#' @return Resolved endpoint URL string.
#' @keywords internal
#' @noRd
resolve_provider_endpoint_url <- function(
  provider,
  endpoint,
  prefer_mtls = FALSE
) {
  base_url <- switch(
    endpoint,
    token_endpoint = provider@token_url,
    userinfo_endpoint = provider@userinfo_url,
    introspection_endpoint = provider@introspection_url,
    revocation_endpoint = provider@revocation_url,
    par_endpoint = provider@par_url,
    err_input(paste0("Unsupported provider endpoint: ", endpoint))
  )

  if (!isTRUE(prefer_mtls)) {
    return(base_url)
  }

  alias_names <- switch(
    endpoint,
    par_endpoint = c("par_endpoint", "pushed_authorization_request_endpoint"),
    endpoint
  )

  for (alias_name in alias_names) {
    alias_url <- provider@mtls_endpoint_aliases[[alias_name]] %||% NA_character_
    if (is_valid_string(alias_url)) {
      return(alias_url)
    }
  }

  base_url
}

## 1.3 Apply client certificates to requests -----------------------------------

#' Attach an mTLS client certificate to a request
#'
#' Used before outbound calls to authorization-server or resource endpoints.
#'
#' @param req httr2 request object.
#' @param oauth_client OAuthClient providing certificate configuration.
#' @return Updated request.
#' @keywords internal
#' @noRd
req_apply_mtls_client_certificate <- function(req, oauth_client) {
  if (!inherits(req, "httr2_request")) {
    return(req)
  }

  cert_file <- oauth_client@tls_client_cert_file %||% NA_character_
  key_file <- oauth_client@tls_client_key_file %||% NA_character_
  key_password <- oauth_client@tls_client_key_password %||% NA_character_
  ca_file <- oauth_client@tls_client_ca_file %||% NA_character_

  if (!(is_valid_string(cert_file) && is_valid_string(key_file))) {
    return(req)
  }

  options <- compact_list(list(
    sslcert = cert_file,
    sslkey = key_file,
    keypasswd = if (is_valid_string(key_password)) key_password else NULL,
    cainfo = if (is_valid_string(ca_file)) ca_file else NULL
  ))

  do.call(httr2::req_options, c(list(req), options))
}

#' Attach mTLS client authentication to authorization-server requests
#'
#' Used by token, revocation, introspection, and PAR request builders.
#'
#' @param req httr2 request object.
#' @param oauth_client OAuthClient instance.
#' @param token Optional token context.
#' @return Request with the client certificate applied when needed.
#' @keywords internal
#' @noRd
req_apply_authorization_server_mtls <- function(
  req,
  oauth_client,
  token = NULL
) {
  if (!client_uses_mtls_endpoint(oauth_client, token = token)) {
    return(req)
  }
  if (!S7::S7_inherits(oauth_client, class = OAuthClient)) {
    err_input(
      paste(
        "oauth_client must be an OAuthClient when an authorization-server",
        "request requires mTLS"
      )
    )
  }
  if (!client_has_mtls_certificate(oauth_client)) {
    err_input(
      paste(
        "oauth_client must include tls_client_cert_file and tls_client_key_file",
        "when an authorization-server request requires mTLS"
      )
    )
  }

  # RFC 8705 applies the certificate-thumbprint check when a certificate-bound
  # access token is presented to a protected resource, not when calling AS
  # endpoints such as token, revocation, or introspection.
  req_apply_mtls_client_certificate(req, oauth_client)
}

## 1.4 Resolve token certificate bindings --------------------------------------

#' Read an mTLS certificate thumbprint from a token
#'
#' @param token Optional [OAuthToken] object or raw token string.
#' @param access_token Optional raw access-token string.
#' @param cnf Optional explicit cnf claim data.
#' @return Thumbprint string, or `NA_character_` when none is available.
#' @keywords internal
#' @noRd
token_cnf_x5t_s256 <- function(token = NULL, access_token = NULL, cnf = NULL) {
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
  thumbprint <- cnf[["x5t#S256"]] %||% NA_character_
  if (!is_valid_string(thumbprint)) {
    return(NA_character_)
  }

  thumbprint
}

#' Normalize a cnf claim for mTLS binding
#'
#' @param cnf cnf-like value from a token or introspection payload.
#' @return Normalized list.
#' @keywords internal
#' @noRd
normalize_token_cnf <- function(cnf) {
  if (is.data.frame(cnf)) {
    cnf <- as.list(cnf)
  }
  if (!is.list(cnf)) {
    return(list())
  }

  thumbprint <- cnf[["x5t#S256"]] %||% NA_character_
  dpop_jkt <- cnf[["jkt"]] %||% NA_character_

  normalized <- compact_list(list(
    `x5t#S256` = if (is_valid_string(thumbprint)) thumbprint else NULL,
    jkt = if (is_valid_string(dpop_jkt)) dpop_jkt else NULL
  ))

  if (!length(normalized)) {
    return(list())
  }

  normalized
}

#' Parse observable cnf data from an access token
#'
#' Used only to observe `cnf` on self-contained JWT access tokens. This does
#' not verify the access-token signature and therefore is not independent proof
#' that the token was issued by the authorization server.
#'
#' @param access_token Raw access-token string.
#' @return Normalized cnf list.
#' @keywords internal
#' @noRd
token_cnf_from_access_token <- function(access_token) {
  if (!is_valid_string(access_token)) {
    return(list())
  }

  payload <- try(parse_jwt_payload(access_token), silent = TRUE)
  if (inherits(payload, "try-error") || !is.list(payload)) {
    return(list())
  }

  normalize_token_cnf(payload$cnf %||% NULL)
}

#' Parse cnf data from an introspection result
#'
#' @param introspection_result Introspection result object or raw payload list.
#' @return Normalized cnf list.
#' @keywords internal
#' @noRd
token_cnf_from_introspection <- function(introspection_result) {
  if (!is.list(introspection_result)) {
    return(list())
  }

  raw <- introspection_result$raw %||% introspection_result
  if (is.data.frame(raw)) {
    raw <- as.list(raw)
  }
  if (!is.list(raw)) {
    return(list())
  }

  normalize_token_cnf(raw$cnf %||% NULL)
}

#' Resolve the effective cnf claim
#'
#' @param cnf Optional explicit cnf data.
#' @param access_token Optional raw access-token string.
#' @param introspection_result Optional introspection payload.
#' @return Normalized cnf list. Preference order is explicit token-response
#'   `cnf`, then introspection `cnf`, then locally observed JWT `cnf`.
#' @keywords internal
#' @noRd
resolve_token_cnf <- function(
  cnf = NULL,
  access_token = NULL,
  introspection_result = NULL
) {
  normalized <- normalize_token_cnf(cnf)
  jwt_cnf <- token_cnf_from_access_token(access_token)
  introspection_cnf <- token_cnf_from_introspection(introspection_result)

  compact_list(list(
    `x5t#S256` = normalized[["x5t#S256"]] %||%
      introspection_cnf[["x5t#S256"]] %||%
      jwt_cnf[["x5t#S256"]] %||%
      NULL,
    jkt = normalized[["jkt"]] %||%
      introspection_cnf[["jkt"]] %||%
      jwt_cnf[["jkt"]] %||%
      NULL
  ))
}

#' Resolve cnf for a refreshed token
#'
#' @param prior_cnf cnf from the pre-refresh token.
#' @param cnf Optional explicit cnf data returned by the refresh response.
#' @param access_token Optional raw refreshed access-token string.
#' @param introspection_result Optional introspection payload for the refreshed
#'   token.
#' @return Normalized cnf list. When the refreshed token does not expose any
#'   new cnf binding, this preserves the prior certificate thumbprint so later
#'   mTLS resource requests do not silently lose sender-constraint state. Treat
#'   that preserved thumbprint as continuity state rather than fresh proof of
#'   binding for the new token; for strong assurance on opaque refresh
#'   responses, prefer refresh-time introspection.
#' @keywords internal
#' @noRd
resolve_refresh_token_cnf <- function(
  prior_cnf = NULL,
  cnf = NULL,
  access_token = NULL,
  introspection_result = NULL
) {
  resolved <- resolve_token_cnf(
    cnf = cnf,
    access_token = access_token,
    introspection_result = introspection_result
  )
  if (length(resolved) > 0L) {
    return(resolved)
  }

  prior_thumbprint <- token_cnf_x5t_s256(cnf = prior_cnf)
  if (!is_valid_string(prior_thumbprint)) {
    return(resolved)
  }

  list(`x5t#S256` = prior_thumbprint)
}

#' Check whether mTLS sender constraints are required
#'
#' @param token Optional token or token string.
#' @param oauth_client Optional OAuthClient.
#' @return `TRUE` when sender-constrained mTLS is required; otherwise `FALSE`.
#' @keywords internal
#' @noRd
token_requires_mtls_sender_constraint <- function(
  token = NULL,
  oauth_client = NULL
) {
  if (is_valid_string(token_cnf_x5t_s256(token))) {
    return(TRUE)
  }

  if (client_requests_certificate_bound_tokens(oauth_client)) {
    return(TRUE)
  }

  FALSE
}

## 1.5 Read certificates and enforce binding -----------------------------------

#' Read client certificates
#'
#' @param cert_file Certificate file path.
#' @return List of certificate objects.
#' @keywords internal
#' @noRd
read_client_certificates <- function(cert_file) {
  certs <- try(openssl::read_cert_bundle(cert_file), silent = TRUE)
  if (!inherits(certs, "try-error") && length(certs) > 0) {
    return(certs)
  }

  cert <- try(openssl::read_cert(cert_file), silent = TRUE)
  if (!inherits(cert, "try-error")) {
    return(list(cert))
  }

  err_config(
    "Failed to parse tls_client_cert_file as a PEM certificate",
    context = list(tls_client_cert_file = cert_file)
  )
}

#' Read a client private key
#'
#' @param key_file Private-key file path.
#' @param key_password Optional key passphrase.
#' @return Openssl key object.
#' @keywords internal
#' @noRd
read_client_private_key <- function(key_file, key_password = NULL) {
  key <- try(
    openssl::read_key(
      key_file,
      password = if (is_valid_string(key_password)) key_password else NULL
    ),
    silent = TRUE
  )
  if (!inherits(key, "try-error")) {
    return(key)
  }

  err_config(
    "Failed to parse tls_client_key_file as a PEM private key",
    context = list(tls_client_key_file = key_file)
  )
}

#' Read the keyed client certificate
#'
#' @param cert_file Certificate or bundle path.
#' @param key_file Optional private-key path.
#' @param key_password Optional key passphrase.
#' @return Matching certificate object.
#' @keywords internal
#' @noRd
read_keyed_client_certificate <- function(
  cert_file,
  key_file = NULL,
  key_password = NULL
) {
  certs <- read_client_certificates(cert_file)
  if (!is_valid_string(key_file)) {
    return(certs[[1]])
  }

  key <- read_client_private_key(key_file, key_password = key_password)
  key_fingerprint <- as.list(key)$pubkey$fingerprint %||% NULL

  for (cert in certs) {
    cert_fingerprint <- as.list(cert)$pubkey$fingerprint %||% NULL
    if (
      !is.null(cert_fingerprint) && identical(cert_fingerprint, key_fingerprint)
    ) {
      return(cert)
    }
  }

  err_config(
    paste(
      "tls_client_cert_file does not contain a certificate matching",
      "tls_client_key_file"
    ),
    context = list(
      tls_client_cert_file = cert_file,
      tls_client_key_file = key_file
    )
  )
}

#' Compute a client certificate thumbprint
#'
#' @param cert_file Certificate path.
#' @param key_file Optional private-key path.
#' @param key_password Optional key passphrase.
#' @return Base64url-encoded certificate thumbprint string.
#' @keywords internal
#' @noRd
tls_client_cert_thumbprint_s256 <- function(
  cert_file,
  key_file = NULL,
  key_password = NULL
) {
  cache_key <- try(
    mtls_thumbprint_cache_key(
      cert_file,
      key_file = key_file,
      key_password = key_password
    ),
    silent = TRUE
  )
  if (!inherits(cache_key, "try-error")) {
    cached_thumbprint <- mtls_thumbprint_cache_get(cache_key)
    if (is_valid_string(cached_thumbprint)) {
      return(cached_thumbprint)
    }
  }

  # PEM bundles may contain a full chain; hash the certificate bound to the
  # configured private key instead of assuming bundle order.
  cert <- read_keyed_client_certificate(
    cert_file,
    key_file = key_file,
    key_password = key_password
  )
  der <- try(openssl::write_der(cert), silent = TRUE)
  if (inherits(der, "try-error")) {
    err_config(
      "Failed to serialize tls_client_cert_file for thumbprint calculation",
      context = list(tls_client_cert_file = cert_file)
    )
  }

  thumbprint <- base64url_encode(openssl::sha256(der))
  if (!inherits(cache_key, "try-error")) {
    mtls_thumbprint_cache_set(cache_key, thumbprint)
  }

  thumbprint
}

#' Validate certificate-bound token binding
#'
#' @param token Optional token or token object to validate.
#' @param access_token Optional raw access-token string.
#' @param cnf Optional explicit cnf claim data.
#' @param oauth_client OAuthClient whose certificate should match.
#' @param error_context Whether binding failures should raise input or token
#'   errors.
#' @param phase Optional token-processing phase for token errors.
#' @return Invisibly returns `TRUE` on success. Otherwise this function raises
#'   an input or token error.
#' @keywords internal
#' @noRd
validate_token_certificate_binding <- function(
  token = NULL,
  oauth_client,
  access_token = NULL,
  cnf = NULL,
  error_context = c("input", "token"),
  phase = NULL
) {
  error_context <- match.arg(error_context)

  fail <- switch(
    error_context,
    input = function(message) err_input(message),
    token = function(message) {
      err_token(message, context = compact_list(list(phase = phase)))
    }
  )

  expected_thumbprint <- token_cnf_x5t_s256(
    token = token,
    access_token = access_token,
    cnf = cnf
  )
  if (!is_valid_string(expected_thumbprint)) {
    # If the client explicitly requests certificate-bound tokens, accepting a
    # token without cnf.x5t#S256 would silently downgrade that contract.
    if (client_requests_certificate_bound_tokens(oauth_client)) {
      fail(
        paste(
          "oauth_client requires certificate-bound access tokens, but the token",
          "does not include the required cnf x5t#S256 thumbprint"
        )
      )
    }
    return(invisible(TRUE))
  }

  if (!S7::S7_inherits(oauth_client, class = OAuthClient)) {
    fail(
      "oauth_client must be an OAuthClient when using certificate-bound access tokens"
    )
  }

  if (
    !(is_valid_string(oauth_client@tls_client_cert_file) &&
      is_valid_string(oauth_client@tls_client_key_file))
  ) {
    fail(
      paste(
        "oauth_client must include tls_client_cert_file and tls_client_key_file",
        "when using certificate-bound access tokens"
      )
    )
  }

  actual_thumbprint <- tls_client_cert_thumbprint_s256(
    oauth_client@tls_client_cert_file,
    key_file = oauth_client@tls_client_key_file,
    key_password = oauth_client@tls_client_key_password
  )
  if (!identical(actual_thumbprint, expected_thumbprint)) {
    fail(
      "oauth_client TLS certificate does not match token cnf x5t#S256 thumbprint"
    )
  }

  invisible(TRUE)
}

#' Attach sender-constrained mTLS to a resource request
#'
#' @param req Outgoing request.
#' @param token Optional token or token string.
#' @param oauth_client Optional OAuthClient.
#' @return Updated request.
#' @keywords internal
#' @noRd
req_apply_sender_constrained_mtls <- function(
  req,
  token = NULL,
  oauth_client = NULL
) {
  if (!token_requires_mtls_sender_constraint(token, oauth_client)) {
    return(req)
  }

  if (!S7::S7_inherits(oauth_client, class = OAuthClient)) {
    err_input(
      "oauth_client must be an OAuthClient when using certificate-bound access tokens"
    )
  }

  validate_token_certificate_binding(token, oauth_client)
  req_apply_mtls_client_certificate(req, oauth_client)
}
