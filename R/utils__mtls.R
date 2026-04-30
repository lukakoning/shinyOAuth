# This file contains the helpers for mutual TLS client authentication,
# certificate-bound access tokens, and mTLS endpoint selection.
# Use them when shinyOAuth needs to choose an mTLS alias endpoint, attach a
# client certificate, or confirm that a sender-constrained token matches it.

# 1 Mutual TLS helpers -----------------------------------------------------

## 1.1 Policy constants and thumbprint cache ------------------------------

# Internal: token_auth_style values that mean "authenticate the client with
# mutual TLS". Treated as constant policy data by discovery and token request
# code rather than a helper function.
MTLS_TOKEN_AUTH_STYLES <- c(
  "tls_client_auth",
  "self_signed_tls_client_auth"
)

# Cache mTLS certificate thumbprints so repeated requests avoid rereading the
# same certificate files.
mtls_thumbprint_cache_env <- new.env(parent = emptyenv())

# Build a file signature used in the mTLS thumbprint cache key.
# Used when certificate or key files may change on disk. Input: path. Output:
# cacheable signature string or NA.
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

# Build the cache key for one certificate/key/password combination.
# Used by the thumbprint cache. Input: cert path, key path, and optional key
# password. Output: cache key string.
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

# Read one cached certificate thumbprint when available.
# Used before recalculating thumbprints. Input: cache key. Output: thumbprint
# string or NULL.
mtls_thumbprint_cache_get <- function(cache_key) {
  if (!is_valid_string(cache_key)) {
    return(NULL)
  }
  if (!exists(cache_key, envir = mtls_thumbprint_cache_env, inherits = FALSE)) {
    return(NULL)
  }

  get(cache_key, envir = mtls_thumbprint_cache_env, inherits = FALSE)
}

# Store one certificate thumbprint in the in-memory cache.
# Used after thumbprint calculation. Input: cache key and thumbprint. Output:
# invisible thumbprint.
mtls_thumbprint_cache_set <- function(cache_key, thumbprint) {
  if (!(is_valid_string(cache_key) && is_valid_string(thumbprint))) {
    return(invisible(thumbprint))
  }

  assign(cache_key, thumbprint, envir = mtls_thumbprint_cache_env)
  invisible(thumbprint)
}

## 1.2 Decide when mTLS applies ------------------------------------------

# Check whether an OAuthClient has both certificate and private-key paths.
# Used before attempting mTLS client auth. Input: OAuthClient-like object.
# Output: TRUE or FALSE.
client_has_mtls_certificate <- function(oauth_client) {
  if (!S7::S7_inherits(oauth_client, class = OAuthClient)) {
    return(FALSE)
  }

  is_valid_string(oauth_client@tls_client_cert_file) &&
    is_valid_string(oauth_client@tls_client_key_file)
}

# Check whether the provider authenticates the client with mutual TLS.
# Used when choosing token endpoint auth behavior. Input: OAuthClient-like
# object. Output: TRUE or FALSE.
client_uses_mtls_auth <- function(oauth_client) {
  if (!S7::S7_inherits(oauth_client, class = OAuthClient)) {
    return(FALSE)
  }

  token_auth_style <- normalize_token_auth_style(
    oauth_client@provider@token_auth_style %||% "header"
  )
  token_auth_style %in% MTLS_TOKEN_AUTH_STYLES
}

# Check whether the provider wants certificate-bound access tokens and the
# client can present a certificate.
# Used when deciding whether mTLS must be applied to protected requests.
# Input: OAuthClient-like object. Output: TRUE or FALSE.
client_requests_certificate_bound_tokens <- function(oauth_client) {
  if (!S7::S7_inherits(oauth_client, class = OAuthClient)) {
    return(FALSE)
  }

  isTRUE(oauth_client@provider@tls_client_certificate_bound_access_tokens) &&
    client_has_mtls_certificate(oauth_client)
}

# Check whether a given call should use the provider's mTLS endpoints.
# Used for token, revocation, introspection, PAR, and userinfo requests.
# Input: OAuthClient and optional token. Output: TRUE or FALSE.
client_uses_mtls_endpoint <- function(oauth_client, token = NULL) {
  client_uses_mtls_auth(oauth_client) ||
    client_requests_certificate_bound_tokens(oauth_client) ||
    (!is.null(token) &&
      token_requires_mtls_sender_constraint(token, oauth_client))
}

# Resolve one provider endpoint, preferring an mTLS alias when requested.
# Used before building outbound requests. Input: provider, endpoint name, and
# prefer_mtls flag. Output: endpoint URL string.
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

## 1.3 Apply client certificates to requests ------------------------------

# Attach the configured client certificate and key to one httr2 request.
# Used once request routing has decided that mTLS applies. Input: request and
# OAuthClient. Output: updated request.
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

# Attach an mTLS certificate to authorization-server requests when policy says
# they should use mTLS endpoints.
# Used for token-like authorization-server calls. Input: request, client, and
# optional token. Output: request.
req_apply_authorization_server_mtls <- function(
  req,
  oauth_client,
  token = NULL
) {
  if (!client_uses_mtls_endpoint(oauth_client, token = token)) {
    return(req)
  }

  # RFC 8705 applies the certificate-thumbprint check when a certificate-bound
  # access token is presented to a protected resource, not when calling AS
  # endpoints such as token, revocation, or introspection.
  req_apply_mtls_client_certificate(req, oauth_client)
}

## 1.4 Resolve token certificate bindings ---------------------------------

# Read the x5t#S256 thumbprint from a token or raw access token when present.
# Used to detect sender-constrained mTLS tokens. Input: OAuthToken or token
# string. Output: thumbprint string or NA.
token_cnf_x5t_s256 <- function(token) {
  cnf <- NULL
  access_token <- NA_character_

  if (S7::S7_inherits(token, class = OAuthToken)) {
    cnf <- token@cnf
    access_token <- token@access_token
  } else if (is_valid_string(token)) {
    access_token <- token
  } else {
    return(NA_character_)
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

# Normalize a cnf claim into the subset shinyOAuth uses for mTLS binding.
# Used when cnf arrives from tokens or introspection. Input: cnf-like value.
# Output: normalized list.
normalize_token_cnf <- function(cnf) {
  if (is.data.frame(cnf)) {
    cnf <- as.list(cnf)
  }
  if (!is.list(cnf)) {
    return(list())
  }

  thumbprint <- cnf[["x5t#S256"]] %||% NA_character_
  if (!is_valid_string(thumbprint)) {
    return(list())
  }

  list(`x5t#S256` = thumbprint)
}

# Parse cnf data from a JWT access token payload.
# Used when token objects do not already expose cnf. Input: access token
# string. Output: normalized cnf list.
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

# Parse cnf data from an introspection result.
# Used as a fallback when token payload cnf is unavailable. Input:
# introspection result object. Output: normalized cnf list.
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

# Resolve the effective cnf claim from explicit data, JWT payload, or
# introspection output.
# Used by sender-constrained token checks. Input: optional cnf, access token,
# and introspection result. Output: normalized cnf list.
resolve_token_cnf <- function(
  cnf = NULL,
  access_token = NULL,
  introspection_result = NULL
) {
  normalized <- normalize_token_cnf(cnf)
  if (length(normalized) > 0) {
    return(normalized)
  }

  jwt_cnf <- token_cnf_from_access_token(access_token)
  if (length(jwt_cnf) > 0) {
    return(jwt_cnf)
  }

  token_cnf_from_introspection(introspection_result)
}

# Check whether a token or client configuration requires mTLS sender
# constraints.
# Used before choosing protected-resource request behavior. Input: optional
# token and OAuthClient. Output: TRUE or FALSE.
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

## 1.5 Read certificates and enforce binding ------------------------------

# Read one PEM certificate file or bundle into certificate objects.
# Used before thumbprint calculation and certificate/key matching. Input:
# certificate file path. Output: certificate list.
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

# Read one PEM private key for mTLS client auth.
# Used before certificate/key matching. Input: key file path and optional key
# password. Output: openssl key object.
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

# Read the certificate from a bundle that matches the configured private key.
# Used before thumbprint calculation. Input: certificate file, optional key
# file, and optional key password. Output: matching certificate object.
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

# Compute the SHA-256 thumbprint of the client certificate bound to the private
# key.
# Used for sender-constrained token validation. Input: certificate file,
# optional key file, and optional key password. Output: base64url thumbprint.
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

# Verify that a certificate-bound token matches the configured client
# certificate.
# Used before protected-resource requests that enforce sender constraints.
# Input: token and OAuthClient. Output: invisible TRUE or an input error.
validate_token_certificate_binding <- function(token, oauth_client) {
  expected_thumbprint <- token_cnf_x5t_s256(token)
  if (!is_valid_string(expected_thumbprint)) {
    return(invisible(TRUE))
  }

  if (!S7::S7_inherits(oauth_client, class = OAuthClient)) {
    err_input(
      "oauth_client must be an OAuthClient when using certificate-bound access tokens"
    )
  }

  if (
    !(is_valid_string(oauth_client@tls_client_cert_file) &&
      is_valid_string(oauth_client@tls_client_key_file))
  ) {
    err_input(
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
    err_input(
      "oauth_client TLS certificate does not match token cnf x5t#S256 thumbprint"
    )
  }

  invisible(TRUE)
}

# Attach the client certificate to one protected-resource request after
# validating any sender-constrained token binding.
# Used for mTLS-bound resource requests. Input: request, optional token, and
# optional OAuthClient. Output: request.
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
