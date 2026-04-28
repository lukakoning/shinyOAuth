mtls_token_auth_styles <- function() {
  c("tls_client_auth", "self_signed_tls_client_auth")
}

client_has_mtls_certificate <- function(oauth_client) {
  if (!S7::S7_inherits(oauth_client, class = OAuthClient)) {
    return(FALSE)
  }

  is_valid_string(oauth_client@tls_client_cert_file) &&
    is_valid_string(oauth_client@tls_client_key_file)
}

client_uses_mtls_auth <- function(oauth_client) {
  if (!S7::S7_inherits(oauth_client, class = OAuthClient)) {
    return(FALSE)
  }

  token_auth_style <- oauth_client@provider@token_auth_style %||% "header"
  token_auth_style %in% mtls_token_auth_styles()
}

client_requests_certificate_bound_tokens <- function(oauth_client) {
  if (!S7::S7_inherits(oauth_client, class = OAuthClient)) {
    return(FALSE)
  }

  isTRUE(oauth_client@provider@tls_client_certificate_bound_access_tokens) &&
    client_has_mtls_certificate(oauth_client)
}

client_uses_mtls_endpoint <- function(oauth_client, token = NULL) {
  client_uses_mtls_auth(oauth_client) ||
    client_requests_certificate_bound_tokens(oauth_client) ||
    (!is.null(token) &&
      token_requires_mtls_sender_constraint(token, oauth_client))
}

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

tls_client_cert_thumbprint_s256 <- function(
  cert_file,
  key_file = NULL,
  key_password = NULL
) {
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

  base64url_encode(openssl::sha256(der))
}

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
