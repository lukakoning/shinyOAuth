test_that("mTLS token auth styles accept certificate-backed clients", {
  cert_file <- tempfile(fileext = ".pem")
  key_file <- tempfile(fileext = ".pem")
  ca_file <- tempfile(fileext = ".pem")
  on.exit(unlink(c(cert_file, key_file, ca_file), force = TRUE), add = TRUE)

  write_fake_pem(cert_file, "CERTIFICATE")
  write_fake_pem(key_file, "PRIVATE KEY")
  write_fake_pem(ca_file, "CERTIFICATE")

  for (style in c("tls_client_auth", "self_signed_tls_client_auth")) {
    prov <- oauth_provider(
      name = "example",
      auth_url = "https://example.com/auth",
      token_url = "https://example.com/token",
      use_nonce = FALSE,
      use_pkce = TRUE,
      id_token_required = FALSE,
      id_token_validation = FALSE,
      token_auth_style = style,
      mtls_endpoint_aliases = list(
        token_endpoint = "https://example.com/mtls/token",
        userinfo_endpoint = "https://example.com/mtls/userinfo"
      ),
      tls_client_certificate_bound_access_tokens = TRUE
    )

    cli <- oauth_client(
      provider = prov,
      client_id = "abc",
      client_secret = "",
      redirect_uri = "http://localhost:8100/callback",
      scopes = character(0),
      tls_client_cert_file = cert_file,
      tls_client_key_file = key_file,
      tls_client_ca_file = ca_file
    )

    expect_true(S7::S7_inherits(cli, OAuthClient))
    expect_identical(prov@token_auth_style, style)
    expect_true(isTRUE(prov@tls_client_certificate_bound_access_tokens))
    expect_identical(
      prov@mtls_endpoint_aliases$token_endpoint,
      "https://example.com/mtls/token"
    )
    expect_identical(cli@tls_client_cert_file, cert_file)
    expect_identical(cli@tls_client_key_file, key_file)
    expect_identical(cli@tls_client_ca_file, ca_file)
  }

  tok <- OAuthToken(
    access_token = "at",
    userinfo = list(),
    cnf = list(`x5t#S256` = "thumbprint")
  )
  expect_identical(tok@cnf$`x5t#S256`, "thumbprint")
})

test_that("certificate-bound sender constraint requires token binding or an mTLS client", {
  cert_file <- tempfile(fileext = ".pem")
  key_file <- tempfile(fileext = ".pem")
  ca_file <- tempfile(fileext = ".pem")
  on.exit(unlink(c(cert_file, key_file, ca_file), force = TRUE), add = TRUE)

  write_fake_pem(cert_file, "CERTIFICATE")
  write_fake_pem(key_file, "PRIVATE KEY")
  write_fake_pem(ca_file, "CERTIFICATE")

  prov <- oauth_provider(
    name = "example",
    auth_url = "https://example.com/auth",
    token_url = "https://example.com/token",
    userinfo_url = "https://example.com/userinfo",
    use_nonce = FALSE,
    use_pkce = TRUE,
    id_token_required = FALSE,
    id_token_validation = FALSE,
    token_auth_style = "body",
    tls_client_certificate_bound_access_tokens = TRUE
  )

  public_client <- oauth_client(
    provider = prov,
    client_id = "abc",
    client_secret = "",
    redirect_uri = "http://localhost:8100/callback",
    scopes = character(0)
  )
  mtls_client <- oauth_client(
    provider = prov,
    client_id = "abc",
    client_secret = "",
    redirect_uri = "http://localhost:8100/callback",
    scopes = character(0),
    tls_client_cert_file = cert_file,
    tls_client_key_file = key_file,
    tls_client_ca_file = ca_file
  )
  plain_token <- OAuthToken(
    access_token = "at",
    token_type = "Bearer",
    userinfo = list()
  )
  bound_token <- OAuthToken(
    access_token = "at",
    token_type = "Bearer",
    userinfo = list(),
    cnf = list(`x5t#S256` = "thumbprint")
  )

  expect_false(
    shinyOAuth:::token_requires_mtls_sender_constraint(
      plain_token,
      public_client
    )
  )
  expect_true(
    shinyOAuth:::token_requires_mtls_sender_constraint(
      plain_token,
      mtls_client
    )
  )
  expect_true(
    shinyOAuth:::token_requires_mtls_sender_constraint(
      bound_token,
      public_client
    )
  )
})

test_that("mTLS token auth styles require certificate and key files", {
  cert_file <- tempfile(fileext = ".pem")
  key_file <- tempfile(fileext = ".pem")
  on.exit(unlink(c(cert_file, key_file), force = TRUE), add = TRUE)

  write_fake_pem(cert_file, "CERTIFICATE")
  write_fake_pem(key_file, "PRIVATE KEY")

  prov <- oauth_provider(
    name = "example",
    auth_url = "https://example.com/auth",
    token_url = "https://example.com/token",
    use_nonce = FALSE,
    use_pkce = TRUE,
    id_token_required = FALSE,
    id_token_validation = FALSE,
    token_auth_style = "tls_client_auth"
  )

  expect_error(
    oauth_client(
      provider = prov,
      client_id = "abc",
      client_secret = "",
      redirect_uri = "http://localhost:8100/callback",
      scopes = character(0),
      tls_client_cert_file = cert_file
    ),
    regexp = "tls_client_cert_file and tls_client_key_file are required"
  )

  missing_key_file <- tempfile(fileext = ".pem")
  expect_error(
    oauth_client(
      provider = prov,
      client_id = "abc",
      client_secret = "",
      redirect_uri = "http://localhost:8100/callback",
      scopes = character(0),
      tls_client_cert_file = cert_file,
      tls_client_key_file = missing_key_file
    ),
    regexp = "tls_client_key_file must point to an existing file"
  )

  missing_cert_file <- tempfile(fileext = ".pem")
  expect_error(
    oauth_client(
      provider = prov,
      client_id = "abc",
      client_secret = "",
      redirect_uri = "http://localhost:8100/callback",
      scopes = character(0),
      tls_client_cert_file = missing_cert_file,
      tls_client_key_file = key_file
    ),
    regexp = "tls_client_cert_file must point to an existing file"
  )
})
