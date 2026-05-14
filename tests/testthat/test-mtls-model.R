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

  dpop_tok <- OAuthToken(
    access_token = "at",
    userinfo = list(),
    cnf = list(jkt = "jkt-thumbprint")
  )
  expect_identical(dpop_tok@cnf$jkt, "jkt-thumbprint")

  expect_identical(
    shinyOAuth:::resolve_token_cnf(cnf = list(jkt = "jkt-thumbprint")),
    list(jkt = "jkt-thumbprint")
  )

  mixed_access_token <- build_dummy_jwt(list(
    sub = "user-1",
    cnf = list(jkt = "jwt-jkt")
  ))
  expect_identical(
    shinyOAuth:::resolve_token_cnf(
      cnf = list(`x5t#S256` = "explicit-thumbprint"),
      access_token = mixed_access_token,
      introspection_result = list(
        raw = list(
          cnf = list(jkt = "intro-jkt")
        )
      )
    ),
    list(
      `x5t#S256` = "explicit-thumbprint",
      jkt = "intro-jkt"
    )
  )

  expect_error(
    shinyOAuth:::validate_token_cnf_consistency(
      access_token = build_dummy_jwt(list(
        sub = "user-1",
        cnf = list(jkt = "jwt-jkt")
      )),
      introspection_result = list(
        raw = list(cnf = list(jkt = "intro-jkt"))
      )
    ),
    class = "shinyOAuth_input_error",
    regexp = "Conflicting token cnf values"
  )
})

test_that("certificate-bound sender constraint requires token binding or explicit client opt-in", {
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
  requested_client <- oauth_client(
    provider = prov,
    client_id = "abc",
    client_secret = "",
    redirect_uri = "http://localhost:8100/callback",
    scopes = character(0),
    tls_client_cert_file = cert_file,
    tls_client_key_file = key_file,
    tls_client_ca_file = ca_file,
    mtls_request_certificate_bound_access_tokens = TRUE
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
      requested_client
    )
  )
  expect_false(
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

test_that("refresh cnf resolution preserves prior mTLS binding only as a fallback", {
  expect_identical(
    shinyOAuth:::resolve_refresh_token_cnf(
      prior_cnf = list(`x5t#S256` = "prior-thumbprint")
    ),
    list(`x5t#S256` = "prior-thumbprint")
  )

  expect_identical(
    shinyOAuth:::resolve_refresh_token_cnf(
      prior_cnf = list(`x5t#S256` = "prior-thumbprint"),
      access_token = build_dummy_jwt(list(cnf = list(jkt = "fresh-jkt")))
    ),
    list(jkt = "fresh-jkt")
  )

  expect_length(
    shinyOAuth:::resolve_refresh_token_cnf(
      prior_cnf = list(`x5t#S256` = "prior-thumbprint"),
      introspection_result = list(active = TRUE),
      preserve_prior_thumbprint = FALSE
    ),
    0L
  )
})

test_that("certificate-bound clients reject tokens missing cnf thumbprints", {
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
    use_nonce = FALSE,
    use_pkce = TRUE,
    id_token_required = FALSE,
    id_token_validation = FALSE,
    token_auth_style = "body",
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
    tls_client_ca_file = ca_file,
    mtls_request_certificate_bound_access_tokens = TRUE
  )

  expect_error(
    shinyOAuth:::validate_token_certificate_binding(
      access_token = "at",
      cnf = NULL,
      oauth_client = cli
    ),
    class = "shinyOAuth_input_error",
    regexp = "required cnf x5t#S256 thumbprint"
  )
})

test_that("requesting certificate-bound tokens requires provider support and certificate files", {
  cert_file <- tempfile(fileext = ".pem")
  key_file <- tempfile(fileext = ".pem")
  ca_file <- tempfile(fileext = ".pem")
  on.exit(unlink(c(cert_file, key_file, ca_file), force = TRUE), add = TRUE)

  write_fake_pem(cert_file, "CERTIFICATE")
  write_fake_pem(key_file, "PRIVATE KEY")
  write_fake_pem(ca_file, "CERTIFICATE")

  prov_without_capability <- oauth_provider(
    name = "example",
    auth_url = "https://example.com/auth",
    token_url = "https://example.com/token",
    use_nonce = FALSE,
    use_pkce = TRUE,
    id_token_required = FALSE,
    id_token_validation = FALSE,
    token_auth_style = "body"
  )

  expect_error(
    oauth_client(
      provider = prov_without_capability,
      client_id = "abc",
      client_secret = "",
      redirect_uri = "http://localhost:8100/callback",
      scopes = character(0),
      tls_client_cert_file = cert_file,
      tls_client_key_file = key_file,
      tls_client_ca_file = ca_file,
      mtls_request_certificate_bound_access_tokens = TRUE
    ),
    regexp = "requires provider@tls_client_certificate_bound_access_tokens = TRUE"
  )

  prov_with_capability <- oauth_provider(
    name = "example",
    auth_url = "https://example.com/auth",
    token_url = "https://example.com/token",
    use_nonce = FALSE,
    use_pkce = TRUE,
    id_token_required = FALSE,
    id_token_validation = FALSE,
    token_auth_style = "body",
    tls_client_certificate_bound_access_tokens = TRUE
  )

  expect_error(
    oauth_client(
      provider = prov_with_capability,
      client_id = "abc",
      client_secret = "",
      redirect_uri = "http://localhost:8100/callback",
      scopes = character(0),
      mtls_request_certificate_bound_access_tokens = TRUE
    ),
    regexp = "requires tls_client_cert_file and tls_client_key_file"
  )
})

test_that("verify_token_set rejects certificate thumbprint mismatches during exchange and refresh", {
  cert_file <- mtls_pem_fixture("client-cert.pem")
  key_file <- mtls_pem_fixture("client-key.pem")
  ca_file <- mtls_pem_fixture("ca-cert.pem")

  prov <- oauth_provider(
    name = "example",
    auth_url = "https://example.com/auth",
    token_url = "https://example.com/token",
    use_nonce = FALSE,
    use_pkce = TRUE,
    id_token_required = FALSE,
    id_token_validation = FALSE,
    token_auth_style = "body",
    tls_client_certificate_bound_access_tokens = TRUE,
    allowed_token_types = character(0)
  )
  cli <- oauth_client(
    provider = prov,
    client_id = "abc",
    client_secret = "",
    redirect_uri = "http://localhost:8100/callback",
    scopes = character(0),
    tls_client_cert_file = cert_file,
    tls_client_key_file = key_file,
    tls_client_key_password = "password",
    tls_client_ca_file = ca_file
  )

  expect_mismatch <- function(is_refresh) {
    expect_error(
      shinyOAuth:::verify_token_set(
        cli,
        token_set = list(
          access_token = "at-1",
          token_type = "Bearer",
          expires_in = 60,
          cnf = list(`x5t#S256` = "wrong-thumbprint")
        ),
        nonce = NULL,
        is_refresh = is_refresh,
        requested_scopes = character(0),
        prior_granted_scopes = character(0)
      ),
      class = "shinyOAuth_token_error",
      regexp = "TLS certificate does not match token cnf x5t#S256 thumbprint"
    )
  }

  expect_mismatch(FALSE)
  expect_mismatch(TRUE)
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
