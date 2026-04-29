testthat::test_that("OAuthClient validator rejects incompatible private_key_jwt signing algs", {
  prov <- oauth_provider(
    name = "example",
    auth_url = "https://example.com/auth",
    token_url = "https://example.com/token",
    issuer = NA_character_,
    use_nonce = FALSE,
    use_pkce = TRUE,
    token_auth_style = "private_key_jwt",
    id_token_required = FALSE,
    id_token_validation = FALSE
  )

  expect_error(
    oauth_client(
      provider = prov,
      client_id = "abc",
      client_secret = "",
      client_private_key = openssl::rsa_keygen(),
      client_assertion_alg = "eddsa",
      redirect_uri = "http://localhost:8100",
      scopes = c("openid")
    ),
    regexp = paste(
      "client_assertion_alg 'EdDSA' is incompatible",
      "with the provided private key"
    )
  )

  key_ec <- try(openssl::ec_keygen(curve = "P-256"), silent = TRUE)
  if (inherits(key_ec, "try-error")) {
    testthat::skip("EC key generation not supported on this platform")
  }

  expect_error(
    oauth_client(
      provider = prov,
      client_id = "abc",
      client_secret = "",
      client_private_key = key_ec,
      client_assertion_alg = "ES512",
      redirect_uri = "http://localhost:8100",
      scopes = c("openid")
    ),
    regexp = paste(
      "client_assertion_alg 'ES512' is incompatible",
      "with the provided private key"
    )
  )
})

testthat::test_that("build_client_assertion rejects incompatible resolved algs", {
  prov <- oauth_provider(
    name = "example",
    auth_url = "https://example.com/auth",
    token_url = "https://example.com/token",
    issuer = NA_character_,
    use_nonce = FALSE,
    use_pkce = TRUE,
    token_auth_style = "private_key_jwt",
    id_token_required = FALSE,
    id_token_validation = FALSE
  )
  cli <- oauth_client(
    provider = prov,
    client_id = "abc",
    client_secret = "",
    client_private_key = openssl::rsa_keygen(),
    redirect_uri = "http://localhost:8100",
    scopes = c("openid")
  )

  testthat::local_mocked_bindings(
    choose_default_alg_for_private_key = function(key) {
      "EdDSA"
    },
    .package = "shinyOAuth"
  )

  expect_error(
    shinyOAuth:::build_client_assertion(cli, prov@token_url),
    regexp = paste(
      "client_assertion_alg 'EdDSA' is incompatible",
      "with the provided private key"
    )
  )
})
