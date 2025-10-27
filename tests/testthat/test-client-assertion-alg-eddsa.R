testthat::test_that("OAuthClient validator accepts EdDSA for private_key_jwt", {
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
  # Provide any private key to satisfy validator; RSA is fine for this check
  key <- openssl::rsa_keygen()

  # Should not error when client_assertion_alg = "EdDSA" under private_key_jwt
  expect_silent(
    oauth_client(
      provider = prov,
      client_id = "abc",
      client_secret = "",
      client_private_key = key,
      client_assertion_alg = "EdDSA",
      redirect_uri = "http://localhost:8100",
      scopes = c("openid")
    )
  )
})
