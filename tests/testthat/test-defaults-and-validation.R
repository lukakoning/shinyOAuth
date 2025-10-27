test_that("OAuthClient state_entropy fails fast on NA and non-scalar", {
  prov <- oauth_provider(
    name = "ex",
    auth_url = "https://example.com/auth",
    token_url = "https://example.com/token",
    userinfo_url = NA_character_,
    issuer = NA_character_,
    # Form-body + PKCE allows empty client_secret during validation
    token_auth_style = "body",
    use_pkce = TRUE
  )

  # NA should error
  expect_error(
    oauth_client(
      provider = prov,
      client_id = "id",
      client_secret = "",
      redirect_uri = "https://app.example.com/callback",
      state_entropy = NA_integer_
    ),
    regexp = "state_entropy"
  )

  # Vector should error deterministically (no 'condition length > 1' warnings)
  expect_error(
    oauth_client(
      provider = prov,
      client_id = "id",
      client_secret = "",
      redirect_uri = "https://app.example.com/callback",
      state_entropy = c(64, 128)
    ),
    regexp = "state_entropy"
  )
})

test_that("OAuthProvider default jwks_host_issuer_match is FALSE", {
  p <- OAuthProvider(
    name = "t",
    auth_url = "https://example.com/authorize",
    token_url = "https://example.com/token"
  )
  expect_identical(p@jwks_host_issuer_match, FALSE)
})
