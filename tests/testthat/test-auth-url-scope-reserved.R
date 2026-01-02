test_that("OAuthProvider rejects scope in extra_auth_params (prevents scope desync)", {
  expect_error(
    oauth_provider(
      name = "test",
      auth_url = "https://example.com/authorize",
      token_url = "https://example.com/token",
      extra_auth_params = list(scope = "user-read-email")
    ),
    regexp = "extra_auth_params must not contain reserved keys|scope"
  )
})
