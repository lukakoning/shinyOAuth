testthat::test_that("OAuthClient requires redirect_uri to be absolute", {
  prov <- oauth_provider(
    name = "t",
    auth_url = "https://example.com/auth",
    token_url = "https://example.com/token",
    token_auth_style = "header"
  )

  testthat::expect_error(
    oauth_client(
      provider = prov,
      client_id = "id",
      client_secret = "secret",
      redirect_uri = "localhost:8100/callback"
    ),
    "redirect_uri must be an absolute URL"
  )
})

testthat::test_that("OAuthProvider requires endpoint URLs to be absolute", {
  testthat::expect_error(
    oauth_provider(
      name = "t",
      auth_url = "example.com/auth",
      token_url = "https://example.com/token"
    ),
    "auth_url must be an absolute URL"
  )

  testthat::expect_error(
    oauth_provider(
      name = "t",
      auth_url = "https://example.com/auth",
      token_url = "example.com/token"
    ),
    "token_url must be an absolute URL"
  )
})

testthat::test_that("OIDC discovery issuer must be absolute", {
  f <- shinyOAuth:::.discover_assert_valid_issuer
  testthat::expect_error(
    f("localhost:8100"),
    class = "shinyOAuth_input_error"
  )
})
