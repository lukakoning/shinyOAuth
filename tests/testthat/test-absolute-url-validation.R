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

testthat::test_that("OAuthClient rejects redirect_uri with fragment", {
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
      redirect_uri = "https://app.example/cb#frag"
    ),
    "redirect_uri must not contain a URI fragment"
  )
})

testthat::test_that("OAuthProvider rejects issuer with query component", {
  testthat::expect_error(
    oauth_provider(
      name = "t",
      auth_url = "https://example.com/auth",
      token_url = "https://example.com/token",
      issuer = "https://idp.example.com?x=1"
    ),
    "issuer must not contain query or fragment"
  )
})

testthat::test_that("OAuthProvider rejects issuer with fragment component", {
  testthat::expect_error(
    oauth_provider(
      name = "t",
      auth_url = "https://example.com/auth",
      token_url = "https://example.com/token",
      issuer = "https://idp.example.com#frag"
    ),
    "issuer must not contain query or fragment"
  )
})

testthat::test_that("OAuthProvider accepts issuer without query/fragment", {
  prov <- oauth_provider(
    name = "t",
    auth_url = "https://example.com/auth",
    token_url = "https://example.com/token",
    issuer = "https://idp.example.com/realms/test"
  )
  testthat::expect_equal(prov@issuer, "https://idp.example.com/realms/test")
})

testthat::test_that("OIDC discovery issuer must be absolute", {
  f <- shinyOAuth:::.discover_assert_valid_issuer
  testthat::expect_error(
    f("localhost:8100"),
    class = "shinyOAuth_input_error"
  )
})

testthat::test_that("validate_endpoint rejects non-scalar endpoint values", {
  f <- shinyOAuth:::validate_endpoint

  testthat::expect_error(
    f(
      c("https://example.com/auth", "https://example.com/token"),
      "example.com"
    ),
    class = "shinyOAuth_config_error",
    regexp = "Endpoint must be an absolute URL"
  )

  testthat::expect_error(
    f(
      list("https://example.com/auth", "https://example.com/token"),
      "example.com"
    ),
    class = "shinyOAuth_config_error",
    regexp = "Endpoint must be an absolute URL"
  )

  testthat::expect_no_error(f(NA_character_, "example.com"))
  testthat::expect_no_error(f("", "example.com"))
})
