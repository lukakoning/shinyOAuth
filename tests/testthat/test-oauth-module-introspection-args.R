test_that("OAuthClient validates introspection args", {
  base_provider <- make_test_provider(use_pkce = TRUE, use_nonce = FALSE)

  # introspect = TRUE requires introspection_url
  testthat::expect_error(
    shinyOAuth::oauth_client(
      provider = base_provider,
      client_id = "abc",
      client_secret = "xyz",
      redirect_uri = "https://localhost:8100/callback",
      introspect = TRUE,
      introspect_elements = character(0)
    ),
    regexp = "introspection_url"
  )

  # introspect_elements with introspect = FALSE is an error
  testthat::expect_error(
    shinyOAuth::oauth_client(
      provider = base_provider,
      client_id = "abc",
      client_secret = "xyz",
      redirect_uri = "https://localhost:8100/callback",
      introspect = FALSE,
      introspect_elements = "sub"
    ),
    regexp = "introspect_elements.*introspect = FALSE"
  )

  # For introspect_elements validation, we need a provider with introspection_url
  prov_with_introspect <- base_provider
  prov_with_introspect@introspection_url <- "https://example.com/introspect"

  # Invalid introspect_elements values
  testthat::expect_error(
    shinyOAuth::oauth_client(
      provider = prov_with_introspect,
      client_id = "abc",
      client_secret = "xyz",
      redirect_uri = "https://localhost:8100/callback",
      introspect = TRUE,
      introspect_elements = c("sub", "nope")
    ),
    regexp = "invalid introspect_elements"
  )

  # Valid configuration should work
  cli <- shinyOAuth::oauth_client(
    provider = prov_with_introspect,
    client_id = "abc",
    client_secret = "xyz",
    redirect_uri = "https://localhost:8100/callback",
    introspect = TRUE,
    introspect_elements = c("sub", "client_id")
  )
  testthat::expect_true(cli@introspect)
  testthat::expect_equal(cli@introspect_elements, c("sub", "client_id"))
})
