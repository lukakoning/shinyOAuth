test_that("oauth_module_server validates introspection args", {
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)

  testthat::expect_error(
    shinyOAuth::oauth_module_server(
      "oauth",
      client = cli,
      introspect = TRUE,
      introspect_elements = character(0)
    ),
    class = "shinyOAuth_config_error",
    regexp = "introspection_url"
  )

  testthat::expect_error(
    shinyOAuth::oauth_module_server(
      "oauth",
      client = cli,
      introspect = FALSE,
      introspect_elements = "sub"
    ),
    class = "shinyOAuth_config_error",
    regexp = "introspect_elements.*introspect = FALSE"
  )

  # For introspect_elements validation, we need a provider with introspection_url
  cli_with_introspect <- cli
  cli_with_introspect@provider@introspection_url <- "https://example.com/introspect"

  testthat::expect_error(
    shinyOAuth::oauth_module_server(
      "oauth",
      client = cli_with_introspect,
      introspect = TRUE,
      introspect_elements = c("sub", "nope")
    ),
    class = "shinyOAuth_config_error",
    regexp = "Invalid `introspect_elements`"
  )
})
