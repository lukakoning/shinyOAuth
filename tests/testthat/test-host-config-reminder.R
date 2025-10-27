test_that("no host reminder when allowlist configured", {
  # Configure a global allowlist
  withr::local_options(list(
    shinyOAuth.allowed_hosts = c(".example.com", "api.example.com")
  ))

  testthat::with_mocked_bindings(
    .package = "shinyOAuth",
    .is_test = function() FALSE,
    .is_interactive = function() FALSE,
    {
      expect_no_warning(
        oauth_provider_oidc(
          name = "ex3",
          base_url = "https://login.example.com"
        )
      )
    }
  )
})
