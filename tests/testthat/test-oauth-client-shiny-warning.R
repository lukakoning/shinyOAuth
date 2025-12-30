test_that("oauth_client does not warn outside Shiny", {
  prov <- make_test_provider(use_pkce = TRUE, use_nonce = FALSE)

  testthat::with_mocked_bindings(
    .package = "shinyOAuth",
    .is_test = function() FALSE,
    get_current_shiny_session = function() NULL,
    {
      expect_no_warning(
        oauth_client(
          provider = prov,
          client_id = "abc",
          client_secret = "",
          redirect_uri = "http://localhost:8100"
        )
      )
    }
  )
})

test_that("oauth_client warns when constructed inside Shiny (once per R session)", {
  prov <- make_test_provider(use_pkce = TRUE, use_nonce = FALSE)

  testthat::with_mocked_bindings(
    .package = "shinyOAuth",
    .is_test = function() FALSE,
    get_current_shiny_session = function() list(id = "dummy"),
    {
      expect_warning(
        oauth_client(
          provider = prov,
          client_id = "abc",
          client_secret = "",
          redirect_uri = "http://localhost:8100"
        ),
        regexp = "OAuthClient created inside Shiny|OAuth client construction",
        fixed = FALSE
      )

      # Warn-once guard: subsequent construction should not spam warnings
      expect_no_warning(
        oauth_client(
          provider = prov,
          client_id = "abc",
          client_secret = "",
          redirect_uri = "http://localhost:8100"
        )
      )
    }
  )
})
