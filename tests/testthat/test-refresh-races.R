testthat::test_that("proactive async refresh may trigger multiple attempts but settles to a valid token", {
  testthat::skip_on_cran()
  testthat::skip_if_not_installed("promises")
  testthat::skip_if_not_installed("future")
  testthat::skip_if_not_installed("later")

  withr::local_options(list(
    shinyOAuth.skip_browser_token = TRUE
  ))

  # Configure a background plan; fall back to sequential if multisession fails
  old_plan <- NULL
  if (requireNamespace("future", quietly = TRUE)) {
    old_plan <- tryCatch(future::plan(), error = function(...) NULL)
    ok <- tryCatch(
      {
        future::plan(future::multisession, workers = 2)
        TRUE
      },
      error = function(...) FALSE
    )
    if (!ok) {
      try(future::plan(future::sequential), silent = TRUE)
    }
    withr::defer({
      if (!is.null(old_plan)) try(future::plan(old_plan), silent = TRUE)
    })
  }

  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)

  shiny::testServer(
    app = oauth_module_server,
    args = list(
      id = "auth",
      client = cli,
      auto_redirect = FALSE,
      async = TRUE,
      refresh_proactively = TRUE,
      refresh_lead_seconds = 1,
      refresh_check_interval = 100, # wake frequently during test
      indefinite_session = TRUE
    ),
    expr = {
      testthat::expect_true(values$has_browser_token())

      # Seed a token that will expire shortly
      t0 <- OAuthToken(
        access_token = "old",
        refresh_token = "rt",
        id_token = NA_character_,
        expires_at = as.numeric(Sys.time()) + 1
      )
      values$token <- t0

      # Count refresh attempts and alternate returned access tokens
      calls <- 0L
      token_after <- testthat::with_mocked_bindings(
        refresh_token = function(
          oauth_client,
          token,
          async = TRUE,
          introspect = FALSE
        ) {
          calls <<- calls + 1L
          # Simulate a slow provider so scheduler may trigger another attempt
          promises::future_promise({
            Sys.sleep(0.4)
            OAuthToken(
              access_token = paste0("new-", calls),
              refresh_token = token@refresh_token,
              id_token = token@id_token,
              expires_at = as.numeric(Sys.time()) + 3600
            )
          })
        },
        .package = "shinyOAuth",
        {
          # Pump the event loop until we see an updated token or timeout
          deadline <- Sys.time() + 5
          while (
            identical(values$token@access_token, "old") && Sys.time() < deadline
          ) {
            later::run_now(0.1)
            session$flushReact()
            Sys.sleep(0.02)
          }
          values$token
        }
      )

      # Assertions: refresh happened at least once, token updated and valid
      testthat::expect_true(calls >= 1)
      testthat::expect_s3_class(token_after, "S7_object")
      testthat::expect_true(startsWith(token_after@access_token, "new-"))
      # No error should be latched in indefinite_session mode
      testthat::expect_null(values$error)
      testthat::expect_null(values$error_description)
    }
  )
})
