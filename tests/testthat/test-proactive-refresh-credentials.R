test_that("proactive refresh preserves valid tokens without refresh credentials", {
  local_options(shinyOAuth.skip_browser_token = TRUE)
  attempts <- 0L
  local_mocked_bindings(
    refresh_token = function(...) {
      attempts <<- attempts + 1L
      stop("refresh must not start without credentials")
    },
    .package = "shinyOAuth"
  )
  for (async in c(FALSE, TRUE)) {
    for (keep in c(FALSE, TRUE)) {
      shiny::testServer(
        oauth_module_server,
        args = list(
          id = "auth",
          client = make_test_client(use_nonce = FALSE),
          auto_redirect = FALSE,
          async = async,
          indefinite_session = keep,
          refresh_proactively = TRUE
        ),
        {
          original <- OAuthToken(
            access_token = "still-valid",
            expires_at = as.numeric(Sys.time()) + 30
          )
          values$token <- original
          values$auth_started_at <- as.numeric(Sys.time())
          session$flushReact()
          expect_identical(values$token, original)
          expect_null(values$error)
          expect_true(values$authenticated)
          expect_false(values$refresh_in_progress)
        }
      )
    }
  }
  expect_identical(attempts, 0L)
})
