testthat::test_that("auto_redirected isn't set when auth URL build fails", {
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))

  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)

  shiny::testServer(
    app = oauth_module_server,
    args = list(
      id = "auth",
      client = cli,
      auto_redirect = TRUE,
      indefinite_session = TRUE
    ),
    expr = {
      # Force prepare_call to throw so .build_auth_url() signals error
      testthat::with_mocked_bindings(
        prepare_call = function(...) {
          stop(structure(
            list(message = "boom"),
            class = c("error", "condition")
          ))
        },
        .package = "shinyOAuth",
        {
          # Simulate initial load with no code/error in query
          values$.process_query("")
          session$flushReact()
          # auto_redirected should remain FALSE because redirect didn't happen
          testthat::expect_false(isTRUE(values$auto_redirected))
          # Should also set an error code for visibility
          testthat::expect_identical(values$error, "auth_url_error")
        }
      )
    }
  )
})

testthat::test_that("invalid shinyOAuth_sid input is rejected and regeneration attempted", {
  # Do NOT skip cookie handling to exercise validator path
  withr::local_options(list(shinyOAuth.skip_browser_token = FALSE))

  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)

  shiny::testServer(
    app = oauth_module_server,
    args = list(
      id = "auth",
      client = cli,
      auto_redirect = FALSE,
      indefinite_session = TRUE
    ),
    expr = {
      # Inject an obviously invalid token (too short, uppercase)
      session$setInputs(shinyOAuth_sid = "ABC")
      session$flushReact()
      # Server should not accept this as a browser_token
      testthat::expect_null(values$browser_token)
      # Module did not set a fatal error; this is auto-repaired
      testthat::expect_false(identical(values$error, "browser_cookie_error"))
    }
  )
})
