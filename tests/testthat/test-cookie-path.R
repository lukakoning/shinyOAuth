testthat::test_that("browser cookie path defaults to request path", {
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))

  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)

  shiny::testServer(
    app = oauth_module_server,
    args = list(
      id = "auth",
      client = cli,
      auto_redirect = FALSE,
      indefinite_session = TRUE,
      browser_cookie_path = NULL
    ),
    expr = {
      # Expose internal JS building helpers via function side effects: we can't
      # inspect cookies in this test environment, but we can assert that the
      # module did not error and helper exists.
      testthat::expect_true(is.function(values$set_browser_token))
      testthat::expect_true(is.function(values$clear_browser_token))
      testthat::expect_true(values$has_browser_token())

      # Clearing should reset the in-memory token presence flag
      values$clear_browser_token()
      testthat::expect_false(values$has_browser_token())
    }
  )
})

testthat::test_that("browser cookie path can be set explicitly", {
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))

  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)

  shiny::testServer(
    app = oauth_module_server,
    args = list(
      id = "auth",
      client = cli,
      auto_redirect = FALSE,
      indefinite_session = TRUE,
      browser_cookie_path = "/foo"
    ),
    expr = {
      # Ensure the server constructs fine with custom path
      testthat::expect_true(is.function(values$set_browser_token))
      testthat::expect_true(is.function(values$clear_browser_token))
      testthat::expect_true(values$has_browser_token())

      # Clearing should reset the in-memory token presence flag
      values$clear_browser_token()
      testthat::expect_false(values$has_browser_token())
    }
  )
})

testthat::test_that("browser cookie path rejects unsafe configured values", {
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))

  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  invalid_paths <- c(
    "foo",
    "/app; SameSite=None; Secure",
    paste0("/app", "\r", "\n", "Secure"),
    paste0("/app", intToUtf8(1L))
  )

  for (bad_path in invalid_paths) {
    testthat::expect_error(
      shiny::testServer(
        app = oauth_module_server,
        args = list(
          id = "auth",
          client = cli,
          auto_redirect = FALSE,
          indefinite_session = TRUE,
          browser_cookie_path = bad_path
        ),
        expr = {}
      ),
      regexp = "browser_cookie_path",
      fixed = TRUE,
      info = paste(
        "Expected invalid browser_cookie_path to be rejected:",
        bad_path
      )
    )
  }
})
