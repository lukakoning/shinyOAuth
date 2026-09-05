test_that("oversized queries are rejected before callback scanning on any route", {
  withr::local_options(list(shinyOAuth.callback_max_query_bytes = 64))
  scans <- 0L
  scan <- function(...) { scans <<- scans + 1L; stop("scanner ran") }
  testthat::local_mocked_bindings(
    oauth_module_query_has_callback_keys = scan,
    oauth_module_query_raw_values = scan,
    .package = "shinyOAuth"
  )
  shiny::testServer(oauth_module_server,
    args = list(id = "auth", client = make_test_client(), auto_redirect = FALSE),
    expr = {
      for (path in c("/", "/wrong-route")) {
        values$.process_query(paste0("?code=", strrep("x", 100)), current_path = path)
        expect_identical(values$error, "invalid_callback_query")
      }
      expect_identical(scans, 0L)
    }
  )
})

test_that("callback query size caps are configurable via options", {
  client <- make_test_client()

  # 1) state payload cap
  old <- options(shinyOAuth.callback_max_state_bytes = 10)
  on.exit(options(old), add = TRUE)

  expect_error(
    handle_callback(
      oauth_client = client,
      code = "abcd",
      payload = paste(rep("x", 20), collapse = ""),
      browser_token = valid_browser_token()
    ),
    class = "shinyOAuth_state_error"
  )
})

test_that("callback browser_token cap is configurable via options", {
  client <- make_test_client()

  old <- options(
    shinyOAuth.callback_max_code_bytes = 4096,
    shinyOAuth.callback_max_state_bytes = 8192,
    shinyOAuth.callback_max_browser_token_bytes = 5
  )
  on.exit(options(old), add = TRUE)

  expect_error(
    handle_callback(
      oauth_client = client,
      code = "abcd",
      payload = "x",
      browser_token = "123456"
    ),
    class = "shinyOAuth_state_error"
  )
})

test_that("callback code cap is configurable via options", {
  client <- make_test_client()

  old <- options(shinyOAuth.callback_max_code_bytes = 3)
  on.exit(options(old), add = TRUE)

  expect_error(
    handle_callback(
      oauth_client = client,
      code = "abcd",
      payload = "x",
      browser_token = "123"
    ),
    class = "shinyOAuth_state_error"
  )
})
