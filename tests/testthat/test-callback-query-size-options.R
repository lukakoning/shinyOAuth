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
