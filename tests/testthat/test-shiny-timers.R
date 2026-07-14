test_that("shiny_timer_delay_ms handles the integer boundary", {
  max_ms <- as.double(.Machine$integer.max)

  expect_equal(
    shinyOAuth:::shiny_timer_delay_ms((max_ms - 1) / 1000),
    max_ms - 1
  )
  expect_equal(
    shinyOAuth:::shiny_timer_delay_ms((max_ms + 1) / 1000),
    max_ms
  )
})

test_that("shiny_timer_delay_ms chunks long-lived durations", {
  max_ms <- as.double(.Machine$integer.max)

  expect_equal(shinyOAuth:::shiny_timer_delay_ms(30 * 86400), max_ms)
  expect_equal(shinyOAuth:::shiny_timer_delay_ms(90 * 86400), max_ms)
})

test_that("oauth_module_server rejects infinite timer durations", {
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))
  client <- make_test_client(use_nonce = FALSE)

  expect_error(
    shiny::testServer(
      oauth_module_server,
      args = list(id = "auth", client = client, refresh_lead_seconds = Inf)
    ),
    class = "shinyOAuth_input_error"
  )
  expect_error(
    shiny::testServer(
      oauth_module_server,
      args = list(id = "auth", client = client, refresh_check_interval = Inf)
    ),
    class = "shinyOAuth_input_error"
  )
  expect_error(
    shiny::testServer(
      oauth_module_server,
      args = list(id = "auth", client = client, reauth_after_seconds = Inf)
    ),
    class = "shinyOAuth_input_error"
  )
})