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

test_that("short-lived refresh success waits for half the token lifetime", {
  token <- OAuthToken(
    access_token = "token",
    refresh_token = "refresh",
    expires_at = 104
  )

  expect_equal(
    shinyOAuth:::proactive_refresh_success_delay(token, 100, 60),
    2
  )
  expect_equal(
    shinyOAuth:::proactive_refresh_success_delay(token, 100, 1),
    0
  )
})

test_that("refresh failure backoff is exponential, jittered, and bounded", {
  delay <- shinyOAuth:::proactive_refresh_failure_delay

  expect_equal(delay(1, jitter = 0), 1)
  expect_equal(delay(2, jitter = 0), 2)
  expect_equal(delay(3, jitter = 1), 5)
  expect_equal(delay(100, jitter = 1), 320)
  expect_equal(delay(1, retry_after = 120, jitter = 0), 120)
  expect_equal(delay(1, retry_after = 7200, jitter = 0), 3600)
})

test_that("refresh failure pacing reads Retry-After from HTTP errors", {
  response <- httr2::response(
    url = "https://example.com/token",
    status = 429,
    headers = list("retry-after" = "120")
  )
  condition <- structure(
    list(message = "rate limited", response = response),
    class = c("test_http_error", "error", "condition")
  )

  expect_equal(
    shinyOAuth:::refresh_condition_retry_after(condition),
    120
  )
})
