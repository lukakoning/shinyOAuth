testthat::test_that("state failure delay jitter respects configured bounds (0,0)", {
  # Timing-sensitive test: skip on CRAN
  testthat::skip_on_cran()

  # Configure zero-delay to keep tests fast
  withr::local_options(list(shinyOAuth.state_fail_delay_ms = c(0, 0)))
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))

  # Minimal client and a bogus token to trigger early failure
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  bad_token <- "not_base64url!!!" # invalid base64 -> early error path

  t0 <- proc.time()[[3]]
  testthat::expect_error(
    shinyOAuth:::state_decrypt_gcm(bad_token, key = cli@state_key),
    class = "shinyOAuth_state_error"
  )
  t1 <- proc.time()[[3]]
  # Ensure it returned quickly (< 100ms budget on CI machines)
  testthat::expect_lt((t1 - t0), 0.1)
})
