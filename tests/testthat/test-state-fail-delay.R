testthat::test_that("state decryption failures reject without sleeping by default", {
  # Unset the option to exercise the package default, even if the app sets it.
  withr::local_options(list(shinyOAuth.state_fail_delay_ms = NULL))
  sleeps <- numeric()
  testthat::local_mocked_bindings(
    Sys.sleep = function(time) {
      sleeps <<- c(sleeps, time)
      invisible(NULL)
    },
    .package = "base"
  )

  key <- as.raw(rep(1L, 32L))
  token <- shinyOAuth:::state_encrypt_gcm(list(state = "test-state"), key)
  testthat::expect_error(
    shinyOAuth:::state_decrypt_gcm("not_base64url!!!", key),
    class = "shinyOAuth_state_error"
  )
  testthat::expect_error(
    shinyOAuth:::state_decrypt_gcm(token, key = as.raw(rep(2L, 32L))),
    class = "shinyOAuth_state_error"
  )
  testthat::expect_length(sleeps, 0L)
})

testthat::test_that("explicit state failure delays remain supported", {
  withr::local_options(list(shinyOAuth.state_fail_delay_ms = c(0, 0)))
  sleeps <- numeric()
  testthat::local_mocked_bindings(
    Sys.sleep = function(time) {
      sleeps <<- c(sleeps, time)
      invisible(NULL)
    },
    .package = "base"
  )
  key <- as.raw(rep(1L, 32L))

  testthat::expect_error(
    shinyOAuth:::state_decrypt_gcm("not_base64url!!!", key),
    class = "shinyOAuth_state_error"
  )
  testthat::expect_length(sleeps, 0L)

  options(shinyOAuth.state_fail_delay_ms = 20)
  testthat::expect_error(
    shinyOAuth:::state_decrypt_gcm("not_base64url!!!", key),
    class = "shinyOAuth_state_error"
  )
  testthat::expect_equal(sleeps, 0.020)

  options(shinyOAuth.state_fail_delay_ms = c(10, 30))
  testthat::expect_error(
    shinyOAuth:::state_decrypt_gcm("not_base64url!!!", key),
    class = "shinyOAuth_state_error"
  )
  testthat::expect_length(sleeps, 2L)
  testthat::expect_gte(sleeps[[2]], 0.010)
  testthat::expect_lte(sleeps[[2]], 0.030)
})
