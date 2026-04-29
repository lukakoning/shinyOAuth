test_that("error_on_softened ignores removed print options", {
  withr::local_options(lifecycle_verbosity = "quiet")

  old <- options(
    shinyOAuth.skip_browser_token = FALSE,
    shinyOAuth.skip_id_sig = FALSE,
    shinyOAuth.print_errors = TRUE,
    shinyOAuth.print_traceback = TRUE,
    shinyOAuth.expose_error_body = FALSE,
    shinyOAuth.allow_unsigned_userinfo_jwt = FALSE,
    shinyOAuth.allow_redirect = FALSE
  )
  on.exit(options(old), add = TRUE)

  expect_invisible(shinyOAuth::error_on_softened())
})

test_that("error_on_softened only errors when explicitly opted-in", {
  withr::local_options(lifecycle_verbosity = "quiet")

  # Ensure defaults (no opt-in)
  old <- options(
    shinyOAuth.skip_browser_token = FALSE,
    shinyOAuth.skip_id_sig = FALSE,
    shinyOAuth.expose_error_body = FALSE,
    shinyOAuth.allow_unsigned_userinfo_jwt = FALSE,
    shinyOAuth.allow_redirect = FALSE
  )
  on.exit(options(old), add = TRUE)

  expect_invisible(shinyOAuth::error_on_softened())

  # Now opt-in to a real softener; in tests this should trigger the guard
  old2 <- options(shinyOAuth.skip_id_sig = TRUE)
  on.exit(options(old2), add = TRUE)
  expect_error(
    shinyOAuth::error_on_softened(),
    "One or more safety settings have been disabled",
    fixed = TRUE
  )
})

test_that("error_on_softened catches allow_unsigned_userinfo_jwt", {
  withr::local_options(lifecycle_verbosity = "quiet")

  old <- options(
    shinyOAuth.skip_browser_token = FALSE,
    shinyOAuth.skip_id_sig = FALSE,
    shinyOAuth.expose_error_body = FALSE,
    shinyOAuth.allow_unsigned_userinfo_jwt = TRUE
  )
  on.exit(options(old), add = TRUE)

  expect_error(
    shinyOAuth::error_on_softened(),
    "One or more safety settings have been disabled",
    fixed = TRUE
  )
})

test_that("error_on_softened does not cover broader hardening opt-ins", {
  withr::local_options(lifecycle_verbosity = "quiet")

  old <- options(
    shinyOAuth.skip_browser_token = FALSE,
    shinyOAuth.skip_id_sig = FALSE,
    shinyOAuth.expose_error_body = FALSE,
    shinyOAuth.allow_unsigned_userinfo_jwt = FALSE,
    shinyOAuth.allow_redirect = FALSE,
    shinyOAuth.allow_non_atomic_state_store = TRUE,
    shinyOAuth.unblock_auth_params = "state"
  )
  on.exit(options(old), add = TRUE)

  expect_invisible(shinyOAuth::error_on_softened())
})

test_that("error_on_softened is deprecated", {
  withr::local_options(lifecycle_verbosity = "warning")

  expect_warning(
    shinyOAuth::error_on_softened(),
    class = "lifecycle_warning_deprecated"
  )
})

test_that("allow_unsigned_userinfo_jwt errors in production (non-test, non-interactive)", {
  ns <- asNamespace("shinyOAuth")
  old_fun <- get(".is_test_or_interactive", envir = ns)
  was_locked <- bindingIsLocked(".is_test_or_interactive", ns)
  if (was_locked) {
    unlockBinding(".is_test_or_interactive", ns)
  }
  assign(".is_test_or_interactive", function() FALSE, envir = ns)
  on.exit(
    {
      assign(".is_test_or_interactive", old_fun, envir = ns)
      if (was_locked) lockBinding(".is_test_or_interactive", ns)
    },
    add = TRUE
  )

  old <- options(shinyOAuth.allow_unsigned_userinfo_jwt = TRUE)
  on.exit(options(old), add = TRUE)

  expect_error(
    shinyOAuth:::allow_unsigned_userinfo_jwt(),
    class = "shinyOAuth_config_error"
  )
})

test_that("allow_unsigned_userinfo_jwt returns FALSE when option is not set", {
  old <- options(shinyOAuth.allow_unsigned_userinfo_jwt = NULL)
  on.exit(options(old), add = TRUE)

  expect_false(shinyOAuth:::allow_unsigned_userinfo_jwt())
})

test_that("allow_unsigned_userinfo_jwt returns TRUE in test mode when option set", {
  old <- options(shinyOAuth.allow_unsigned_userinfo_jwt = TRUE)
  on.exit(options(old), add = TRUE)

  # We are currently in testthat, so .is_test_or_interactive() returns TRUE
  expect_true(shinyOAuth:::allow_unsigned_userinfo_jwt())
})

# ── allow_redirect softener tests ──────────────────────────────────────────

test_that("error_on_softened catches allow_redirect", {
  withr::local_options(lifecycle_verbosity = "quiet")

  old <- options(
    shinyOAuth.skip_browser_token = FALSE,
    shinyOAuth.skip_id_sig = FALSE,
    shinyOAuth.expose_error_body = FALSE,
    shinyOAuth.allow_unsigned_userinfo_jwt = FALSE,
    shinyOAuth.allow_redirect = TRUE
  )
  on.exit(options(old), add = TRUE)

  expect_error(
    shinyOAuth::error_on_softened(),
    "One or more safety settings have been disabled",
    fixed = TRUE
  )
})

test_that("allow_redirect can be enabled in production explicitly", {
  ns <- asNamespace("shinyOAuth")
  old_fun <- get(".is_test_or_interactive", envir = ns)
  was_locked <- bindingIsLocked(".is_test_or_interactive", ns)
  if (was_locked) {
    unlockBinding(".is_test_or_interactive", ns)
  }
  assign(".is_test_or_interactive", function() FALSE, envir = ns)
  on.exit(
    {
      assign(".is_test_or_interactive", old_fun, envir = ns)
      if (was_locked) lockBinding(".is_test_or_interactive", ns)
    },
    add = TRUE
  )

  old <- options(shinyOAuth.allow_redirect = TRUE)
  on.exit(options(old), add = TRUE)

  expect_true(shinyOAuth:::allow_redirect())
})

test_that("allow_redirect returns FALSE when option is not set", {
  old <- options(shinyOAuth.allow_redirect = NULL)
  on.exit(options(old), add = TRUE)

  expect_false(shinyOAuth:::allow_redirect())
})

test_that("allow_redirect returns TRUE in test mode when option set", {
  old <- options(shinyOAuth.allow_redirect = TRUE)
  on.exit(options(old), add = TRUE)

  # We are currently in testthat, so .is_test_or_interactive() returns TRUE
  expect_true(shinyOAuth:::allow_redirect())
})
