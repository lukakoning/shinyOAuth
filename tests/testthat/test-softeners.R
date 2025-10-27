test_that("print softeners honor guards in test mode", {
  # In testthat (is_test = TRUE), options should enable printing
  old <- options(
    shinyOAuth.print_errors = TRUE,
    shinyOAuth.print_traceback = TRUE
  )
  on.exit(options(old), add = TRUE)

  expect_true(shinyOAuth:::allow_print_errors())
  expect_true(shinyOAuth:::allow_print_traceback())
})

test_that("print softeners are FALSE in production even if options TRUE", {
  # Force the internal guard to behave like non-test, non-interactive
  ns <- asNamespace("shinyOAuth")
  # Save and replace
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

  old <- options(
    shinyOAuth.print_errors = TRUE,
    shinyOAuth.print_traceback = TRUE
  )
  on.exit(options(old), add = TRUE)

  # With options TRUE but guards failing, helpers must return FALSE
  expect_false(shinyOAuth:::allow_print_errors())
  expect_false(shinyOAuth:::allow_print_traceback())
})

test_that("traceback softener defaults to FALSE (no opt-in)", {
  old <- options(
    shinyOAuth.print_errors = FALSE,
    shinyOAuth.print_traceback = NULL
  )
  on.exit(options(old), add = TRUE)

  # Default should be FALSE even in test mode unless explicitly set TRUE
  expect_false(shinyOAuth:::allow_print_traceback())
})

test_that("error_on_softened only errors when explicitly opted-in", {
  # Ensure defaults (no opt-in)
  old <- options(
    shinyOAuth.skip_browser_token = FALSE,
    shinyOAuth.skip_id_sig = FALSE,
    shinyOAuth.print_errors = FALSE,
    shinyOAuth.print_traceback = NULL,
    shinyOAuth.expose_error_body = FALSE
  )
  on.exit(options(old), add = TRUE)

  expect_invisible(shinyOAuth::error_on_softened())

  # Now opt-in to traceback printing; in tests this should trigger the guard
  old2 <- options(shinyOAuth.print_traceback = TRUE)
  on.exit(options(old2), add = TRUE)
  expect_error(
    shinyOAuth::error_on_softened(),
    "One or more safety settings have been disabled",
    fixed = TRUE
  )
})
