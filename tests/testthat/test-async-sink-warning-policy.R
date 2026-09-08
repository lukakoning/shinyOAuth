test_that("captured sink warnings cannot reject successful async results", {
  skip_if_not_installed("callr")
  local_options(warn = 2, shinyOAuth.replay_async_conditions = TRUE)
  warnings <- list()
  value <- withCallingHandlers(
    {
      shinyOAuth:::warn_event_sink_failure(
        "Sample sink failed",
        "sample detail"
      )
      "successful result"
    },
    warning = function(w) {
      warnings[[length(warnings) + 1L]] <<- w
      invokeRestart("muffleWarning")
    }
  )
  expect_s3_class(warnings[[1]], "shinyOAuth_event_sink_warning")
  wrapped <- list(
    .shinyOAuth_async_wrapped = TRUE,
    value = value,
    warnings = warnings,
    messages = list()
  )
  # Replay outside testthat's warning handlers so the strict policy really runs.
  replay <- function(wrapped) {
    callr::r(
      function(wrapped, path) {
        pkgload::load_all(path, quiet = TRUE, helpers = FALSE)
        options(warn = 2)
        list(
          value = tryCatch(
            shinyOAuth:::replay_async_conditions(wrapped),
            error = identity
          ),
          warn = getOption("warn")
        )
      },
      args = list(wrapped, normalizePath(test_path("../..")))
    )
  }
  result <- replay(wrapped)
  expect_identical(result$value, "successful result")
  expect_identical(result$warn, 2L)

  wrapped$warnings <- list(simpleWarning("business warning"))
  result <- replay(wrapped)
  expect_s3_class(result$value, "error")
  expect_match(conditionMessage(result$value), "business warning")
  expect_identical(result$warn, 2L)
})
