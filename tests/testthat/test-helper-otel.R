testthat::test_that("helper-otel does not disable OTel outside testthat", {
  testthat::skip_if_not_installed("callr")

  helper_path <- if (file.exists("helper-otel.R")) {
    normalizePath("helper-otel.R")
  } else {
    normalizePath(file.path("tests", "testthat", "helper-otel.R"))
  }

  res <- callr::r(
    function(helper_path) {
      Sys.unsetenv("TESTTHAT")
      Sys.setenv(
        OTEL_R_TRACES_EXPORTER = "console",
        OTEL_R_LOGS_EXPORTER = "console",
        OTEL_R_METRICS_EXPORTER = "console",
        OTEL_TRACES_EXPORTER = "console",
        OTEL_LOGS_EXPORTER = "console",
        OTEL_METRICS_EXPORTER = "console"
      )
      options(
        shinyOAuth.otel_tracing_enabled = TRUE,
        shinyOAuth.otel_logging_enabled = TRUE
      )

      helper_env <- new.env(parent = globalenv())
      sys.source(helper_path, envir = helper_env)

      list(
        tracing = getOption("shinyOAuth.otel_tracing_enabled"),
        logging = getOption("shinyOAuth.otel_logging_enabled"),
        env = Sys.getenv(c(
          "OTEL_R_TRACES_EXPORTER",
          "OTEL_R_LOGS_EXPORTER",
          "OTEL_R_METRICS_EXPORTER",
          "OTEL_TRACES_EXPORTER",
          "OTEL_LOGS_EXPORTER",
          "OTEL_METRICS_EXPORTER"
        ))
      )
    },
    args = list(helper_path),
    spinner = FALSE
  )

  testthat::expect_true(isTRUE(res$tracing))
  testthat::expect_true(isTRUE(res$logging))
  testthat::expect_true(all(res$env == "console"))
})
