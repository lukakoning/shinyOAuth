test_that("real SDK message diagnostics follow exposure policy and preserve work", {
  skip_if_not_installed("otelsdk")
  reset_test_otel_cache()
  withr::defer(reset_test_otel_cache())
  local_options(
    warn = 2,
    shinyOAuth.otel_tracing_enabled = TRUE,
    shinyOAuth.otel_logging_enabled = TRUE
  )
  withr::local_envvar(c(
    OTEL_R_TRACES_EXPORTER = "INVALID-SDK-SENTINEL",
    OTEL_R_LOGS_EXPORTER = "INVALID-SDK-SENTINEL"
  ))
  operations <- list(
    span = function() with_otel_span("diagnostic-test", "success"),
    log = function() {
      otel_emit_log(list(type = "sample"))
      "success"
    },
    async = function() {
      parent <- otel_start_async_parent("diagnostic-async")
      otel_end_async_parent(parent)
      "success"
    }
  )
  for (expose in c(FALSE, TRUE)) {
    local_options(shinyOAuth.expose_error_body = expose)
    for (operation in operations) {
      get("otel_clean_cache", asNamespace("otel"))()
      warnings <- list()
      messages <- character()
      result <- withCallingHandlers(
        operation(),
        warning = function(w) {
          warnings[[length(warnings) + 1L]] <<- w
          invokeRestart("muffleWarning")
        },
        message = function(m) {
          messages <<- c(messages, conditionMessage(m))
          invokeRestart("muffleMessage")
        }
      )
      expect_identical(result, "success")
      expect_length(messages, 0L)
      expect_true(length(warnings) > 0L)
      for (warning in warnings) {
        expect_s3_class(warning, "shinyOAuth_event_sink_warning")
        detail <- conditionMessage(warning)
        expect_match(detail, "otel_error_message")
        expect_match(detail, "diagnostic digest: [a-f0-9]+")
        expect_identical(
          grepl("INVALID-SDK-SENTINEL", detail, fixed = TRUE),
          expose
        )
      }
      expect_identical(getOption("warn"), 2L)
    }
  }
  expect_message(
    otel_sdk_call(message("application message"), "test"),
    "application message"
  )
})

test_that("setup and cache-reset warnings gate exception details", {
  messages <- character()
  local_mocked_bindings(warn_pkg = function(title, bullets, ...) {
    messages <<- c(messages, paste(c(title, bullets), collapse = " "))
  })
  for (expose in c(FALSE, TRUE)) {
    withr::local_options(shinyOAuth.expose_error_body = expose)
    error <- simpleError(paste0(
      "Authorization: Bearer SETUP-SENTINEL ",
      "https://user:URL-SECRET@example.com/export?key=QUERY-SECRET\n{detail}"
    ))
    messages <- character()
    otel_telemetry_warning("setup", error)
    warn_about_async_otel_cache_reset("failed", "reset", error)
    expect_length(messages, 2L)
    for (message in messages) {
      expect_match(message, "simpleError")
      expect_match(message, "diagnostic digest: [a-f0-9]+")
      expect_identical(grepl("SETUP-SENTINEL", message, fixed = TRUE), expose)
      expect_false(grepl("URL-SECRET|QUERY-SECRET|\n", message))
    }
  }
})
