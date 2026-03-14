# Tests for otel log emission, severity/attribute mapping, and error span status

# --- otel_emit_log -----------------------------------------------------------

testthat::test_that("otel_emit_log calls otel::log with correct severity and message", {
  log_calls <- list()

  testthat::with_mocked_bindings(
    log = function(msg, severity, ...) {
      log_calls[[length(log_calls) + 1L]] <<- list(
        msg = msg,
        severity = severity,
        dots = list(...)
      )
    },
    .package = "otel",
    {
      shinyOAuth:::otel_emit_log(list(
        type = "audit_login_success",
        trace_id = "abc123",
        provider = "github"
      ))
    }
  )

  testthat::expect_length(log_calls, 1L)
  testthat::expect_identical(log_calls[[1]]$severity, "info")
  testthat::expect_identical(log_calls[[1]]$msg, "audit_login_success")
})

testthat::test_that("otel_emit_log uses error severity for error events", {
  log_calls <- list()

  testthat::with_mocked_bindings(
    log = function(msg, severity, ...) {
      log_calls[[length(log_calls) + 1L]] <<- list(
        msg = msg,
        severity = severity
      )
    },
    .package = "otel",
    {
      shinyOAuth:::otel_emit_log(list(
        type = "audit_token_exchange_error",
        message = "Token exchange failed"
      ))
    }
  )

  testthat::expect_length(log_calls, 1L)
  testthat::expect_identical(log_calls[[1]]$severity, "error")
  # Uses message field when available
  testthat::expect_identical(log_calls[[1]]$msg, "Token exchange failed")
})

testthat::test_that("otel_emit_log uses warn severity for validation failures", {
  log_calls <- list()

  testthat::with_mocked_bindings(
    log = function(msg, severity, ...) {
      log_calls[[length(log_calls) + 1L]] <<- list(
        msg = msg,
        severity = severity
      )
    },
    .package = "otel",
    {
      shinyOAuth:::otel_emit_log(list(
        type = "audit_callback_validation_failed"
      ))
    }
  )

  testthat::expect_length(log_calls, 1L)
  testthat::expect_identical(log_calls[[1]]$severity, "warn")
})

testthat::test_that("otel_emit_log does not call otel::log for empty events", {
  log_called <- FALSE
  testthat::with_mocked_bindings(
    log = function(...) {
      log_called <<- TRUE
    },
    .package = "otel",
    {
      shinyOAuth:::otel_emit_log(NULL)
      shinyOAuth:::otel_emit_log(list())
    }
  )

  testthat::expect_false(log_called)
})

testthat::test_that("otel_emit_log does not include sensitive fields in attributes", {
  captured_attrs <- NULL

  testthat::with_mocked_bindings(
    log = function(msg, severity, attributes = NULL, ...) {
      captured_attrs <<- attributes
    },
    .package = "otel",
    {
      shinyOAuth:::otel_emit_log(list(
        type = "audit_login_success",
        provider = "github",
        access_token = "secret_at",
        refresh_token = "secret_rt",
        id_token = "secret_id",
        code = "secret_code",
        state = "secret_state",
        browser_token = "secret_bt"
      ))
    }
  )

  # captured_attrs is an otel_attributes object; convert to list names
  # The sensitive fields should never appear in any form
  if (!is.null(captured_attrs)) {
    attr_names <- names(captured_attrs)
    sensitive_keys <- c(
      "access_token", "refresh_token", "id_token",
      "code", "state", "browser_token"
    )
    for (key in sensitive_keys) {
      testthat::expect_false(
        key %in% attr_names,
        info = paste0("Sensitive key '", key, "' must not appear in otel log attributes")
      )
    }
  }
})

# --- Error paths and span status ---------------------------------------------

testthat::test_that("with_otel_span marks span ok on success", {
  marked_ok <- FALSE
  noted_error <- FALSE

  testthat::with_mocked_bindings(
    otel_mark_span_ok = function(span = NULL) {
      marked_ok <<- TRUE
      invisible(NULL)
    },
    otel_note_error = function(error, span = NULL, attributes = list()) {
      noted_error <<- TRUE
      invisible(NULL)
    },
    .package = "shinyOAuth",
    {
      result <- shinyOAuth:::with_otel_span("test.span", 42)
    }
  )

  testthat::expect_equal(result, 42)
  testthat::expect_true(marked_ok)
  testthat::expect_false(noted_error)
})

testthat::test_that("with_otel_span notes error and re-throws on failure", {
  marked_ok <- FALSE
  noted_error <- FALSE

  testthat::with_mocked_bindings(
    otel_mark_span_ok = function(span = NULL) {
      marked_ok <<- TRUE
      invisible(NULL)
    },
    otel_note_error = function(error, span = NULL, attributes = list()) {
      noted_error <<- TRUE
      testthat::expect_true(inherits(error, "error"))
      testthat::expect_match(conditionMessage(error), "test failure")
      invisible(NULL)
    },
    .package = "shinyOAuth",
    {
      testthat::expect_error(
        shinyOAuth:::with_otel_span("test.span", stop("test failure")),
        "test failure"
      )
    }
  )

  testthat::expect_false(marked_ok)
  testthat::expect_true(noted_error)
})

testthat::test_that("otel_note_error sets error status and adds exception event", {
  set_attr_calls <- list()
  add_event_calls <- list()
  set_status_calls <- list()

  mock_span <- list(
    set_attribute = function(nm, val) {
      set_attr_calls[[length(set_attr_calls) + 1L]] <<- list(nm = nm, val = val)
    },
    add_event = function(name, attributes = NULL) {
      add_event_calls[[length(add_event_calls) + 1L]] <<- list(
        name = name, attrs = attributes
      )
    },
    set_status = function(status, description = NULL) {
      set_status_calls[[length(set_status_calls) + 1L]] <<- list(
        status = status, description = description
      )
    }
  )

  err <- simpleError("something went wrong")

  shinyOAuth:::otel_note_error(err, span = mock_span)

  # Should have added an exception event
  testthat::expect_true(length(add_event_calls) >= 1L)
  testthat::expect_identical(add_event_calls[[1]]$name, "exception")

  # Should have set status to error
  testthat::expect_true(length(set_status_calls) >= 1L)
  testthat::expect_identical(set_status_calls[[1]]$status, "error")
  testthat::expect_identical(
    set_status_calls[[1]]$description,
    "something went wrong"
  )
})

testthat::test_that("otel_note_error is a no-op when tracing is disabled", {
  withr::local_options(list(shinyOAuth.otel_tracing_enabled = FALSE))

  mock_span <- list(
    set_attribute = function(...) testthat::fail("should not be called"),
    add_event = function(...) testthat::fail("should not be called"),
    set_status = function(...) testthat::fail("should not be called")
  )

  # Should not error or call any methods
  shinyOAuth:::otel_note_error(simpleError("test"), span = mock_span)
  testthat::expect_true(TRUE)
})

testthat::test_that("otel_note_error is a no-op for NULL error", {
  called <- FALSE
  mock_span <- list(
    set_attribute = function(...) { called <<- TRUE },
    add_event = function(...) { called <<- TRUE },
    set_status = function(...) { called <<- TRUE }
  )

  shinyOAuth:::otel_note_error(NULL, span = mock_span)
  testthat::expect_false(called)
})

testthat::test_that("otel_end_async_parent marks ok or error correctly", {
  # ok path
  ok_calls <- list()
  err_calls <- list()
  end_calls <- 0L

  mock_span <- list(
    set_status = function(status, ...) {
      if (status == "ok") ok_calls[[length(ok_calls) + 1L]] <<- TRUE
    },
    add_event = function(...) {},
    set_attribute = function(...) {}
  )

  testthat::with_mocked_bindings(
    otel_mark_span_ok = function(span) {
      ok_calls[[length(ok_calls) + 1L]] <<- TRUE
    },
    otel_note_error = function(error, span, ...) {
      err_calls[[length(err_calls) + 1L]] <<- conditionMessage(error)
    },
    .package = "shinyOAuth",
    {
      shinyOAuth:::otel_end_async_parent(
        list(span = mock_span),
        status = "ok"
      )
    }
  )

  testthat::expect_length(ok_calls, 1L)
  testthat::expect_length(err_calls, 0L)

  # error path
  ok_calls <- list()
  err_calls <- list()
  testthat::with_mocked_bindings(
    otel_mark_span_ok = function(span) {
      ok_calls[[length(ok_calls) + 1L]] <<- TRUE
    },
    otel_note_error = function(error, span, ...) {
      err_calls[[length(err_calls) + 1L]] <<- conditionMessage(error)
    },
    .package = "shinyOAuth",
    {
      shinyOAuth:::otel_end_async_parent(
        list(span = mock_span),
        status = "error",
        error = simpleError("async failure")
      )
    }
  )

  testthat::expect_length(ok_calls, 0L)
  testthat::expect_length(err_calls, 1L)
  testthat::expect_identical(err_calls[[1]], "async failure")
})

testthat::test_that("otel_end_async_parent is a no-op for NULL parent/span", {
  # Should not error

  shinyOAuth:::otel_end_async_parent(NULL, status = "ok")
  shinyOAuth:::otel_end_async_parent(list(span = NULL), status = "ok")
  testthat::expect_true(TRUE)
})

# --- emit_trace_event otel bridge --------------------------------------------

testthat::test_that("emit_trace_event calls otel_emit_log", {
  log_called <- FALSE

  testthat::with_mocked_bindings(
    otel_emit_log = function(event) {
      log_called <<- TRUE
    },
    augment_with_shiny_context = function(event) event,
    .package = "shinyOAuth",
    {
      shinyOAuth:::emit_trace_event(list(type = "audit_test", trace_id = "t1"))
    }
  )

  testthat::expect_true(log_called)
})

testthat::test_that("emit_trace_event warns on otel_emit_log failure", {
  testthat::with_mocked_bindings(
    otel_emit_log = function(event) {
      stop("otel log error")
    },
    augment_with_shiny_context = function(event) event,
    .package = "shinyOAuth",
    {
      testthat::expect_warning(
        shinyOAuth:::emit_trace_event(list(type = "test")),
        "otel telemetry error"
      )
    }
  )
})

testthat::test_that("otel_telemetry_warning uses rlang::warn", {
  testthat::expect_warning(
    shinyOAuth:::otel_telemetry_warning("test context", simpleError("boom")),
    "OpenTelemetry test context disabled"
  )
})
