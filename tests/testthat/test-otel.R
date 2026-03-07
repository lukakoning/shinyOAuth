# Tests for OpenTelemetry instrumentation helpers (R/utils__otel.R)
# and otel integration in errors.R

# ---------------------------------------------------------------------------
# Guard helpers
# ---------------------------------------------------------------------------

test_that("is_otel_tracing returns FALSE when otel not installed", {
  with_mocked_bindings(
    is_otel_tracing = function() FALSE,
    .package = "shinyOAuth",
    {
      expect_false(shinyOAuth:::is_otel_tracing())
    }
  )
})

test_that("is_otel_logging returns FALSE when otel not installed", {
  with_mocked_bindings(
    is_otel_logging = function() FALSE,
    .package = "shinyOAuth",
    {
      expect_false(shinyOAuth:::is_otel_logging())
    }
  )
})

test_that("is_otel_measuring returns FALSE when otel not installed", {
  with_mocked_bindings(
    is_otel_measuring = function() FALSE,
    .package = "shinyOAuth",
    {
      expect_false(shinyOAuth:::is_otel_measuring())
    }
  )
})

# ---------------------------------------------------------------------------
# Context propagation: no-op when tracing is off
# ---------------------------------------------------------------------------

test_that("otel_capture_context returns NULL when tracing is disabled", {
  with_mocked_bindings(
    is_otel_tracing = function() FALSE,
    .package = "shinyOAuth",
    {
      expect_null(shinyOAuth:::otel_capture_context())
    }
  )
})

test_that("otel_restore_context returns NULL when headers are NULL", {
  expect_null(shinyOAuth:::otel_restore_context(NULL))
})

test_that("otel_restore_context returns NULL when tracing is disabled", {
  with_mocked_bindings(
    is_otel_tracing = function() FALSE,
    .package = "shinyOAuth",
    {
      expect_null(shinyOAuth:::otel_restore_context(c(traceparent = "x")))
    }
  )
})

# ---------------------------------------------------------------------------
# otel_start_async_child: no-op when tracing is off
# ---------------------------------------------------------------------------

test_that("otel_start_async_child returns NULL when tracing is disabled", {
  with_mocked_bindings(
    is_otel_tracing = function() FALSE,
    .package = "shinyOAuth",
    {
      result <- shinyOAuth:::otel_start_async_child("test", NULL)
      expect_null(result)
    }
  )
})

test_that("otel_start_async_child passes activation_scope (not .local_envir)", {
  # Verify the fix for the critical bug: the function must pass

  # activation_scope to otel::start_local_active_span so the span is
  # scoped to the caller's frame, not otel_start_async_child's frame.
  captured_args <- list()
  mock_ctx <- list(is_valid = function() TRUE)

  with_mocked_bindings(
    is_otel_tracing = function() TRUE,
    otel_restore_context = function(headers) mock_ctx,
    .package = "shinyOAuth",
    {
      # Mock otel::start_local_active_span to capture its arguments
      local_mocked_bindings(
        start_local_active_span = function(
          name,
          attributes = NULL,
          options = NULL,
          ...,
          activation_scope = parent.frame()
        ) {
          captured_args <<- list(
            name = name,
            attributes = attributes,
            options = options,
            activation_scope = activation_scope
          )
          "mock_span"
        },
        .package = "otel"
      )
      test_env <- environment()
      result <- shinyOAuth:::otel_start_async_child(
        "worker:test",
        c(traceparent = "x"),
        kind = "client",
        .local_envir = test_env
      )
    }
  )
  expect_equal(captured_args$name, "worker:test")
  expect_identical(captured_args$activation_scope, test_env)
  expect_equal(captured_args$options$kind, "client")
  expect_equal(captured_args$options$parent, mock_ctx)
})

# ---------------------------------------------------------------------------
# otel_end_span_ok / otel_end_span_error: NULL safety
# ---------------------------------------------------------------------------

test_that("otel_end_span_ok is no-op for NULL span", {
  expect_invisible(shinyOAuth:::otel_end_span_ok(NULL))
})

test_that("otel_end_span_error is no-op for NULL span", {
  expect_invisible(shinyOAuth:::otel_end_span_error(NULL, "err"))
})

test_that("otel_end_span_ok calls span$end with status ok", {
  ended <- FALSE
  mock_span <- list(
    end = function(status_code = NULL) {
      ended <<- TRUE
      expect_equal(status_code, "ok")
    }
  )
  shinyOAuth:::otel_end_span_ok(mock_span)
  expect_true(ended)
})

test_that("otel_end_span_error records condition and ends with error status", {
  calls <- list()
  mock_span <- list(
    record_exception = function(error, ...) {
      calls$record_exception <<- error
    },
    end = function(status_code = NULL) {
      calls$end_status <<- status_code
    }
  )
  cond <- simpleError("test error")
  shinyOAuth:::otel_end_span_error(mock_span, cond)
  expect_identical(calls$record_exception, cond)
  expect_equal(calls$end_status, "error")
})

test_that("otel_end_span_error records string error with exception.type", {
  event_attrs <- NULL
  mock_span <- list(
    add_event = function(name, attributes = NULL) {
      event_attrs <<- attributes
    },
    end = function(status_code = NULL) NULL
  )
  # Need otel::as_attributes to work; mock it to pass through
  local_mocked_bindings(
    as_attributes = function(x) x,
    .package = "otel"
  )
  shinyOAuth:::otel_end_span_error(mock_span, "something broke")
  expect_equal(event_attrs$exception.type, "character")
  expect_equal(event_attrs$exception.message, "something broke")
})

test_that("otel_end_span_ok does not error when span$end throws", {
  # Production safety: should swallow errors
  bad_span <- list(end = function(...) stop("boom"))
  expect_silent(shinyOAuth:::otel_end_span_ok(bad_span))
})

test_that("otel_end_span_error does not error when span methods throw", {
  bad_span <- list(
    record_exception = function(...) stop("boom"),
    add_event = function(...) stop("boom"),
    end = function(...) stop("boom")
  )
  expect_silent(shinyOAuth:::otel_end_span_error(bad_span, simpleError("x")))
})

# ---------------------------------------------------------------------------
# Metric helpers: no-op when measuring is off
# ---------------------------------------------------------------------------

test_that("otel_count_login is no-op when measuring disabled", {
  with_mocked_bindings(
    is_otel_measuring = function() FALSE,
    .package = "shinyOAuth",
    {
      expect_invisible(shinyOAuth:::otel_count_login(TRUE, "github"))
    }
  )
})

test_that("otel_count_refresh is no-op when measuring disabled", {
  with_mocked_bindings(
    is_otel_measuring = function() FALSE,
    .package = "shinyOAuth",
    {
      expect_invisible(shinyOAuth:::otel_count_refresh(FALSE, "google"))
    }
  )
})

test_that("otel_record_exchange_duration is no-op when measuring disabled", {
  with_mocked_bindings(
    is_otel_measuring = function() FALSE,
    .package = "shinyOAuth",
    {
      expect_invisible(shinyOAuth:::otel_record_exchange_duration(1.5, "x"))
    }
  )
})

test_that("otel_record_exchange_duration is no-op when seconds is NULL", {
  with_mocked_bindings(
    is_otel_measuring = function() TRUE,
    .package = "shinyOAuth",
    {
      expect_invisible(shinyOAuth:::otel_record_exchange_duration(NULL, "x"))
    }
  )
})

test_that("otel_record_refresh_duration is no-op when measuring disabled", {
  with_mocked_bindings(
    is_otel_measuring = function() FALSE,
    .package = "shinyOAuth",
    {
      expect_invisible(shinyOAuth:::otel_record_refresh_duration(1.5, "x"))
    }
  )
})

test_that("otel_record_refresh_duration is no-op when seconds is NULL", {
  with_mocked_bindings(
    is_otel_measuring = function() TRUE,
    .package = "shinyOAuth",
    {
      expect_invisible(shinyOAuth:::otel_record_refresh_duration(NULL, "x"))
    }
  )
})

test_that("otel_active_sessions is no-op when measuring disabled", {
  with_mocked_bindings(
    is_otel_measuring = function() FALSE,
    .package = "shinyOAuth",
    {
      expect_invisible(shinyOAuth:::otel_active_sessions(1L))
      expect_invisible(shinyOAuth:::otel_active_sessions(-1L))
    }
  )
})

# ---------------------------------------------------------------------------
# Metric helpers: correct otel calls when measuring is enabled
# ---------------------------------------------------------------------------

test_that("otel_count_login calls counter_add with correct metric name", {
  captured <- list()
  with_mocked_bindings(
    is_otel_measuring = function() TRUE,
    .package = "shinyOAuth",
    {
      local_mocked_bindings(
        as_attributes = function(x) x,
        counter_add = function(name, attributes = NULL) {
          captured <<- list(name = name, attrs = attributes)
        },
        .package = "otel"
      )
      shinyOAuth:::otel_count_login(TRUE, "github")
    }
  )
  expect_equal(captured$name, "shinyoauth.login.total")
  expect_true(captured$attrs$success)
  expect_equal(captured$attrs$provider, "github")
})

test_that("otel_count_refresh calls counter_add with correct metric name", {
  captured <- list()
  with_mocked_bindings(
    is_otel_measuring = function() TRUE,
    .package = "shinyOAuth",
    {
      local_mocked_bindings(
        as_attributes = function(x) x,
        counter_add = function(name, attributes = NULL) {
          captured <<- list(name = name, attrs = attributes)
        },
        .package = "otel"
      )
      shinyOAuth:::otel_count_refresh(FALSE, "google")
    }
  )
  expect_equal(captured$name, "shinyoauth.token_refresh.total")
  expect_false(captured$attrs$success)
  expect_equal(captured$attrs$provider, "google")
})

test_that("otel_record_exchange_duration calls histogram_record", {
  captured <- list()
  with_mocked_bindings(
    is_otel_measuring = function() TRUE,
    .package = "shinyOAuth",
    {
      local_mocked_bindings(
        as_attributes = function(x) x,
        histogram_record = function(name, value, attributes = NULL) {
          captured <<- list(name = name, value = value, attrs = attributes)
        },
        .package = "otel"
      )
      shinyOAuth:::otel_record_exchange_duration(0.42, "microsoft")
    }
  )
  expect_equal(captured$name, "shinyoauth.token_exchange.duration_seconds")
  expect_equal(captured$value, 0.42)
  expect_equal(captured$attrs$provider, "microsoft")
})

test_that("otel_record_refresh_duration calls histogram_record", {
  captured <- list()
  with_mocked_bindings(
    is_otel_measuring = function() TRUE,
    .package = "shinyOAuth",
    {
      local_mocked_bindings(
        as_attributes = function(x) x,
        histogram_record = function(name, value, attributes = NULL) {
          captured <<- list(name = name, value = value, attrs = attributes)
        },
        .package = "otel"
      )
      shinyOAuth:::otel_record_refresh_duration(1.23, "keycloak")
    }
  )
  expect_equal(captured$name, "shinyoauth.token_refresh.duration_seconds")
  expect_equal(captured$value, 1.23)
  expect_equal(captured$attrs$provider, "keycloak")
})

test_that("otel_active_sessions calls up_down_counter_add", {
  captured <- list()
  with_mocked_bindings(
    is_otel_measuring = function() TRUE,
    .package = "shinyOAuth",
    {
      local_mocked_bindings(
        up_down_counter_add = function(name, value) {
          captured <<- list(name = name, value = value)
        },
        .package = "otel"
      )
      shinyOAuth:::otel_active_sessions(1L)
    }
  )
  expect_equal(captured$name, "shinyoauth.active_sessions")
  expect_equal(captured$value, 1L)
})

# ---------------------------------------------------------------------------
# audit_event otel log integration
# ---------------------------------------------------------------------------

test_that("audit_event emits otel log_info with context fields", {
  captured <- list()
  with_mocked_bindings(
    is_otel_logging = function() TRUE,
    emit_trace_event = function(event) invisible(NULL),
    .package = "shinyOAuth",
    {
      local_mocked_bindings(
        log_info = function(message, attributes = NULL) {
          captured <<- list(message = message, attributes = attributes)
        },
        as_attributes = function(x) x,
        .package = "otel"
      )
      shinyOAuth:::audit_event(
        "login_success",
        context = list(
          provider = "github",
          issuer = "https://github.com",
          was_authenticated = TRUE,
          complex_obj = list(nested = TRUE) # non-scalar, should be excluded
        )
      )
    }
  )
  expect_equal(captured$message, "audit:login_success")
  expect_equal(captured$attributes$audit.type, "login_success")
  expect_equal(captured$attributes$provider, "github")
  expect_equal(captured$attributes$issuer, "https://github.com")
  expect_true(captured$attributes$was_authenticated)
  # Non-scalar values should not appear

  expect_null(captured$attributes$complex_obj)
})

test_that("audit_event otel log excludes non-atomic context values", {
  captured <- list()
  with_mocked_bindings(
    is_otel_logging = function() TRUE,
    emit_trace_event = function(event) invisible(NULL),
    .package = "shinyOAuth",
    {
      local_mocked_bindings(
        log_info = function(message, attributes = NULL) {
          captured <<- list(attributes = attributes)
        },
        as_attributes = function(x) x,
        .package = "otel"
      )
      shinyOAuth:::audit_event(
        "test",
        context = list(
          simple = "ok",
          multi_val = c("a", "b"), # length > 1, should be excluded
          a_list = list(a = 1), # non-atomic, should be excluded
          a_null = NULL # NULL, should be excluded by compact_list
        )
      )
    }
  )
  expect_equal(captured$attributes$simple, "ok")
  expect_null(captured$attributes$multi_val)
  expect_null(captured$attributes$a_list)
})

test_that("audit_event skips otel logging when otel is disabled", {
  log_called <- FALSE
  with_mocked_bindings(
    is_otel_logging = function() FALSE,
    emit_trace_event = function(event) invisible(NULL),
    .package = "shinyOAuth",
    {
      local_mocked_bindings(
        log_info = function(...) {
          log_called <<- TRUE
        },
        .package = "otel"
      )
      shinyOAuth:::audit_event("test", context = list(x = 1))
    }
  )
  expect_false(log_called)
})

# ---------------------------------------------------------------------------
# err_abort otel log integration
# ---------------------------------------------------------------------------

test_that("err_abort emits otel log_error with class and trace_id", {
  captured <- list()
  with_mocked_bindings(
    is_otel_logging = function() TRUE,
    .package = "shinyOAuth",
    {
      local_mocked_bindings(
        log_error = function(message, attributes = NULL) {
          captured <<- list(message = message, attributes = attributes)
        },
        as_attributes = function(x) x,
        .package = "otel"
      )
      tryCatch(
        shinyOAuth:::err_abort(
          "test error",
          class = "shinyOAuth_token_error"
        ),
        error = function(e) NULL
      )
    }
  )
  expect_equal(captured$message, "test error")
  expect_match(captured$attributes$error.class, "shinyOAuth_token_error")
  expect_true(nzchar(captured$attributes$trace_id))
})

test_that("err_abort skips otel log when logging disabled", {
  log_called <- FALSE
  with_mocked_bindings(
    is_otel_logging = function() FALSE,
    .package = "shinyOAuth",
    {
      local_mocked_bindings(
        log_error = function(...) {
          log_called <<- TRUE
        },
        .package = "otel"
      )
      tryCatch(
        shinyOAuth:::err_abort("msg"),
        error = function(e) NULL
      )
    }
  )
  expect_false(log_called)
})

# ---------------------------------------------------------------------------
# otel_tracer_name
# ---------------------------------------------------------------------------

test_that("otel_tracer_name follows otel package naming convention", {
  name <- shinyOAuth:::otel_tracer_name
  expect_true(startsWith(name, "r.package."))
  expect_equal(name, "r.package.shinyOAuth")
})
