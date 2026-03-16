# Tests for OTel disable paths and graceful degradation.

reset_test_otel_cache()
withr::defer(reset_test_otel_cache())

# ---------------------------------------------------------------------------
# Option gating — tracing
# ---------------------------------------------------------------------------

testthat::test_that("tracing disabled: with_otel_span executes without spans", {
  withr::local_options(list(shinyOAuth.otel_tracing_enabled = FALSE))

  testthat::with_mocked_bindings(
    start_local_active_span = function(...) {
      testthat::fail(
        "start_local_active_span should not be called"
      )
    },
    start_span = function(...) {
      testthat::fail("start_span should not be called")
    },
    pack_http_context = function(...) {
      testthat::fail(
        "pack_http_context should not be called"
      )
    },
    .package = "otel",
    {
      span_out <- shinyOAuth:::with_otel_span("shinyOAuth.test", 42)
      parent <- shinyOAuth:::otel_start_async_parent(
        "shinyOAuth.test.async"
      )
      ctx <- shinyOAuth:::otel_capture_context()
    }
  )

  testthat::expect_equal(span_out, 42)
  testthat::expect_null(parent$span)
  testthat::expect_null(parent$headers)
  testthat::expect_null(ctx)
})

# ---------------------------------------------------------------------------
# Option gating — logging
# ---------------------------------------------------------------------------

testthat::test_that("logging disabled: otel_emit_log does not call otel::log", {
  withr::local_options(list(
    shinyOAuth.otel_tracing_enabled = TRUE,
    shinyOAuth.otel_logging_enabled = FALSE
  ))

  testthat::with_mocked_bindings(
    log = function(...) {
      testthat::fail("otel::log should not be called")
    },
    .package = "otel",
    {
      shinyOAuth:::otel_emit_log(list(type = "audit_login_success"))
    }
  )

  testthat::succeed()
})

# ---------------------------------------------------------------------------
# Graceful degradation — otel errors
# ---------------------------------------------------------------------------

testthat::test_that("with_otel_span falls back on otel error", {
  withr::local_options(list(shinyOAuth.otel_tracing_enabled = TRUE))

  warned <- FALSE
  out <- withCallingHandlers(
    testthat::with_mocked_bindings(
      start_local_active_span = function(...) {
        stop("otel span init failed")
      },
      .package = "otel",
      {
        shinyOAuth:::with_otel_span("shinyOAuth.test", 42)
      }
    ),
    warning = function(w) {
      if (grepl("OpenTelemetry", conditionMessage(w))) {
        warned <<- TRUE
        tryInvokeRestart("muffleWarning")
      }
    }
  )

  testthat::expect_true(warned)
  testthat::expect_equal(out, 42)
})

testthat::test_that("otel_start_async_parent degrades to NULL on otel error", {
  withr::local_options(list(shinyOAuth.otel_tracing_enabled = TRUE))

  warned <- FALSE
  parent <- withCallingHandlers(
    testthat::with_mocked_bindings(
      start_span = function(...) {
        stop("otel async span init failed")
      },
      .package = "otel",
      {
        shinyOAuth:::otel_start_async_parent("shinyOAuth.test.async")
      }
    ),
    warning = function(w) {
      if (grepl("OpenTelemetry", conditionMessage(w))) {
        warned <<- TRUE
        tryInvokeRestart("muffleWarning")
      }
    }
  )

  testthat::expect_null(parent$span)
  testthat::expect_null(parent$headers)
})

testthat::test_that("otel_start_async_parent does not activate main-thread span", {
  withr::local_options(list(shinyOAuth.otel_tracing_enabled = TRUE))

  before <- otel::pack_http_context()
  parent <- shinyOAuth:::otel_start_async_parent("shinyOAuth.test.async")
  after <- otel::pack_http_context()

  testthat::expect_identical(after, before)
  if (!is.null(parent$span)) {
    shinyOAuth:::otel_end_async_parent(parent, status = "ok")
  }
})

# ---------------------------------------------------------------------------
# otel_end_async_parent NULL safety
# ---------------------------------------------------------------------------

testthat::test_that("otel_end_async_parent is a no-op for NULL parent/span", {
  withr::local_options(list(shinyOAuth.otel_tracing_enabled = TRUE))

  shinyOAuth:::otel_end_async_parent(NULL, status = "ok")
  shinyOAuth:::otel_end_async_parent(list(span = NULL), status = "ok")
  testthat::succeed()
})

# ---------------------------------------------------------------------------
# otel_note_error gating
# ---------------------------------------------------------------------------

testthat::test_that("otel_note_error is a no-op when tracing disabled", {
  withr::local_options(list(shinyOAuth.otel_tracing_enabled = FALSE))

  mock_span <- list(
    set_attribute = function(...) testthat::fail("should not be called"),
    add_event = function(...) testthat::fail("should not be called"),
    set_status = function(...) testthat::fail("should not be called")
  )

  shinyOAuth:::otel_note_error(simpleError("test"), span = mock_span)
  testthat::succeed()
})

testthat::test_that("otel_note_error is a no-op for NULL error", {
  withr::local_options(list(shinyOAuth.otel_tracing_enabled = TRUE))

  called <- FALSE
  mock_span <- list(
    set_attribute = function(...) called <<- TRUE,
    add_event = function(...) called <<- TRUE,
    set_status = function(...) called <<- TRUE
  )

  shinyOAuth:::otel_note_error(NULL, span = mock_span)
  testthat::expect_false(called)
})

# ---------------------------------------------------------------------------
# E2E: disabled tracing still returns correct values
# ---------------------------------------------------------------------------

testthat::test_that("prepare_call succeeds with tracing disabled", {
  withr::local_options(list(
    shinyOAuth.otel_tracing_enabled = FALSE,
    shinyOAuth.otel_logging_enabled = FALSE,
    shinyOAuth.skip_browser_token = TRUE
  ))

  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  btok <- valid_browser_token()
  url <- shinyOAuth::prepare_call(cli, browser_token = btok)

  testthat::expect_true(grepl("^https://", url))
  testthat::expect_true(grepl("state=", url))
})
