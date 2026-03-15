reset_test_otel_cache()
withr::defer(reset_test_otel_cache())

otel_test_that <- function(desc, code) {
  testthat::test_that(desc, {
    testthat::skip_if_not_installed("otel")
    withr::local_options(list(
      shinyOAuth.otel_tracing_enabled = TRUE,
      shinyOAuth.otel_logging_enabled = FALSE
    ))
    force(code)
  })
}

otel_test_that("with_otel_span falls back to uninstrumented execution on otel errors", {
  out <- testthat::with_mocked_bindings(
    start_local_active_span = function(...) {
      stop("otel span init failed")
    },
    .package = "otel",
    {
      shinyOAuth:::with_otel_span("shinyOAuth.test", 42)
    }
  )

  testthat::expect_equal(out, 42)
})

otel_test_that("otel_start_async_parent degrades to NULL span on otel errors", {
  parent <- testthat::with_mocked_bindings(
    start_span = function(...) {
      stop("otel async span init failed")
    },
    .package = "otel",
    {
      shinyOAuth:::otel_start_async_parent("shinyOAuth.test.async")
    }
  )

  testthat::expect_null(parent$span)
  testthat::expect_null(parent$headers)
})

otel_test_that("otel_start_async_parent does not activate a main-thread span", {
  before <- otel::pack_http_context()
  parent <- shinyOAuth:::otel_start_async_parent("shinyOAuth.test.async")
  after <- otel::pack_http_context()

  testthat::expect_identical(after, before)
  if (!is.null(parent$span)) {
    shinyOAuth:::otel_end_async_parent(parent, status = "ok")
  }
})

otel_test_that("otel tracing can be disabled via option", {
  withr::local_options(list(shinyOAuth.otel_tracing_enabled = FALSE))

  out <- testthat::with_mocked_bindings(
    start_local_active_span = function(...) {
      testthat::fail(
        "start_local_active_span should not be called when tracing is disabled"
      )
    },
    start_span = function(...) {
      testthat::fail("start_span should not be called when tracing is disabled")
    },
    pack_http_context = function(...) {
      testthat::fail(
        "pack_http_context should not be called when tracing is disabled"
      )
    },
    .package = "otel",
    {
      span_out <- shinyOAuth:::with_otel_span("shinyOAuth.test", 42)
      parent <- shinyOAuth:::otel_start_async_parent("shinyOAuth.test.async")
      ctx <- shinyOAuth:::otel_capture_context()

      list(span_out = span_out, parent = parent, ctx = ctx)
    }
  )

  testthat::expect_equal(out$span_out, 42)
  testthat::expect_null(out$parent$span)
  testthat::expect_null(out$parent$headers)
  testthat::expect_null(out$ctx)
})

otel_test_that("otel logging can be disabled via option", {
  withr::local_options(list(shinyOAuth.otel_logging_enabled = FALSE))

  testthat::with_mocked_bindings(
    log = function(...) {
      testthat::fail("otel::log should not be called when logging is disabled")
    },
    .package = "otel",
    {
      shinyOAuth:::otel_emit_log(list(type = "audit_login_success"))
    }
  )

  testthat::expect_true(TRUE)
})
