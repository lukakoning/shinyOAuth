testthat::test_that("with_otel_span falls back to uninstrumented execution on otel errors", {
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

testthat::test_that("otel_start_async_parent degrades to NULL span on otel errors", {
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

testthat::test_that("otel_start_async_parent does not activate a main-thread span", {
  before <- otel::pack_http_context()
  parent <- shinyOAuth:::otel_start_async_parent("shinyOAuth.test.async")
  after <- otel::pack_http_context()

  testthat::expect_identical(after, before)
  if (!is.null(parent$span)) {
    shinyOAuth:::otel_end_async_parent(parent, status = "ok")
  }
})

testthat::test_that("otel metrics are disabled by default", {
  testthat::with_mocked_bindings(
    counter_add = function(...) {
      testthat::fail("counter_add should not be called when metrics are disabled")
    },
    up_down_counter_add = function(...) {
      testthat::fail("up_down_counter_add should not be called when metrics are disabled")
    },
    .package = "otel",
    {
      shinyOAuth:::otel_emit_metrics(list(type = "audit_session_started"))
    }
  )

  testthat::expect_true(TRUE)
})
