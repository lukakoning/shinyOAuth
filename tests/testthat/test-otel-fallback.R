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
