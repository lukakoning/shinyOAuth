# Integration tests using otelsdk to verify real OTel span/attribute emission.
# These tests require the 'otelsdk' package and are skipped when unavailable.

testthat::test_that("with_otel_span creates a real span with correct status", {
  testthat::skip_if_not_installed("otelsdk")

  r <- otelsdk::with_otel_record({
    shinyOAuth:::with_otel_span("shinyOAuth.test.ok", 42)
  })

  testthat::expect_identical(r$value, 42)
  spans <- r$traces
  testthat::expect_true("shinyOAuth.test.ok" %in% names(spans))
  testthat::expect_identical(spans[["shinyOAuth.test.ok"]]$status, "ok")
})

testthat::test_that("with_otel_span marks span as error on failure", {
  testthat::skip_if_not_installed("otelsdk")

  r <- otelsdk::with_otel_record({
    tryCatch(
      shinyOAuth:::with_otel_span("shinyOAuth.test.err", stop("boom")),
      error = function(e) NULL
    )
  })

  spans <- r$traces
  testthat::expect_true("shinyOAuth.test.err" %in% names(spans))
  s <- spans[["shinyOAuth.test.err"]]
  testthat::expect_identical(s$status, "error")
  testthat::expect_true(length(s$events) > 0)
})

testthat::test_that("with_otel_span records provided attributes", {
  testthat::skip_if_not_installed("otelsdk")

  r <- otelsdk::with_otel_record({
    shinyOAuth:::with_otel_span(
      "shinyOAuth.test.attrs",
      42,
      attributes = list(
        oauth.provider.name = "github",
        oauth.phase = "test"
      )
    )
  })

  s <- r$traces[["shinyOAuth.test.attrs"]]
  testthat::expect_identical(s$attributes[["oauth.provider.name"]], "github")
  testthat::expect_identical(s$attributes[["oauth.phase"]], "test")
})

testthat::test_that("nested spans have correct parent-child relationship", {
  testthat::skip_if_not_installed("otelsdk")

  r <- otelsdk::with_otel_record({
    shinyOAuth:::with_otel_span("shinyOAuth.test.parent", {
      shinyOAuth:::with_otel_span("shinyOAuth.test.child", 42)
    })
  })

  spans <- r$traces
  parent <- spans[["shinyOAuth.test.parent"]]
  child <- spans[["shinyOAuth.test.child"]]

  testthat::expect_false(is.null(parent))
  testthat::expect_false(is.null(child))
  # Child's parent span_id should match the parent's span_id
  testthat::expect_identical(child$parent, parent$span_id)
  # Both in the same trace
  testthat::expect_identical(child$trace_id, parent$trace_id)
})

testthat::test_that("async parent span propagates context", {
  testthat::skip_if_not_installed("otelsdk")

  r <- otelsdk::with_otel_record({
    parent <- shinyOAuth:::otel_start_async_parent(
      "shinyOAuth.test.async.parent",
      attributes = list(oauth.phase = "test")
    )
    testthat::expect_false(is.null(parent$span))
    testthat::expect_false(is.null(parent$headers))
    testthat::expect_true("traceparent" %in% names(parent$headers))

    # Simulate worker: restore from headers
    worker_span <- shinyOAuth:::otel_restore_parent_in_worker(
      parent$headers,
      "shinyOAuth.test.async.worker",
      attributes = list(oauth.phase = "test.worker")
    )
    testthat::expect_false(is.null(worker_span))

    # End worker then parent
    shinyOAuth:::otel_end_async_parent(
      list(span = worker_span),
      status = "ok"
    )
    shinyOAuth:::otel_end_async_parent(parent, status = "ok")
  })

  spans <- r$traces
  parent_span <- spans[["shinyOAuth.test.async.parent"]]
  worker_span <- spans[["shinyOAuth.test.async.worker"]]

  testthat::expect_false(is.null(parent_span))
  testthat::expect_false(is.null(worker_span))
  # Worker should be child of parent (same trace)
  testthat::expect_identical(worker_span$trace_id, parent_span$trace_id)
  testthat::expect_identical(worker_span$parent, parent_span$span_id)
  testthat::expect_identical(parent_span$status, "ok")
  testthat::expect_identical(worker_span$status, "ok")
})

testthat::test_that("otel_with_active_span nests child spans under an existing span", {
  testthat::skip_if_not_installed("otelsdk")

  r <- otelsdk::with_otel_record({
    parent <- shinyOAuth:::otel_start_async_parent("shinyOAuth.test.callback.parent")
    shinyOAuth:::otel_with_active_span(parent$span, {
      shinyOAuth:::with_otel_span("shinyOAuth.test.callback.child", 42)
    })
    shinyOAuth:::otel_end_async_parent(parent, status = "ok")
  })

  spans <- r$traces
  parent_span <- spans[["shinyOAuth.test.callback.parent"]]
  child_span <- spans[["shinyOAuth.test.callback.child"]]

  testthat::expect_false(is.null(parent_span))
  testthat::expect_false(is.null(child_span))
  testthat::expect_identical(child_span$trace_id, parent_span$trace_id)
  testthat::expect_identical(child_span$parent, parent_span$span_id)
})

testthat::test_that("prepare_call emits real spans with expected names", {
  testthat::skip_if_not_installed("otelsdk")
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))

  r <- otelsdk::with_otel_record({
    cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
    btok <- valid_browser_token()
    shinyOAuth::prepare_call(cli, browser_token = btok)
  })

  span_names <- names(r$traces)
  testthat::expect_true("shinyOAuth.login.request" %in% span_names)
  testthat::expect_true("shinyOAuth.audit.emit" %in% span_names)

  login_span <- r$traces[["shinyOAuth.login.request"]]
  testthat::expect_identical(login_span$status, "ok")
  testthat::expect_identical(
    login_span$attributes[["oauth.phase"]],
    "login.request"
  )
  testthat::expect_identical(
    login_span$attributes[["oauth.provider.name"]],
    "example"
  )
})

testthat::test_that("instrumentation scope is set correctly", {
  testthat::skip_if_not_installed("otelsdk")

  r <- otelsdk::with_otel_record({
    shinyOAuth:::with_otel_span("shinyOAuth.test.scope", 1)
  })

  s <- r$traces[["shinyOAuth.test.scope"]]
  testthat::expect_identical(
    s$instrumentation_scope$name,
    "r.package.shinyOAuth"
  )
})
