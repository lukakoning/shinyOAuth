# End-to-end OpenTelemetry tests for async span propagation.
# Uses otelsdk::with_otel_record() with mirai sync mode (in-process) to
# capture parent/worker spans without subprocess complications.

reset_test_otel_cache()
withr::defer(reset_test_otel_cache())

otel_async <- function(desc, code) {
  testthat::test_that(desc, {
    testthat::skip_if_not_installed("otelsdk")
    testthat::skip_if_not_installed("mirai")
    testthat::skip_if_not_installed("promises")
    testthat::skip_if_not_installed("later")
    withr::local_options(list(
      shinyOAuth.otel_tracing_enabled = TRUE,
      shinyOAuth.otel_logging_enabled = FALSE,
      shinyOAuth.skip_browser_token = TRUE
    ))
    force(code)
  })
}

otel_async("async parent/worker span propagation via sync mirai", {
  mirai::daemons(1, sync = TRUE)
  withr::defer(mirai::daemons(0))

  r <- otelsdk::with_otel_record({
    parent <- shinyOAuth:::otel_start_async_parent(
      "shinyOAuth.test.async.parent",
      attributes = list(oauth.phase = "test")
    )

    resolved <- NULL
    promises::then(
      promises::as.promise(
        shinyOAuth:::async_dispatch(
          expr = quote({
            .ns <- asNamespace("shinyOAuth")
            .ns$with_otel_span("shinyOAuth.test.async.child", 1)
          }),
          args = list(),
          otel_context = list(
            headers = parent$headers,
            worker_span_name = "shinyOAuth.test.async.worker"
          )
        )
      ),
      function(x) resolved <<- x
    )

    deadline <- Sys.time() + 10
    while (is.null(resolved) && Sys.time() < deadline) {
      later::run_now(0.05)
      Sys.sleep(0.01)
    }

    testthat::expect_false(is.null(resolved))
    shinyOAuth:::replay_async_conditions(resolved)
    shinyOAuth:::otel_end_async_parent(parent, status = "ok")
  })

  span_names <- names(r$traces)
  testthat::expect_true("shinyOAuth.test.async.parent" %in% span_names)

  # sync mirai runs in-process, so worker and child spans may also be captured
  parent_span <- r$traces[["shinyOAuth.test.async.parent"]]
  testthat::expect_identical(parent_span$status, "ok")
})

otel_async("async parent span marked error on failure", {
  r <- otelsdk::with_otel_record({
    parent <- shinyOAuth:::otel_start_async_parent(
      "shinyOAuth.test.async.err"
    )
    shinyOAuth:::otel_end_async_parent(
      parent,
      status = "error",
      error = simpleError("async operation failed")
    )
  })

  s <- r$traces[["shinyOAuth.test.async.err"]]
  testthat::expect_identical(s$status, "error")
  testthat::expect_true(length(s$events) > 0)
})

otel_async("async context headers contain traceparent", {
  r <- otelsdk::with_otel_record({
    parent <- shinyOAuth:::otel_start_async_parent(
      "shinyOAuth.test.async.ctx"
    )
    hdrs <- parent$headers
    shinyOAuth:::otel_end_async_parent(parent, status = "ok")
    hdrs
  })

  testthat::expect_true("traceparent" %in% names(r$value))
  testthat::expect_true(nzchar(r$value[["traceparent"]]))
})
