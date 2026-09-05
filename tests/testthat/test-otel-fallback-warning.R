test_that("OTEL cache-reset fallback cannot abort OAuth under warn = 2", {
  withr::local_options(warn = 2)
  for (hook in list(NULL, function() stop("reset failed"))) {
    local_mocked_bindings(
      resolve_async_otel_cache_reset = function() {
        list(name = "test_reset", reset = hook)
      },
      .package = "shinyOAuth"
    )
    expect_identical(reset_async_otel_cache(character()), FALSE)
    # Force delivery each time, including when the warning is normally rate-limited.
    local_mocked_bindings(
      warn_pkg = function(...) warning("OTEL unavailable"),
      .package = "shinyOAuth"
    )
    withr::local_envvar(OTEL_SERVICE_NAME = "before")
    ran <- FALSE
    with_async_options(
      list(.shinyOAuth.otel_envvars = c(OTEL_SERVICE_NAME = "after")),
      {
        ran <- TRUE
        expect_false(getOption("shinyOAuth.otel_tracing_enabled"))
        expect_false(getOption("shinyOAuth.otel_logging_enabled"))
      }
    )
    expect_true(ran)
    expect_equal(getOption("warn"), 2)
  }
})
