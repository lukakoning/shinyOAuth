for (async in c(FALSE, TRUE)) for (changed in c(FALSE, TRUE)) {
  testthat::test_that(paste("SMART refresh context", async, "changed", changed), {
    expected <- list(patient = if (changed) "synthetic-a-new" else "synthetic-a",
      encounter = if (changed) NULL else "encounter-a", revision = if (changed) 2L else 1L)
    f <- lifecycle_setup(async, list(change_patient = changed), list(expected_context = expected))
    first <- lifecycle_authorize(f, "a", 1L)
    retention_browser_action(f$browser, "read_a", "a:1:context-1")
    retention_browser_action(f$browser, "refresh_a", "refreshed")
    retention_browser_action(f$browser, "check_context", "context:ok")
    retention_browser_action(f$browser, "read_a", paste0("a:2:context-", expected$revision))
    retention_browser_action(f$browser, "user_a", "a:user")
    f$browser$Page$navigate(paste0(f$origin, "/retained"))
    retention_browser_wait(f$browser, function() {
      value <- retention_browser_snapshot(f$browser)
      !is.null(value) && value$session > first$session && length(value$connections) == 1L
    }, "context restoration")
    retention_browser_action(f$browser, "check_context", "context:ok")
    retention_browser_action(f$browser, "read_a", paste0("a:2:context-", expected$revision))
    testthat::expect_identical(f$metrics()$exchanges, 1L)
    testthat::expect_identical(f$metrics()$refreshes, 1L)
    testthat::expect_identical(f$metrics()$reads, 3L)
    testthat::expect_identical(f$metrics()$users, 1L)
  })
}
