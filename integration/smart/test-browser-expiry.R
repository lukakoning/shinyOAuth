for (async in c(FALSE, TRUE)) for (revoked in c(FALSE, TRUE)) {
  testthat::test_that(paste("expired retained SMART grant", async, "revoked", revoked), {
    f <- lifecycle_setup(async, list(access_lifetime = 10))
    lifecycle_authorize(f, "a", 1L)
    both <- lifecycle_authorize(f, "b", 2L)
    id <- lifecycle_connection(f$browser, "a")$connection_id
    expires <- f$metrics()$access_expires
    testthat::expect_gt(expires, as.numeric(Sys.time()))
    # End the only Shiny session. No observer can refresh while the app is closed.
    f$browser$Page$navigate("about:blank")
    if (revoked) f$control("revoke")
    retention_browser_wait(f$browser, function() as.numeric(Sys.time()) > expires + 1,
      "actual access-token expiry", timeout = 15)
    testthat::expect_identical(f$metrics()$refresh_attempts, 0L)
    f$browser$Page$navigate(f$origin)
    retention_browser_wait(f$browser, function() {
      value <- retention_browser_snapshot(f$browser)
      !is.null(value) && value$session > both$session && length(value$connections) == 2L &&
        f$metrics()$refresh_attempts == 1L
    }, "automatic refresh after restoration")
    testthat::expect_identical(lifecycle_connection(f$browser, "a")$connection_id, id)
    if (revoked) {
      retention_browser_action(f$browser, "read_a", "unavailable")
      testthat::expect_identical(f$metrics()$refreshes, 0L)
      testthat::expect_identical(f$metrics()$reads, 0L)
      testthat::expect_false(lifecycle_connection(f$browser, "a")$status %in% c("active", "limited"))
    } else {
      retention_browser_wait(f$browser, function() identical(lifecycle_connection(f$browser, "a")$status,
        "active"), "refreshed grant committed")
      retention_browser_action(f$browser, "read_a", "a:2:context-1")
      retention_browser_action(f$browser, "user_a", "a:user")
      testthat::expect_identical(f$metrics()$refreshes, 1L)
      testthat::expect_identical(f$metrics()$reads, 1L)
    }
    retention_browser_action(f$browser, "read_b", "b:1:context-1")
    testthat::expect_identical(f$metrics("b")$refresh_attempts, 0L)
    testthat::expect_identical(f$metrics()$expired_reads, 0L)
  })
}
