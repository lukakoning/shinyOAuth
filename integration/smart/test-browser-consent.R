for (async in c(FALSE, TRUE)) for (consent in c("reduced", "no_refresh", "missing_required", "denied")) {
  testthat::test_that(paste("SMART consent", consent, "async", async), {
    f <- lifecycle_setup(async, list(consent = consent, access_lifetime = if (consent == "no_refresh") 10 else 3600),
      response_mode = if (async) "form_post" else "query")
    first <- lifecycle_authorize(f, "b", 1L)
    b_id <- lifecycle_connection(f[["browser"]], "b")[["connection_id"]]
    retention_browser_click(f[["browser"]], "connect_a")
    retention_browser_wait(f[["browser"]], function() identical(retention_browser_value(f[["browser"]],
      "document.querySelector('#provider')?.textContent"), "Site a"), "SMART consent page")
    retention_browser_click(f[["browser"]], if (consent == "denied") "deny" else "approve")
    refused <- consent %in% c("denied", "missing_required")
    retention_browser_wait(f[["browser"]], function() {
      value <- retention_browser_snapshot(f[["browser"]])
      !is.null(value) && value[["session"]] > first[["session"]] &&
        length(value[["connections"]]) == (if (refused) 1L else 2L) &&
        (!refused || length(value[["errors"]]) > 0L)
    }, "consent callback completion")
    testthat::expect_identical(lifecycle_connection(f[["browser"]], "b")[["connection_id"]], b_id)
    if (refused) {
      testthat::expect_gt(length(retention_browser_snapshot(f[["browser"]])[["errors"]]), 0L)
      retention_browser_action(f[["browser"]], "read_a", "unavailable")
      testthat::expect_identical(f[["metrics"]]()[["exchanges"]], if (consent == "denied") 0L else 1L)
      testthat::expect_identical(f[["metrics"]]()[["denials"]], if (consent == "denied") 1L else 0L)
      testthat::expect_identical(f[["metrics"]]()[["reads"]], 0L)
    } else {
      retention_browser_action(f[["browser"]], "read_a", "a:1:context-1")
      retention_browser_action(f[["browser"]], "user_a", "a:user")
      if (consent == "reduced") {
        testthat::expect_identical(lifecycle_connection(f[["browser"]], "a")[["status"]], "limited")
        retention_browser_action(f[["browser"]], "search_a", "unavailable")
        testthat::expect_identical(f[["metrics"]]()[["searches"]], 0L)
      } else {
        retention_browser_action(f[["browser"]], "refresh_a", "unavailable")
        expires <- f[["metrics"]]()[["access_expires"]]
        retention_browser_wait(f[["browser"]], function() as.numeric(Sys.time()) > expires + 1,
          "expiry without a refresh token", timeout = 15)
        retention_browser_action(f[["browser"]], "read_a", "unavailable")
        testthat::expect_identical(f[["metrics"]]()[["refresh_attempts"]], 0L)
        testthat::expect_identical(f[["metrics"]]()[["reads"]], 1L)
      }
    }
    retention_browser_action(f[["browser"]], "read_b", "b:1:context-1")
    testthat::expect_identical(f[["metrics"]]("b")[["reads"]], 1L)
    testthat::expect_identical(f[["metrics"]]("b")[["refresh_attempts"]], 0L)
  })
}
