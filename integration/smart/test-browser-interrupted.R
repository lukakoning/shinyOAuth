for (operation in c("disconnect", "logout")) {
  testthat::test_that(
    paste(operation, "wins against a delayed SMART refresh"),
    {
      f <- lifecycle_setup(
        TRUE,
        list(refresh_delay = 6),
        list(http_timeout = 20)
      )
      lifecycle_authorize(f, "a", 1L)
      lifecycle_authorize(f, "b", 2L)
      retention_browser_click(f[["browser"]], "refresh_a")
      retention_browser_wait(
        f[["browser"]],
        function() f[["metrics"]]()[["refreshes"]] == 1L,
        "refresh credential consumed"
      )
      testthat::expect_identical(f[["metrics"]]()[["refresh_responses"]], 0L)
      retention_browser_click(
        f[["browser"]],
        if (operation == "logout") "logout" else "disconnect_a"
      )
      retention_browser_wait(
        f[["browser"]],
        function() {
          value <- retention_browser_snapshot(f[["browser"]])
          if (operation == "logout") {
            !is.null(value) && length(value[["connections"]]) == 0L
          } else {
            identical(
              lifecycle_connection(f[["browser"]], "a")[["status"]],
              "disconnected"
            )
          }
        },
        "local invalidation before refresh response"
      )
      retention_browser_wait(
        f[["browser"]],
        function() f[["metrics"]]()[["refresh_responses"]] == 1L,
        "late refresh response"
      )
      # Let the worker completion reach Shiny, then recheck through a fresh session.
      f[["browser"]][["Page"]][["navigate"]](paste0(f[["origin"]], "/retained"))
      retention_browser_wait(
        f[["browser"]],
        function() retention_browser_snapshot(f[["browser"]]),
        "post-invalidation session"
      )
      retention_browser_action(f[["browser"]], "read_a", "unavailable")
      retention_browser_action(f[["browser"]], "refresh_a", "unavailable")
      testthat::expect_identical(f[["metrics"]]()[["refresh_attempts"]], 1L)
      testthat::expect_identical(f[["metrics"]]()[["reads"]], 0L)
      if (operation == "disconnect") {
        retention_browser_action(f[["browser"]], "read_b", "b:1:context-1")
      } else {
        retention_browser_action(f[["browser"]], "read_b", "unavailable")
      }
    }
  )
}

testthat::test_that("two Shiny tabs cannot consume the same rotating SMART grant", {
  f <- lifecycle_setup(TRUE, list(refresh_delay = 5), list(http_timeout = 20))
  lifecycle_authorize(f, "a", 1L)
  context <- f[["chrome"]][["Target"]][["getTargetInfo"]](
    targetId = f[["browser"]][["get_target_id"]]()
  )[["targetInfo"]][["browserContextId"]]
  target <- f[["chrome"]][["Target"]][["createTarget"]](
    "about:blank",
    browserContextId = context
  )[["targetId"]]
  second <- chromote::ChromoteSession[["new"]](
    parent = f[["chrome"]],
    targetId = target
  )
  withr::defer(second[["close"]]())
  second[["Security"]][["setIgnoreCertificateErrors"]](ignore = TRUE)
  second[["Page"]][["navigate"]](f[["origin"]])
  retention_browser_wait(
    second,
    function() {
      length(retention_browser_snapshot(second)[["connections"]]) == 1L
    },
    "second tab"
  )
  retention_browser_click(f[["browser"]], "refresh_a")
  retention_browser_wait(
    f[["browser"]],
    function() f[["metrics"]]()[["refreshes"]] == 1L,
    "rotating refresh in progress"
  )
  testthat::expect_identical(f[["metrics"]]()[["refresh_responses"]], 0L)
  retention_browser_action(second, "refresh_a", "unavailable")
  first_result <- retention_browser_wait(
    f[["browser"]],
    function() {
      value <- retention_browser_snapshot(f[["browser"]])
      if (!is.null(value) && value[["result_revision"]] > 0L) value else NULL
    },
    "first tab refresh completion"
  )
  testthat::expect_identical(
    first_result[["result"]],
    "refreshed",
    info = jsonlite::toJSON(
      list(
        metrics = f[["metrics"]](),
        connections = first_result[["connections"]]
      ),
      auto_unbox = TRUE
    )
  )
  for (browser in list(f[["browser"]], second)) {
    retention_browser_action(browser, "read_a", "a:2:context-1")
  }
  testthat::expect_identical(f[["metrics"]]()[["refresh_attempts"]], 1L)
  testthat::expect_identical(f[["metrics"]]()[["reads"]], 2L)
})

for (async in c(FALSE, TRUE)) {
  testthat::test_that(
    paste(
      "consumed SMART refresh with lost response requires reconnection",
      async
    ),
    {
      f <- lifecycle_setup(
        async,
        list(refresh_delay = 10),
        list(http_timeout = 20)
      )
      lifecycle_authorize(f, "a", 1L)
      lifecycle_authorize(f, "b", 2L)
      retention_browser_click(f[["browser"]], "refresh_a")
      retention_browser_wait(
        f[["browser"]],
        function() f[["metrics"]]()[["refreshes"]] == 1L,
        "refresh consumed before disconnect"
      )
      testthat::expect_identical(f[["metrics"]]()[["refresh_responses"]], 0L)
      testthat::expect_identical(f[["metrics"]]()[["refresh_attempts"]], 1L)
      # Stop only this owned fixture while its response is pending: the actual
      # socket closes after consuming/rotating the credential, before delivery.
      f[["providers"]][["a"]][["stop"]]()
      retention_browser_result(f[["browser"]], "unavailable")
      retention_browser_wait(
        f[["browser"]],
        function() {
          identical(
            lifecycle_connection(f[["browser"]], "a")[["status"]],
            "uncertain"
          )
        },
        "uncertain credential lifecycle"
      )
      retention_browser_action(f[["browser"]], "refresh_a", "unavailable")
      retention_browser_action(f[["browser"]], "read_a", "unavailable")
      retention_browser_action(f[["browser"]], "read_b", "b:1:context-1")
      testthat::expect_identical(
        lifecycle_connection(f[["browser"]], "a")[["status"]],
        "uncertain"
      )
      testthat::expect_identical(f[["metrics"]]("b")[["reads"]], 1L)
    }
  )
}
