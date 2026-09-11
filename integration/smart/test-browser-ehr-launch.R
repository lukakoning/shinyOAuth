for (async_mode in async_modes) {
  for (callback_mode in response_modes) {
    testthat::test_that(paste("EHR browser launch", callback_mode, if (async_mode) "mirai" else "sync"), {
      f <- retention_browser_setup(async_mode, callback_mode,
        provider_factory = smart_ehr_fixture_provider,
        app_script = "integration/smart/fixture-ehr-app.R", app_function = "smart_ehr_fixture_app")
      retention_evidence_env$chrome <- f$chrome$Browser$getVersion()$product
      browser <- f$browser
      browser$Network$clearBrowserCookies()
      browser$Page$navigate(paste0(f$bases$a, "/ehr-launch"))
      retention_browser_wait(browser, function() {
        identical(retention_browser_value(browser, "document.querySelector('#provider')?.textContent"), "Site a")
      }, "EHR A authorization")
      # A second tab shares the local browser owner but has its own launch and
      # OAuth transaction. Both launches are in flight before either approval.
      context_id <- f$chrome$Target$getTargetInfo(targetId = browser$get_target_id())$targetInfo$browserContextId
      testthat::expect_true(is.character(context_id) && length(context_id) == 1L && nzchar(context_id))
      target_id <- f$chrome$Target$createTarget("about:blank", browserContextId = context_id)$targetId
      second <- chromote::ChromoteSession$new(parent = f$chrome, targetId = target_id)
      withr::defer(second$close())
      second$Page$navigate(paste0(f$bases$b, "/ehr-launch"))
      retention_browser_wait(second, function() {
        identical(retention_browser_value(second, "document.querySelector('#provider')?.textContent"), "Site b")
      }, "EHR B authorization")
      testthat::expect_true(retention_browser_value(browser, "location.pathname === '/authorize'"))
      retention_browser_click(browser, "approve")
      retention_browser_wait(browser, function() {
        snapshot <- retention_browser_snapshot(browser)
        !is.null(snapshot) && length(snapshot$connections) == 1L
      }, "accepted connection A")
      retention_browser_click(second, "approve")
      retention_browser_wait(second, function() {
        snapshot <- retention_browser_snapshot(second)
        !is.null(snapshot) && length(snapshot$connections) == 2L
      }, "retained A and accepted B")
      rows <- retention_browser_snapshot(second)$connections
      testthat::expect_setequal(vapply(rows, `[[`, "", "target_label"), c("Site a", "Site b"))
      testthat::expect_true(all(vapply(rows, `[[`, "", "status") == "active"))
      for (site in c("a", "b")) {
        retention_browser_click(second, paste0("read_", site))
        retention_browser_result(second, paste0(site, ":1:context-1"))
        testthat::expect_identical(retention_browser_value(second,
          "document.querySelector('#result').textContent"), paste0(site, ":1:context-1"))
      }
      retention_browser_click(second, "refresh_a")
      retention_browser_result(second, "refreshed")
      retention_browser_click(second, "read_a")
      retention_browser_result(second, "a:2:context-1")
      testthat::expect_identical(retention_browser_value(second,
        "document.querySelector('#result').textContent"), "a:2:context-1")
      testthat::expect_true(retention_browser_value(second,
        "!location.search.includes('launch=') && !location.search.includes('iss=')"))
      metrics <- function(site) httr2::resp_body_json(httr2::req_perform(httr2::request(paste0(f$bases[[site]], "/metrics"))))
      before <- metrics("a")$authorizations
      retention_browser_click(second, "connect_a")
      retention_browser_wait(second, function() {
        snapshot <- retention_browser_snapshot(second)
        !is.null(snapshot) && identical(snapshot$errors$smart_launch, "fresh_ehr_launch_required")
      }, "fresh EHR launch required for reconnect")
      testthat::expect_identical(metrics("a")$authorizations, before)
      testthat::expect_length(retention_browser_snapshot(second)$connections, 2L)
      # Keep both launch tabs active while a separate Chrome process tests
      # another browser owner. Each process uses an isolated browser context.
      foreign_chrome <- chromote::Chromote$new()
      withr::defer(retention_chrome_close(foreign_chrome))
      foreign <- f$new_browser(foreign_chrome)
      testthat::expect_length(retention_browser_snapshot(foreign)$connections, 0L)
      retention_browser_click(second, "logout")
      retention_browser_wait(second, function() {
        snapshot <- retention_browser_snapshot(second)
        !is.null(snapshot) && length(snapshot$connections) == 0L
      }, "local logout")
      testthat::expect_length(retention_browser_snapshot(second)$connections, 0L)
      for (site in c("a", "b")) {
        result <- metrics(site)
        testthat::expect_identical(result$launches, 1L)
        testthat::expect_identical(result$authorizations, 1L)
        testthat::expect_identical(result$exchanges, 1L)
        testthat::expect_gte(result$requests, 1L)
      }
      testthat::expect_identical(metrics("a")$refreshes, 1L)
      testthat::expect_identical(metrics("b")$refreshes, 0L)
    })
  }
}
