cases <- expand.grid(async = c(FALSE, TRUE), response_mode = c("query", "form_post"),
  stringsAsFactors = FALSE)
for (index in seq_len(nrow(cases))) {
  async <- cases$async[[index]]
  response_mode <- cases$response_mode[[index]]
  testthat::test_that(paste("same issuer, shared route and isolated resources", response_mode, async), {
    f <- retention_browser_setup(async, response_mode, shared_issuer = TRUE)
    retention_evidence_env$chrome <- f$chrome$Browser$getVersion()$product
    a <- f$browser
    context <- f$chrome$Target$getTargetInfo(targetId = a$get_target_id())$targetInfo$browserContextId
    target <- f$chrome$Target$createTarget("about:blank", browserContextId = context)$targetId
    b <- chromote::ChromoteSession$new(parent = f$chrome, targetId = target)
    withr::defer(b$close())
    retention_browser_value(b, paste0("window.location.replace(",
      jsonlite::toJSON(f$origin, auto_unbox = TRUE), ")"))
    retention_browser_wait(b, function() retention_browser_snapshot(b), "second tab")
    begin <- function(browser, site) {
      retention_browser_click(browser, paste0("connect_", site))
      retention_browser_wait(browser, function() identical(retention_browser_value(browser,
        "document.querySelector('#provider')?.textContent"), paste("Site", site)), "authorization page")
      testthat::expect_identical(retention_browser_value(browser, "location.hostname"), "localhost")
    }
    begin(a, "a")
    begin(b, "b")
    # The most recently selected client is B; A's pending callback must still
    # import A. Both tabs use the same browser owner and one callback URL.
    finish <- function(browser, count) {
      retention_browser_click(browser, "approve")
      value <- retention_browser_wait(browser, function() {
        snapshot <- retention_browser_snapshot(browser)
        if (!is.null(snapshot) && length(snapshot$connections) == count) snapshot else NULL
      }, "shared callback completion")
      testthat::expect_length(value$errors, 0L)
      testthat::expect_identical(retention_browser_value(browser, "location.pathname"), "/callback/shared")
      testthat::expect_identical(retention_browser_value(browser, "location.search"), "")
      value
    }
    first <- finish(a, 1L)
    testthat::expect_identical(first$connections[[1L]]$client_label, "Site a")
    both <- finish(b, 2L)
    testthat::expect_setequal(vapply(both$connections, function(row) row$client_label, character(1)),
      c("Site a", "Site b"))
    if (response_mode == "form_post") {
      testthat::expect_length(both$post_owner_cookies, 2L)
      testthat::expect_false(any(unlist(both$post_owner_cookies)))
    }
    for (site in c("a", "b")) {
      retention_browser_action(b, paste0("read_", site), paste0(site, ":1"))
      retention_browser_action(b, paste0("refresh_", site), "refreshed")
      retention_browser_action(b, paste0("read_", site), paste0(site, ":2"))
    }
    metrics <- function() httr2::request(f$providers$shared$url("/metrics")) |>
      httr2::req_timeout(5) |> httr2::req_perform() |> httr2::resp_body_json()
    before <- metrics()
    testthat::expect_identical(before$exchanges, 2L)
    testthat::expect_identical(before$refreshes, 2L)
    testthat::expect_identical(before$requests, 4L)
    retention_browser_action(b, "cross_resource", "unavailable")
    testthat::expect_identical(metrics()$requests, before$requests)
    # Separate browser process gives a separate owner while both original tabs
    # remain live. Connection IDs convey no authority to that other owner.
    foreign_chrome <- chromote::Chromote$new()
    withr::defer(retention_chrome_close(foreign_chrome))
    foreign <- f$new_browser(foreign_chrome)
    testthat::expect_length(retention_browser_snapshot(foreign)$connections, 0L)
    retention_browser_value(foreign, paste0("Shiny.setInputValue('probe_id',",
      jsonlite::toJSON(first$connections[[1L]]$connection_id, auto_unbox = TRUE), ",{priority:'event'})"))
    retention_browser_action(foreign, "probe", "unavailable")
    retention_browser_click(b, "logout")
    retention_browser_wait(a, function() {
      snapshot <- retention_browser_snapshot(a)
      !is.null(snapshot) && length(snapshot$connections) == 0L
    }, "logout invalidates both tabs")
    testthat::expect_identical(metrics()$exchanges, 2L)
  })
}
