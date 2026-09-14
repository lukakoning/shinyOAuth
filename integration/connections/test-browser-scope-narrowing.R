cases <- expand.grid(async = c(FALSE, TRUE), response_mode = c("query", "form_post"),
  stringsAsFactors = FALSE)
for (index in seq_len(nrow(cases))) {
  async <- cases$async[[index]]
  response_mode <- cases$response_mode[[index]]
  testthat::test_that(paste("retained refresh scope narrowing", response_mode, async), {
    f <- retention_browser_setup(async, response_mode, scope_narrowing = TRUE)
    retention_evidence_env$chrome <- f$chrome$Browser$getVersion()$product
    browser <- f$browser
    authorize <- function(site, count) {
      retention_browser_click(browser, paste0("connect_", site))
      retention_browser_wait(browser, function() identical(retention_browser_value(browser,
        "document.querySelector('#provider')?.textContent"), paste("Site", site)), "authorization page")
      retention_browser_click(browser, "approve")
      retention_browser_wait(browser, function() {
        snapshot <- retention_browser_snapshot(browser)
        if (!is.null(snapshot) && length(snapshot$connections) == count) snapshot else NULL
      }, "authorization completed")
    }
    metrics <- function(site) httr2::request(f$providers[[site]]$url("/metrics")) |>
      httr2::req_timeout(5) |> httr2::req_perform() |> httr2::resp_body_json()
    first <- authorize("a", 1L)
    id <- first$connections[[1L]]$connection_id
    retention_browser_action(browser, "write_a", "a:written")
    testthat::expect_identical(metrics("a")$writes, 1L)
    retention_browser_action(browser, "narrow_a", "refreshed")
    retention_browser_action(browser, "write_a", "unavailable")
    testthat::expect_identical(metrics("a")$writes, 1L)
    retention_browser_action(browser, "read_a", "a:2")
    narrowed <- retention_browser_snapshot(browser)
    testthat::expect_identical(narrowed$connections[[1L]]$connection_id, id)
    testthat::expect_identical(narrowed$connections[[1L]]$status, "limited")
    testthat::expect_identical(metrics("a")$scoped_refreshes, 1L)
    both <- authorize("b", 2L)
    testthat::expect_gt(both$session, narrowed$session)
    testthat::expect_length(both$errors, 0L)
    # A new Shiny session must restore the local narrowing policy from the
    # encrypted record. An omitted wire scope would restore read+write here.
    retention_browser_action(browser, "refresh_a", "refreshed")
    testthat::expect_identical(metrics("a")$scoped_refreshes, 2L)
    testthat::expect_identical(metrics("a")$omitted_refreshes, 0L)
    retention_browser_action(browser, "write_a", "unavailable")
    retention_browser_action(browser, "read_a", "a:3")
    for (action in c("widen_a", "drop_required")) {
      retention_browser_action(browser, action, "unavailable")
      testthat::expect_identical(metrics("a")$refreshes, 2L)
      retention_browser_action(browser, "read_a", "a:3")
    }
    retention_browser_action(browser, "refresh_b", "refreshed")
    testthat::expect_identical(metrics("b")$scoped_refreshes, 0L)
    testthat::expect_identical(metrics("b")$omitted_refreshes, 1L)
    retention_browser_action(browser, "write_b", "b:written")
    testthat::expect_identical(metrics("b")$writes, 1L)
    testthat::expect_identical(metrics("a")$writes, 1L)
    testthat::expect_length(retention_browser_snapshot(browser)$errors, 0L)
    retention_browser_click(browser, "logout")
    retention_browser_wait(browser, function() {
      snapshot <- retention_browser_snapshot(browser)
      !is.null(snapshot) && length(snapshot$connections) == 0L
    }, "logout")
  })
}
