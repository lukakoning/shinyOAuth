cases <- expand.grid(async = c(FALSE, TRUE), response_mode = c("query", "form_post"),
  grant_reuse = c(FALSE, TRUE), stringsAsFactors = FALSE)
for (index in seq_len(nrow(cases))) {
  case <- cases[index, ]
  testthat::test_that(paste("repeated same-client authorization", case[["response_mode"]],
    "async", case[["async"]], "reused credentials", case[["grant_reuse"]]), {
    f <- retention_browser_setup(case[["async"]], case[["response_mode"]],
      provider_factory = function(site, callback) retention_fixture_provider(site, callback,
        authorization_method = authorization_method, grant_reuse = case[["grant_reuse"]]),
      app_args = list(authorization_method = authorization_method))
    browser <- f[["browser"]]
    retention_evidence_env[["chrome"]] <- f[["chrome"]][["Browser"]][["getVersion"]]()[["product"]]
    ids <- function(snapshot) vapply(snapshot[["connections"]], function(row) row[["connection_id"]], character(1))
    authorize <- function(count) {
      retention_browser_click(browser, "connect_a")
      retention_browser_wait(browser, function() identical(retention_browser_value(browser,
        "document.querySelector('#provider')?.textContent"), "Site a"), "same provider")
      retention_browser_click(browser, "approve")
      snapshot <- retention_browser_wait(browser, function() {
        snapshot <- retention_browser_snapshot(browser)
        if (!is.null(snapshot) && length(snapshot[["connections"]]) == count) snapshot else NULL
      }, "repeated authorization callback")
      testthat::expect_length(snapshot[["errors"]], 0L)
      testthat::expect_identical(retention_browser_value(browser, "location.search"), "")
      snapshot
    }
    select <- function(id) {
      retention_browser_value(browser, paste0("Shiny.setInputValue('selected_id',",
        jsonlite::toJSON(id, auto_unbox = TRUE), ",{priority:'event'})"))
    }
    first <- authorize(1L)
    both <- authorize(2L)
    testthat::expect_gt(both[["session"]], first[["session"]])
    a <- ids(first)[[1L]]
    b <- setdiff(ids(both), a)[[1L]]
    testthat::expect_false(identical(a, b))
    testthat::expect_true(all(vapply(both[["connections"]],
      function(row) identical(row[["client_label"]], "Site a"), logical(1))))
    accounts <- if (case[["grant_reuse"]]) c(1L, 1L) else c(1L, 2L)
    for (i in 1:2) {
      select(c(a, b)[[i]])
      retention_browser_action(browser, "read_selected", paste("a", accounts[[i]], 1L, sep = ":"))
    }
    browser[["Page"]][["navigate"]](paste0(f[["origin"]], "/"))
    restored <- retention_browser_wait(browser, function() {
      snapshot <- retention_browser_snapshot(browser)
      if (!is.null(snapshot) && snapshot[["session"]] > both[["session"]] && length(snapshot[["connections"]]) == 2L) {
        snapshot
      } else NULL
    }, "both same-client records after navigation")
    testthat::expect_setequal(ids(restored), c(a, b))
    select(a)
    retention_browser_action(browser, "refresh_selected", "refreshed")
    retention_browser_action(browser, "read_selected", "a:1:2")
    select(b)
    if (case[["grant_reuse"]]) {
      # A's rotation retires B's known copy locally, before any replay reaches AS.
      retention_browser_action(browser, "refresh_selected", "unavailable")
      retention_browser_action(browser, "read_selected", "unavailable")
    } else {
      retention_browser_action(browser, "refresh_selected", "refreshed")
      retention_browser_action(browser, "read_selected", "a:2:2")
    }
    retention_browser_action(browser, "disconnect_selected", "disconnected")
    retention_browser_action(browser, "read_selected", "unavailable")
    select(a)
    retention_browser_action(browser, "read_selected", "a:1:2")
    metrics <- httr2::request(f[["providers"]][["a"]][["url"]]("/metrics")) |>
      httr2::req_timeout(5) |> httr2::req_perform() |> httr2::resp_body_json()
    testthat::expect_identical(metrics[["exchanges"]], 2L)
    testthat::expect_identical(metrics[["refreshes"]], if (case[["grant_reuse"]]) 1L else 2L)
    testthat::expect_identical(metrics[["rejected_refreshes"]], 0L)
    testthat::expect_identical(metrics[["revocations"]], 0L)
    testthat::expect_length(retention_browser_snapshot(browser)[["errors"]], 0L)
  })
}
