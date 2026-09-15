for (index in seq_len(nrow(cases))) {
  row <- cases[index, ]
  testthat::test_that(paste("mixed OIDC/SMART", paste(unlist(row), collapse = " ")), {
    provider_factory <- function(site, callback) smart_profile_provider(site, callback,
      registration = list(style = "public"), launch = "standalone", https = TRUE,
      behavior = list(ordinary_oidc = site == "b",
        access_lifetime = if (site == "b" && !row[["managed_oidc"]]) 12 else 3600))
    f <- retention_browser_setup(row[["async"]], row[["response_mode"]], provider_factory = provider_factory,
      app_script = "integration/smart/fixture-mixed-app.R", app_function = "smart_mixed_app",
      app_args = list(managed_oidc = row[["managed_oidc"]]), https = TRUE, https_providers = TRUE)
    retention_evidence_env[["chrome"]] <- f[["chrome"]][["Browser"]][["getVersion"]]()[["product"]]
    browser <- f[["browser"]]
    authorize <- function(site) {
      retention_browser_click(browser, paste0("connect_", site))
      retention_browser_wait(browser, function() identical(retention_browser_value(browser,
        "document.querySelector('#provider')?.textContent"), paste("Site", site)), "authorization page")
      testthat::expect_identical(retention_browser_value(browser, "location.origin"), f[["bases"]][[site]])
      retention_browser_click(browser, "approve")
      retention_browser_wait(browser, function() {
        value <- retention_browser_snapshot(browser)
        if (is.null(value)) return(NULL)
        if (site == "b") return(if (isTRUE(value[["oidc_authenticated"]])) value else NULL)
        rows <- Filter(function(x) x[["client_label"]] == "SMART" && x[["status"]] == "active", value[["connections"]])
        if (length(rows)) value else NULL
      }, "authorization callback")
    }
    authorize("b")
    retention_browser_action(browser, "identity_b", "identity:ok")
    first <- authorize("a")
    testthat::expect_identical(first[["oidc_authenticated"]], row[["managed_oidc"]])
    id <- Filter(function(x) x[["client_label"]] == "SMART", first[["connections"]])[[1]][["connection_id"]]
    if (!row[["managed_oidc"]]) authorize("b")
    both <- retention_browser_snapshot(browser)
    testthat::expect_length(both[["errors"]], 0L)
    testthat::expect_identical(Filter(function(x) x[["client_label"]] == "SMART", both[["connections"]])[[1]][["connection_id"]], id)
    retention_browser_action(browser, "read_a", "a:1")
    retention_browser_action(browser, "read_b", "b:1")
    retention_browser_action(browser, "identity_b", "identity:ok")
    if (row[["managed_oidc"]]) {
      retention_browser_action(browser, "refresh_b", "refreshed")
    } else {
      expiry <- retention_browser_snapshot(browser)[["oidc_expiry"]]
      retention_browser_wait(browser, function() {
        value <- retention_browser_snapshot(browser)
        !is.null(value) && !is.null(value[["oidc_expiry"]]) && value[["oidc_expiry"]] > expiry
      }, "ordinary module proactive refresh")
    }
    retention_browser_action(browser, "read_b", "b:2")
    retention_browser_action(browser, "identity_b", "identity:ok")
    retention_browser_action(browser, "refresh_a", "refreshed")
    retention_browser_action(browser, "read_a", "a:2")
    retention_browser_click(browser, "disconnect_a")
    retention_browser_wait(browser, function() {
      rows <- retention_browser_snapshot(browser)[["connections"]]
      any(vapply(rows, function(x) x[["client_label"]] == "SMART" && x[["status"]] == "disconnected", logical(1)))
    }, "local SMART disconnect")
    retention_browser_action(browser, "read_b", "b:2")
    retention_browser_action(browser, "identity_b", "identity:ok")
    testthat::expect_true(retention_browser_snapshot(browser)[["oidc_authenticated"]])
    retention_browser_click(browser, "logout_b")
    retention_browser_wait(browser, function() {
      value <- retention_browser_snapshot(browser)
      !is.null(value) && identical(value[["oidc_authenticated"]], FALSE)
    }, "OIDC logout")
    testthat::expect_false(retention_browser_snapshot(browser)[["oidc_authenticated"]])
  })
}
