# Run with Rscript integration/connections/run-tests.R --strict (optionally --post).
for (async in c(FALSE, TRUE)) for (response_mode in c("query", "form_post")) {
  testthat::test_that(paste("Strict owner callbacks", response_mode, "async =", async), {
    f <- retention_browser_setup(async, response_mode,
      provider_factory = function(site, callback) retention_fixture_provider(site, callback,
        authorization_method = authorization_method),
      app_args = list(same_site = "Strict", authorization_method = authorization_method))
    retention_evidence_env[["chrome"]] <- f[["chrome"]][["Browser"]][["getVersion"]]()[["product"]]
    browser <- f[["browser"]]
    callback_responses <- list()
    browser[["Network"]][["enable"]]()
    browser[["Network"]][["responseReceived"]](function(params) {
      response <- params[["response"]]
      if (identical(params[["type"]], "Document") &&
          startsWith(response[["url"]], paste0(f[["origin"]], "/callback/"))) {
        callback_responses[[length(callback_responses) + 1L]] <<- list(
          status = response[["status"]],
          sets_cookie = "set-cookie" %in% tolower(names(response[["headers"]])))
      }
    })
    owner_cookie <- function() Filter(function(cookie) isTRUE(cookie[["httpOnly"]]),
      browser[["Network"]][["getCookies"]](urls = list(f[["origin"]]))[["cookies"]])
    initial_cookie <- owner_cookie()[[1L]]
    testthat::expect_identical(initial_cookie[["sameSite"]], "Strict")
    authorize <- function() {
      retention_browser_click(browser, "connect_a")
      retention_browser_wait(browser, function() identical(retention_browser_value(browser,
        "document.querySelector('#provider')?.textContent"), "Site a"), "provider consent")
      testthat::expect_identical(retention_browser_value(browser, "location.hostname"), "localhost")
    }
    authorize()
    retention_browser_click(browser, "approve")
    completed <- retention_browser_wait(browser, function() {
      snapshot <- retention_browser_snapshot(browser)
      if (!is.null(snapshot) && length(snapshot[["connections"]]) == 1L) return(snapshot)
      if (isTRUE(retention_browser_value(browser,
        "document.body.textContent.includes('The local owner session ended')"))) return("owner ended")
      NULL
    }, "Strict callback completion")
    testthat::expect_true(is.list(completed), info = "Strict callback must retain the existing owner")
    if (is.list(completed)) {
      testthat::expect_length(completed[["errors"]], 0L)
      testthat::expect_false(any(unlist(completed[["callback_owner_cookies"]])))
      testthat::expect_length(completed[["callback_owner_cookies"]], 1L)
      testthat::expect_identical(owner_cookie()[[1L]][["value"]], initial_cookie[["value"]])
      testthat::expect_identical(retention_browser_value(browser, "location.search"), "")
      retention_browser_action(browser, "read_a", "a:1")

      # A document hop must not create an owner when the actual cookie is gone.
      authorize()
      browser[["Network"]][["deleteCookies"]](name = initial_cookie[["name"]], url = f[["origin"]])
      testthat::expect_length(owner_cookie(), 0L)
      retention_browser_click(browser, "approve")
      retention_browser_wait(browser, function() isTRUE(retention_browser_value(browser,
        "document.body.textContent.includes('The local owner session ended')")), "missing owner rejection")
      testthat::expect_equal(vapply(callback_responses, `[[`, 0, "status"), c(200, 200, 200, 400))
      testthat::expect_false(any(vapply(callback_responses, `[[`, FALSE, "sets_cookie")))
      metrics <- httr2::request(f[["providers"]][["a"]][["url"]]("/metrics")) |>
        httr2::req_perform() |> httr2::resp_body_json()
      testthat::expect_identical(metrics[["exchanges"]], 1L)
    }
  })
}
