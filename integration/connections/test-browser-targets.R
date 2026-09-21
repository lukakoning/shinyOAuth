for (async in c(FALSE, TRUE)) {
  for (response_mode in c("query", "form_post")) {
    testthat::test_that(
      paste(
        "single-module secondary restrictions survive redirects",
        response_mode,
        async
      ),
      {
        f <- retention_browser_setup(
          async,
          response_mode,
          provider_factory = function(site, callback) {
            target_fixture_provider(site, sub("/callback/[ab]$", "/", callback))
          },
          app_script = "integration/connections/fixture-target-app.R",
          app_function = "target_fixture_app",
          app_args = list(single = TRUE)
        )
        browser <- f[["browser"]]
        sign_in <- function(button, previous = NULL) {
          retention_browser_click(browser, button)
          retention_browser_wait(
            browser,
            function() {
              identical(
                retention_browser_value(
                  browser,
                  "document.querySelector('#provider')?.textContent"
                ),
                "Site a"
              )
            },
            "single-module consent page"
          )
          retention_browser_click(browser, "approve")
          retention_browser_wait(
            browser,
            function() {
              snapshot <- retention_browser_snapshot(browser)
              rows <- snapshot[["connections"]]
              if (
                length(rows) == 1L &&
                  !identical(rows[[1L]][["connection_id"]], previous)
              ) {
                snapshot
              } else {
                NULL
              }
            },
            "single-module callback"
          )
        }
        first <- sign_in("connect")
        retention_browser_action(
          browser,
          "narrow_contacts",
          if (async) "refreshed" else "TRUE"
        )
        replacement <- sign_in(
          "reauthorize",
          first[["connections"]][[1L]][["connection_id"]]
        )
        testthat::expect_true(replacement[["can_write"]])
        testthat::expect_identical(
          replacement[["targets"]][["contacts"]][["status"]],
          "not_acquired"
        )
        # Check the local ceiling before acquisition; a provider rejection alone
        # must not mask a widened request in a newly created Shiny session.
        before <- httr2::resp_body_json(httr2::req_perform(httr2::request(f[[
          "providers"
        ]][["a"]][["url"]]("/metrics"))))
        retention_browser_action(browser, "contacts_write", "unavailable")
        after <- httr2::resp_body_json(httr2::req_perform(httr2::request(f[[
          "providers"
        ]][["a"]][["url"]]("/metrics"))))
        testthat::expect_identical(after[["refreshes"]], before[["refreshes"]])
        testthat::expect_identical(
          after[["token_scopes"]],
          before[["token_scopes"]]
        )
        retention_browser_action(browser, "contacts", "contacts")
        testthat::expect_identical(
          retention_browser_snapshot(browser)[["targets"]][["contacts"]][[
            "granted_scopes"
          ]],
          "contacts.read"
        )
        retention_browser_action(browser, "contacts_write", "unavailable")
      }
    )
  }
}

for (async in c(FALSE, TRUE)) {
  for (response_mode in c("query", "form_post")) {
    testthat::test_that(
      paste("target replacement and recovery", response_mode, async),
      {
        f <- retention_browser_setup(
          async,
          response_mode,
          provider_factory = target_fixture_provider,
          app_script = "integration/connections/fixture-target-app.R",
          app_function = "target_fixture_app"
        )
        retention_evidence_env[["chrome"]] <- f[["chrome"]][["Browser"]][[
          "getVersion"
        ]]()[["product"]]
        browser <- f[["browser"]]
        metrics <- function() {
          httr2::resp_body_json(httr2::req_perform(httr2::request(f[[
            "providers"
          ]][["a"]][["url"]]("/metrics"))))
        }
        wait_connection <- function(previous = NULL, empty = FALSE) {
          retention_browser_wait(
            browser,
            function() {
              snapshot <- retention_browser_snapshot(browser)
              if (is.null(snapshot)) {
                return(NULL)
              }
              rows <- snapshot[["connections"]]
              if (empty) {
                return(if (length(rows) == 0L) snapshot else NULL)
              }
              if (
                length(rows) == 1L &&
                  !identical(rows[[1L]][["connection_id"]], previous)
              ) {
                snapshot
              } else {
                NULL
              }
            },
            "replacement callback"
          )
        }
        start <- function(button) {
          retention_browser_click(browser, button)
          retention_browser_wait(
            browser,
            function() {
              identical(
                retention_browser_value(
                  browser,
                  "document.querySelector('#provider')?.textContent"
                ),
                "Site a"
              )
            },
            "target consent page"
          )
        }
        start("connect")
        retention_browser_click(browser, "approve")
        first <- wait_connection()
        first_id <- first[["connections"]][[1L]][["connection_id"]]
        testthat::expect_true(first[["can_write"]])
        testthat::expect_identical(
          first[["targets"]][["contacts"]][["status"]],
          "not_acquired"
        )
        retention_browser_action(browser, "wrong_target", "unavailable")
        testthat::expect_identical(metrics()[["refreshes"]], 0L)
        testthat::expect_identical(metrics()[["requests"]], 0L)
        retention_browser_action(browser, "contacts", "contacts")
        testthat::expect_identical(metrics()[["refreshes"]], 1L)
        testthat::expect_identical(metrics()[["requests"]], 1L)
        retention_browser_action(
          browser,
          "narrow",
          if (async) "refreshed" else "TRUE"
        )
        testthat::expect_false(retention_browser_snapshot(browser)[[
          "can_write"
        ]])
        start("reauthorize")
        requested <- tail(metrics()[["authorization_scopes"]], 1L)[[1L]]
        testthat::expect_setequal(
          strsplit(requested, " ", fixed = TRUE)[[1L]],
          c("calendar.read", "contacts.read")
        )
        retention_browser_click(browser, "approve")
        replacement <- wait_connection(first_id)
        old <- Filter(
          function(row) identical(row[["connection_id"]], first_id),
          replacement[["history"]]
        )
        testthat::expect_length(old, 1L)
        testthat::expect_identical(old[[1L]][["status"]], "disconnected")
        testthat::expect_false(replacement[["can_write"]])
        testthat::expect_identical(
          replacement[["connections"]][[1L]][["replaces_connection_id"]],
          first_id
        )
        testthat::expect_identical(
          replacement[["targets"]][["contacts"]][["status"]],
          "not_acquired"
        )
        if (async) {
          httr2::req_perform(httr2::req_body_form(
            httr2::request(f[["providers"]][["a"]][["url"]]("/delay")),
            seconds = 3
          ))
          retention_browser_action(browser, "pending", "pending")
          previous <- replacement[["connections"]][[1L]][["connection_id"]]
          start("reauthorize")
          retention_browser_click(browser, "approve")
          replacement <- wait_connection(previous)
          testthat::expect_false(replacement[["can_write"]])
          testthat::expect_identical(
            replacement[["connections"]][[1L]][["replaces_connection_id"]],
            previous
          )
          testthat::expect_identical(
            replacement[["targets"]][["contacts"]][["status"]],
            "not_acquired"
          )
          httr2::req_perform(httr2::req_body_form(
            httr2::request(f[["providers"]][["a"]][["url"]]("/delay")),
            seconds = 0
          ))
        }
        retention_browser_action(browser, "contacts", "contacts")
        start("reauthorize")
        retention_browser_click(browser, "deny")
        cancelled <- wait_connection(empty = TRUE)
        testthat::expect_length(cancelled[["connections"]], 0L)
        testthat::expect_false(cancelled[["can_write"]])
        start("connect")
        retention_browser_click(browser, "approve")
        fresh <- wait_connection()
        testthat::expect_true(fresh[["can_write"]])
        retention_browser_click(browser, "logout")
        wait_connection(empty = TRUE)
        start("connect")
        retention_browser_click(browser, "approve")
        recovered <- wait_connection()
        testthat::expect_true(recovered[["can_write"]])
        testthat::expect_length(recovered[["errors"]], 0L)
        testthat::expect_false(identical(
          recovered[["connections"]][[1L]][["connection_id"]],
          fresh[["connections"]][[1L]][["connection_id"]]
        ))
        retention_browser_action(browser, "contacts", "contacts")
      }
    )
  }
}
