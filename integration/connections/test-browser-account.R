cases <- expand.grid(
  async = c(FALSE, TRUE),
  response_mode = c("query", "form_post"),
  stringsAsFactors = FALSE
)
for (index in seq_len(nrow(cases))) {
  testthat::test_that(
    paste(
      "account login and retained authorization",
      cases$response_mode[[index]],
      "async =",
      cases$async[[index]]
    ),
    {
      f <- retention_browser_setup(
        cases$async[[index]],
        cases$response_mode[[index]],
        app_script = "integration/connections/fixture-account-app.R",
        app_function = "account_fixture_app",
        https = TRUE
      )
      retention_evidence_env$chrome <- f$chrome$Browser$getVersion()$product
      browser <- f$browser
      cleanup_env <- environment()
      navigate <- function(tab) {
        retention_browser_value(
          tab,
          paste0(
            "location.replace(",
            jsonlite::toJSON(f$origin, auto_unbox = TRUE),
            ")"
          )
        )
        retention_browser_wait(
          tab,
          function() retention_browser_snapshot(tab),
          "application document"
        )
      }
      login <- function(tab, account) {
        retention_browser_value(
          tab,
          paste0(
            "document.getElementById('username').value=",
            jsonlite::toJSON(account, auto_unbox = TRUE),
            ";",
            "document.getElementById('password').value=",
            jsonlite::toJSON(
              paste0(account, "-fixture-password"),
              auto_unbox = TRUE
            ),
            ";"
          )
        )
        retention_browser_click(tab, "login")
        retention_browser_wait(
          tab,
          function() {
            value <- retention_browser_snapshot(tab)
            if (identical(value$account, account)) value else NULL
          },
          paste("local login", account)
        )
      }
      logout <- function(tab) {
        retention_browser_click(tab, "local_logout")
        retention_browser_wait(
          tab,
          function() {
            identical(retention_browser_snapshot(tab)$result, "login")
          },
          "local logout"
        )
      }
      new_tab <- function() {
        context <- f$chrome$Target$getTargetInfo(
          targetId = browser$get_target_id()
        )$targetInfo$browserContextId
        target <- f$chrome$Target$createTarget(
          "about:blank",
          browserContextId = context
        )$targetId
        tab <- chromote::ChromoteSession$new(
          parent = f$chrome,
          targetId = target
        )
        withr::defer(tab$close(), envir = cleanup_env)
        tab$Security$setIgnoreCertificateErrors(ignore = TRUE)
        navigate(tab)
        tab
      }
      begin <- function(tab, site) {
        retention_browser_click(tab, paste0("connect_", site))
        retention_browser_wait(
          tab,
          function() {
            identical(
              retention_browser_value(
                tab,
                "document.querySelector('#provider')?.textContent"
              ),
              paste("Site", site)
            )
          },
          "provider approval"
        )
      }
      finish <- function(tab, account, count, rejected = FALSE) {
        retention_browser_click(tab, "approve")
        retention_browser_wait(
          tab,
          function() {
            value <- retention_browser_snapshot(tab)
            if (
              identical(value$account, account) &&
                length(value$connections) == count &&
                identical(length(value$errors) > 0L, rejected)
            ) {
              value
            } else {
              NULL
            }
          },
          "owned callback completion"
        )
      }
      metrics <- function(site) {
        httr2::request(f$providers[[site]]$url("/metrics")) |>
          httr2::req_timeout(5) |>
          httr2::req_perform() |>
          httr2::resp_body_json()
      }

      testthat::expect_null(retention_browser_snapshot(browser)$account)
      retention_browser_value(
        browser,
        "document.getElementById('username').value='alice'; document.getElementById('password').value='incorrect';"
      )
      retention_browser_click(browser, "login")
      retention_browser_wait(
        browser,
        function() {
          identical(
            retention_browser_value(browser, "document.body.textContent"),
            "Invalid fixture credentials"
          )
        },
        "rejected local credentials"
      )
      testthat::expect_identical(metrics("a")$exchanges, 0L)
      navigate(browser)
      testthat::expect_length(login(browser, "alice")$connections, 0L)
      cookies <- browser$Network$getCookies(urls = list(f$origin))$cookies
      local_cookies <- Filter(
        function(cookie) identical(cookie$name, "__Host-fixture-account"),
        cookies
      )
      testthat::expect_length(local_cookies, 1L)
      testthat::expect_identical(local_cookies[[1L]]$secure, TRUE)
      testthat::expect_identical(local_cookies[[1L]]$httpOnly, TRUE)
      testthat::expect_identical(
        grepl(
          "fixture-account",
          retention_browser_value(browser, "document.cookie"),
          fixed = TRUE
        ),
        FALSE
      )

      begin(browser, "a")
      alice <- finish(browser, "alice", 1L)
      alice_id <- alice$connections[[1L]]$connection_id
      retention_browser_action(browser, "read_a", "a:1")
      old_alice <- new_tab()
      control <- new_tab()
      begin(browser, "b")
      logout(control)
      bob <- login(control, "bob")
      testthat::expect_length(bob$connections, 0L)
      before <- metrics("a")$requests
      retention_browser_action(old_alice, "read_a", "unavailable")
      testthat::expect_identical(metrics("a")$requests, before)
      testthat::expect_null(retention_browser_snapshot(old_alice)$account)
      switched <- finish(browser, "bob", 0L, rejected = TRUE)
      testthat::expect_length(switched$connections, 0L)
      testthat::expect_identical(metrics("b")$exchanges, 0L)

      begin(control, "a")
      bob <- finish(control, "bob", 1L)
      bob_id <- bob$connections[[1L]]$connection_id
      testthat::expect_identical(bob_id == alice_id, FALSE)
      logout(control)
      restored <- login(control, "alice")
      testthat::expect_identical(
        restored$connections[[1L]]$connection_id,
        alice_id
      )
      testthat::expect_length(restored$connections, 1L)
      retention_browser_action(old_alice, "read_a", "unavailable")
      retention_browser_action(control, "read_a", "a:1")
      retention_browser_action(control, "refresh_a", "refreshed")
      retention_browser_action(control, "read_a", "a:2")

      # A fresh local login must also reject a pending grant from the previous
      # generation of the same account, while restoring already committed grants.
      replacement <- new_tab()
      begin(control, "b")
      logout(replacement)
      testthat::expect_identical(
        login(replacement, "alice")$connections[[1L]]$connection_id,
        alice_id
      )
      same_account <- finish(control, "alice", 1L, rejected = TRUE)
      testthat::expect_identical(
        same_account$connections[[1L]]$connection_id,
        alice_id
      )
      testthat::expect_identical(metrics("b")$exchanges, 0L)
      retention_browser_action(replacement, "manager_logout", "disconnected")
      retention_browser_action(control, "read_a", "unavailable")
      logout(replacement)
      disconnected <- login(replacement, "alice")
      testthat::expect_identical(
        disconnected$connections[[1L]]$status,
        "disconnected"
      )
      retention_browser_action(replacement, "read_a", "unavailable")
      logout(replacement)
      testthat::expect_identical(
        login(replacement, "bob")$connections[[1L]]$connection_id,
        bob_id
      )
      retention_browser_action(replacement, "read_a", "a:1")
    }
  )
}
