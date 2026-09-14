cases <- expand.grid(
  async = c(FALSE, TRUE),
  response_mode = c("query", "form_post"),
  stringsAsFactors = FALSE
)
for (index in seq_len(nrow(cases))) {
  async <- cases$async[[index]]
  response_mode <- cases$response_mode[[index]]
  testthat::test_that(
    paste("two-site browser retention", response_mode, "async =", async),
    {
      f <- retention_browser_setup(async, response_mode,
        provider_factory = function(site, callback) retention_fixture_provider(site, callback,
          authorization_method = authorization_method),
        app_args = list(authorization_method = authorization_method))
      retention_evidence_env$chrome <- f$chrome$Browser$getVersion()$product
      browser <- f$browser
      initial <- retention_browser_snapshot(browser)
      testthat::expect_length(initial$connections, 0L)
      authorize <- function(site, expected_count) {
        before <- retention_browser_snapshot(browser)
        retention_browser_click(browser, paste0("connect_", site))
        retention_browser_wait(
          browser,
          function() {
            identical(
              retention_browser_value(
                browser,
                "document.querySelector('#provider')?.textContent"
              ),
              paste("Site", site)
            )
          },
          paste("provider", site)
        )
        testthat::expect_identical(
          retention_browser_value(browser, "location.hostname"),
          "localhost"
        )
        retention_browser_click(browser, "approve")
        after <- retention_browser_wait(
          browser,
          function() {
            snapshot <- retention_browser_snapshot(browser)
            if (
              !is.null(snapshot) &&
                length(snapshot$connections) == expected_count
            ) {
              snapshot
            } else {
              NULL
            }
          },
          paste("completed authorization", site)
        )
        testthat::expect_gt(after$session, before$session)
        testthat::expect_length(after$errors, 0L)
        testthat::expect_identical(
          retention_browser_value(browser, "location.search"),
          ""
        )
        after
      }
      a <- authorize("a", 1L)
      retention_browser_action(browser, "read_a", "a:1")
      both <- authorize("b", 2L)
      if (response_mode == "form_post") {
        testthat::expect_length(both$post_owner_cookies, 2L)
        testthat::expect_false(any(unlist(both$post_owner_cookies)))
      }
      testthat::expect_gt(both$session, a$session)
      testthat::expect_setequal(
        vapply(both$connections, function(row) row$client_label, character(1)),
        c("Site a", "Site b")
      )
      first_id <- a$connections[[1L]]$connection_id
      testthat::expect_true(
        first_id %in%
          vapply(
            both$connections,
            function(row) row$connection_id,
            character(1)
          )
      )
      retention_browser_action(browser, "read_a", "a:1")
      retention_browser_action(browser, "read_b", "b:1")
      for (site in c("a", "b")) {
        retention_browser_action(browser, paste0("refresh_", site), "refreshed")
        retention_browser_action(browser, paste0("read_", site), paste0(site, ":2"))
      }
      rotated <- retention_browser_snapshot(browser)
      testthat::expect_setequal(
        vapply(
          rotated$connections,
          function(row) row$connection_id,
          character(1)
        ),
        vapply(both$connections, function(row) row$connection_id, character(1))
      )
      cookies <- browser$Network$getCookies(urls = list(f$origin))$cookies
      owner_cookies <- Filter(function(cookie) isTRUE(cookie$httpOnly), cookies)
      testthat::expect_length(owner_cookies, 1L)
      testthat::expect_identical(owner_cookies[[1L]]$sameSite, "Lax")
      testthat::expect_false(grepl(
        owner_cookies[[1L]]$name,
        retention_browser_value(browser, "document.cookie"),
        fixed = TRUE
      ))

      foreign <- f$new_browser()
      testthat::expect_length(
        retention_browser_snapshot(foreign)$connections,
        0L
      )
      retention_browser_value(
        foreign,
        paste0(
          "Shiny.setInputValue('probe_id',",
          jsonlite::toJSON(first_id, auto_unbox = TRUE),
          ",{priority:'event'})"
        )
      )
      retention_browser_action(foreign, "probe", "unavailable")

      retention_browser_action(browser, "disconnect_b", "disconnected")
      retention_browser_action(browser, "read_b", "unavailable")
      retention_browser_action(browser, "read_a", "a:2")
      metrics <- lapply(f$providers, function(provider) {
        httr2::request(provider$url("/metrics")) |>
          httr2::req_timeout(5) |>
          httr2::req_perform() |>
          httr2::resp_body_json()
      })
      for (site in c("a", "b")) {
        testthat::expect_identical(metrics[[site]]$exchanges, 1L)
        testthat::expect_identical(metrics[[site]]$authorization_posts, if (authorization_method == "POST") 1L else 0L)
        testthat::expect_identical(metrics[[site]]$authorization_gets, if (authorization_method == "GET") 1L else 0L)
        testthat::expect_identical(metrics[[site]]$refreshes, 1L)
        testthat::expect_gte(metrics[[site]]$requests, 2L)
      }
      testthat::expect_identical(metrics$b$revocations, 2L)

      # Logout clears the HttpOnly owner cookie through an HTTP reload. Returning
      # to the app establishes a new empty owner; an old connection ID cannot restore it.
      before_logout <- retention_browser_snapshot(browser)$session
      retention_browser_click(browser, "logout")
      empty <- retention_browser_wait(
        browser,
        function() {
          snapshot <- retention_browser_snapshot(browser)
          if (
            !is.null(snapshot) &&
              snapshot$session > before_logout &&
              length(snapshot$connections) == 0L
          ) {
            snapshot
          } else {
            NULL
          }
        },
        "new empty owner after logout"
      )
      testthat::expect_gt(empty$session, before_logout)
      retention_browser_value(
        browser,
        paste0(
          "Shiny.setInputValue('probe_id',",
          jsonlite::toJSON(first_id, auto_unbox = TRUE),
          ",{priority:'event'})"
        )
      )
      retention_browser_action(browser, "probe", "unavailable")
    }
  )
}
