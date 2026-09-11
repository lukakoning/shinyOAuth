for (index in seq_len(nrow(cases))) {
  row <- cases[index, ]
  testthat::test_that(paste("SMART profile", paste(unlist(row), collapse = " ")), {
    key <- openssl::rsa_keygen(2048)
    registration <- list(style = row$registration, secret = "synthetic-profile-secret",
      public_pem = openssl::write_pem(key$pubkey), private_pem = openssl::write_pem(key))
    provider_registration <- registration
    provider_registration$private_pem <- NULL
    provider_factory <- function(site, callback) smart_profile_provider(site, callback, provider_registration, row$launch,
      authorization_method, extra_scopes)
    f <- retention_browser_setup(row$async, row$response_mode, provider_factory = provider_factory,
      app_script = "integration/smart/fixture-profile-app.R", app_function = "smart_profile_app",
      app_args = list(registration = registration, launch = row$launch,
        authorization_method = authorization_method, extra_scopes = extra_scopes))
    retention_evidence_env$chrome <- f$chrome$Browser$getVersion()$product
    browser <- f$browser
    metrics <- function(site) httr2::request(paste0(f$bases[[site]], "/metrics")) |>
      httr2::req_timeout(5) |> httr2::req_perform() |> httr2::resp_body_json()
    authorize <- function(site, count) {
      if (row$launch == "ehr") browser$Page$navigate(paste0(f$bases[[site]], "/ehr-launch")) else
        retention_browser_click(browser, paste0("connect_", site))
      retention_browser_wait(browser, function() identical(retention_browser_value(browser,
        "document.querySelector('#provider')?.textContent"), paste("Site", site)), "SMART authorization")
      retention_browser_click(browser, "approve")
      retention_browser_wait(browser, function() {
        value <- retention_browser_snapshot(browser)
        if (!is.null(value) && length(value$connections) == count) value else NULL
      }, "SMART callback commit")
    }
    first <- authorize("a", 1L)
    id <- first$connections[[1L]]$connection_id
    for (action in c("read", "user", "search")) {
      retention_browser_click(browser, paste0(action, "_a"))
      retention_browser_result(browser, switch(action, read = "a:1:context-1", user = "a:user", search = "a:search"))
    }
    testthat::expect_identical(metrics("a")$searches, 1L)
    retention_browser_click(browser, "narrow_a")
    retention_browser_result(browser, "refreshed")
    retention_browser_click(browser, "search_a")
    retention_browser_result(browser, "unavailable")
    testthat::expect_identical(metrics("a")$searches, 1L)
    retention_browser_click(browser, "read_a")
    retention_browser_result(browser, "a:2:context-1")
    retention_browser_click(browser, "user_a")
    retention_browser_result(browser, "a:user")
    both <- authorize("b", 2L)
    testthat::expect_gt(both$session, first$session)
    testthat::expect_length(both$errors, 0L)
    retained_a <- Filter(function(value) identical(value$client_label, "Site a"), both$connections)[[1L]]
    testthat::expect_identical(retained_a$connection_id, id)
    testthat::expect_identical(retained_a$status, "limited")
    retention_browser_click(browser, "refresh_a")
    retention_browser_result(browser, "refreshed")
    retention_browser_click(browser, "read_a")
    retention_browser_result(browser, "a:3:context-1")
    retention_browser_click(browser, "user_a")
    retention_browser_result(browser, "a:user")
    for (action in c("search_a", "widen_a")) {
      retention_browser_click(browser, action)
      retention_browser_result(browser, "unavailable")
    }
    testthat::expect_identical(metrics("a")$refreshes, 2L)
    testthat::expect_identical(metrics("a")$scoped_refreshes, 2L)
    retention_browser_click(browser, "refresh_b")
    retention_browser_result(browser, "refreshed")
    retention_browser_click(browser, "read_b")
    retention_browser_result(browser, "b:2:context-1")
    retention_browser_click(browser, "search_b")
    retention_browser_result(browser, "b:search")
    testthat::expect_identical(metrics("b")$scoped_refreshes, 0L)
    for (site in c("a", "b")) {
      value <- metrics(site)
      testthat::expect_identical(value$exchanges, 1L)
      testthat::expect_identical(value$authorization_posts, if (authorization_method == "POST") 1L else 0L)
      testthat::expect_identical(value$authorization_gets, if (authorization_method == "GET") 1L else 0L)
      if (authorization_method == "POST") testthat::expect_gt(value$authorization_body_bytes, 8192L)
      testthat::expect_identical(value$assertions, if (row$registration == "private_key_jwt") 1L + value$refreshes else 0L)
    }
    retention_browser_click(browser, "disconnect_b")
    retention_browser_wait(browser, function() {
      rows <- retention_browser_snapshot(browser)$connections
      b <- Filter(function(value) identical(value$client_label, "Site b"), rows)
      length(b) == 1L && identical(b[[1L]]$status, "disconnected")
    }, "disconnect B")
    retention_browser_click(browser, "read_b")
    retention_browser_result(browser, "unavailable")
    retention_browser_click(browser, "read_a")
    retention_browser_result(browser, "a:3:context-1")
    retention_browser_click(browser, "logout")
    retention_browser_wait(browser, function() {
      value <- retention_browser_snapshot(browser)
      !is.null(value) && length(value$connections) == 0L
    }, "logout")
    testthat::expect_length(retention_browser_snapshot(browser)$connections, 0L)
  })
}
