lifecycle_setup <- function(async, behavior = list(), .env = parent.frame()) {
  registration <- list(style = "public", assertion_alg = NA_character_)
  factory <- function(site, callback) smart_profile_provider(site, callback, registration,
    "standalone", https = TRUE, behavior = if (site == "a") behavior else list())
  f <- retention_browser_setup(async, provider_factory = factory,
    app_script = "integration/smart/fixture-profile-app.R", app_function = "smart_profile_app",
    app_args = list(registration = registration, launch = "standalone", refresh_check_interval = 500),
    https = TRUE, https_providers = TRUE, .env = .env)
  f$metrics <- function(site = "a") httr2::request(paste0(f$bases[[site]], "/metrics")) |>
    httr2::req_options(cainfo = file.path(retention_root, "integration/keycloak/tls/ca-cert.pem")) |>
    httr2::req_timeout(5) |> httr2::req_perform() |> httr2::resp_body_json()
  f$control <- function(path, site = "a") httr2::request(paste0(f$bases[[site]], "/test/", path)) |>
    httr2::req_options(cainfo = file.path(retention_root, "integration/keycloak/tls/ca-cert.pem")) |>
    httr2::req_method("POST") |> httr2::req_timeout(5) |> httr2::req_perform()
  f
}
lifecycle_connection <- function(browser, site) {
  rows <- Filter(function(row) identical(row$client_label, paste("Site", site)),
    retention_browser_snapshot(browser)$connections)
  if (length(rows) == 1L) rows[[1L]] else NULL
}
lifecycle_authorize <- function(f, site, count) {
  retention_browser_click(f$browser, paste0("connect_", site))
  retention_browser_wait(f$browser, function() identical(retention_browser_value(f$browser,
    "document.querySelector('#provider')?.textContent"), paste("Site", site)), "provider approval")
  retention_browser_click(f$browser, "approve")
  retention_browser_wait(f$browser, function() {
    value <- retention_browser_snapshot(f$browser)
    if (!is.null(value) && length(value$connections) == count) value else NULL
  }, "SMART callback")
}
