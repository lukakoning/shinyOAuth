## Attack vector: Expired State Payload
##
## Verifies that stale state payloads are rejected based on the
## `issued_at` timestamp in the encrypted state.
## Defense mechanisms tested:
##   1. state_payload_max_age enforcement in state_payload_decrypt_validate()
##   2. Configurable via shinyOAuth.state_payload_max_age option

# Shared helpers (auto-sourced by testthat::test_dir; explicit for standalone use)
if (!exists("make_provider", mode = "function")) {
  source(file.path(dirname(sys.frame(1)$ofile %||% "."), "helper-keycloak.R"))
}

testthat::test_that("Expired state: state exceeding max_age is rejected", {
  skip_common()
  # Set a very short max_age so we can test expiry quickly
  local_test_options()

  prov <- make_provider()
  # state_payload_max_age is a per-client property, not a global option
  client <- shinyOAuth::oauth_client(
    provider = prov,
    client_id = "shiny-public",
    client_secret = "",
    redirect_uri = "http://localhost:3000/callback",
    scopes = c("openid"),
    state_payload_max_age = 2 # 2-second max age
  )

  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client),
    expr = {
      # Build auth URL (state is created with issued_at = now)
      url <- values$build_auth_url()

      # Complete login form immediately (this is fast, well under 2s)
      res <- perform_login_form(url)

      # Wait for the state to expire
      Sys.sleep(3)

      # Now try to process the callback — the state payload is stale
      values$.process_query(paste0(
        "?code=",
        utils::URLencode(res$code),
        "&state=",
        utils::URLencode(res$state_payload)
      ))
      session$flushReact()

      # Must fail due to state freshness check
      testthat::expect_false(isTRUE(values$authenticated))
      testthat::expect_true(!is.null(values$error))
      combo <- paste(values$error, values$error_description)
      testthat::expect_true(grepl(
        "state|State|expired|stale|fresh|age|issued|time",
        combo,
        ignore.case = TRUE
      ))
    }
  )
})

testthat::test_that("Fresh state: state within max_age is accepted", {
  skip_common()
  # Use a generous max_age to confirm the positive case still works
  local_test_options()

  prov <- make_provider()
  client <- make_public_client(prov) # default state_payload_max_age = 300

  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client),
    expr = {
      url <- values$build_auth_url()
      res <- perform_login_form(url)

      # No delay — process immediately
      values$.process_query(paste0(
        "?code=",
        utils::URLencode(res$code),
        "&state=",
        utils::URLencode(res$state_payload)
      ))
      session$flushReact()

      testthat::expect_true(isTRUE(values$authenticated))
      testthat::expect_null(values$error)
    }
  )
})

testthat::test_that("Delayed callback: longer-lived state with deliberate pause", {
  skip_common()
  local_test_options()

  prov <- make_provider()
  client <- shinyOAuth::oauth_client(
    provider = prov,
    client_id = "shiny-public",
    client_secret = "",
    redirect_uri = "http://localhost:3000/callback",
    scopes = c("openid"),
    state_payload_max_age = 5 # 5-second max age
  )

  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client),
    expr = {
      url <- values$build_auth_url()
      res <- perform_login_form(url)

      # Wait 3 seconds (within 5s window)
      Sys.sleep(3)

      values$.process_query(paste0(
        "?code=",
        utils::URLencode(res$code),
        "&state=",
        utils::URLencode(res$state_payload)
      ))
      session$flushReact()

      # Should still succeed — 3s < 5s max_age
      testthat::expect_true(isTRUE(values$authenticated))
      testthat::expect_null(values$error)
    }
  )
})
