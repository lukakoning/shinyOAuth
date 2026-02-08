## Attack vector: State Replay / CSRF
##
## Verifies that replaying a captured state parameter from a previous flow,
## or injecting a state from a different session, fails.
## Defense mechanisms tested:
##   1. Single-use state store — consumed state cannot be reused.
##   2. Per-session state stores — state from session A is not in session B's store.

# Shared helpers (auto-sourced by testthat::test_dir; explicit for standalone use)
if (!exists("make_provider", mode = "function")) {
  source(file.path(dirname(sys.frame(1)$ofile %||% "."), "helper-keycloak.R"))
}

testthat::test_that("State replay: consumed state rejected on new code", {
  skip_common()
  local_test_options()

  prov <- make_provider()
  client <- make_public_client(prov)

  # Capture the old state from the first flow
  old_state <- NULL

  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client),
    expr = {
      # Flow 1: complete successfully, consuming the state
      url1 <- values$build_auth_url()
      res1 <- perform_login_form(url1)
      old_state <<- res1$state_payload

      values$.process_query(paste0(
        "?code=",
        utils::URLencode(res1$code),
        "&state=",
        utils::URLencode(res1$state_payload)
      ))
      session$flushReact()
      testthat::expect_true(isTRUE(values$authenticated))

      # Flow 2: build a new auth URL → new code
      values$logout()
      session$flushReact()
      # Restore browser token (logout clears it; no JS to regenerate in testServer)
      values$browser_token <- "__SKIPPED__"
      url2 <- values$build_auth_url()
      res2 <- perform_login_form(url2)

      # Attack: inject the OLD consumed state with the NEW code
      values$.process_query(paste0(
        "?code=",
        utils::URLencode(res2$code),
        "&state=",
        utils::URLencode(old_state)
      ))
      session$flushReact()

      # Must fail — old state was already consumed from the store
      testthat::expect_false(isTRUE(values$authenticated))
      testthat::expect_true(!is.null(values$error))
    }
  )
})

testthat::test_that("State from different session rejected (cross-session CSRF)", {
  skip_common()
  local_test_options()

  prov <- make_provider()

  # Session A: build auth URL and capture state
  client_a <- make_public_client(prov)
  state_a <- NULL
  code_a <- NULL

  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client_a),
    expr = {
      url_a <- values$build_auth_url()
      res_a <- perform_login_form(url_a)
      state_a <<- res_a$state_payload
      code_a <<- res_a$code
    }
  )

  # Session B: separate client instance (separate state_store)
  client_b <- make_public_client(prov)

  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client_b),
    expr = {
      # Attacker tries to use session A's code + state in session B
      values$.process_query(paste0(
        "?code=",
        utils::URLencode(code_a),
        "&state=",
        utils::URLencode(state_a)
      ))
      session$flushReact()

      # Must fail — state_a is in client_a's store, not client_b's store
      testthat::expect_false(isTRUE(values$authenticated))
      testthat::expect_true(!is.null(values$error))
      combo <- paste(values$error, values$error_description)
      testthat::expect_true(grepl(
        "state|State|store|not found",
        combo,
        ignore.case = TRUE
      ))
    }
  )
})

testthat::test_that("State from different state_key rejected", {
  skip_common()
  local_test_options()

  prov <- make_provider()

  # Client A with one state_key
  client_a <- shinyOAuth::oauth_client(
    provider = prov,
    client_id = "shiny-public",
    client_secret = "",
    redirect_uri = "http://localhost:3000/callback",
    scopes = c("openid"),
    state_key = "aaaa-bbbb-cccc-dddd-eeee-ffff-0000-1111"
  )

  # Client B with a DIFFERENT state_key (same client_id, different encryption key)
  client_b <- shinyOAuth::oauth_client(
    provider = prov,
    client_id = "shiny-public",
    client_secret = "",
    redirect_uri = "http://localhost:3000/callback",
    scopes = c("openid"),
    state_key = "zzzz-yyyy-xxxx-wwww-vvvv-uuuu-9999-8888"
  )

  state_from_a <- NULL
  code_from_a <- NULL

  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client_a),
    expr = {
      url_a <- values$build_auth_url()
      res_a <- perform_login_form(url_a)
      state_from_a <<- res_a$state_payload
      code_from_a <<- res_a$code
    }
  )

  # Now try to use client A's state (encrypted with key A) in client B's session
  # (which would try to decrypt with key B) → AES-GCM auth tag failure
  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client_b),
    expr = {
      values$.process_query(paste0(
        "?code=",
        utils::URLencode(code_from_a),
        "&state=",
        utils::URLencode(state_from_a)
      ))
      session$flushReact()

      testthat::expect_false(isTRUE(values$authenticated))
      testthat::expect_true(!is.null(values$error))
      combo <- paste(values$error, values$error_description)
      testthat::expect_true(grepl(
        "state|State|decrypt|validation",
        combo,
        ignore.case = TRUE
      ))
    }
  )
})
