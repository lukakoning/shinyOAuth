## Attack vector: Concurrent Auth Flow Isolation
##
## Verifies that multiple simultaneous auth flows don't interfere with each
## other. Each flow has its own state entry in the state store, and completing
## them in any order should work correctly.
## Defense mechanisms tested:
##   1. State store entries keyed by unique state value (not session order)
##   2. Each flow's PKCE verifier and nonce are independent
##   3. Concurrent flows from different users don't cross-contaminate

# Shared helpers (auto-sourced by testthat::test_dir; explicit for standalone use)
if (!exists("make_provider", mode = "function")) {
  source(file.path(dirname(sys.frame(1)$ofile %||% "."), "helper-keycloak.R"))
}

testthat::test_that("Concurrent flows: multiple auth URLs have independent state entries", {
  skip_common()
  local_test_options()

  prov <- make_provider()
  client <- make_public_client(prov)

  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client),
    expr = {
      # Build three auth URLs (three independent state entries)
      url1 <- values$build_auth_url()
      url2 <- values$build_auth_url()
      url3 <- values$build_auth_url()

      # Verify all three states are different
      s1 <- parse_query_param(url1, "state")
      s2 <- parse_query_param(url2, "state")
      s3 <- parse_query_param(url3, "state")
      testthat::expect_false(identical(s1, s2))
      testthat::expect_false(identical(s2, s3))
      testthat::expect_false(identical(s1, s3))

      # Each state has its own independent entry in the state store
      si1 <- get_state_info(client, url1)
      si2 <- get_state_info(client, url2)
      si3 <- get_state_info(client, url3)
      testthat::expect_false(identical(si1$key, si2$key))
      testthat::expect_false(identical(si2$key, si3$key))

      # Each entry has unique PKCE verifier and nonce
      e1 <- client@state_store$get(si1$key, missing = NULL)
      e2 <- client@state_store$get(si2$key, missing = NULL)
      e3 <- client@state_store$get(si3$key, missing = NULL)
      testthat::expect_false(identical(
        e1$pkce_code_verifier,
        e2$pkce_code_verifier
      ))
      testthat::expect_false(identical(e1$nonce, e2$nonce))

      # Process the LAST one (Keycloak SSO session means already-used codes
      # from the same session get invalidated, so we only process one)
      res3 <- perform_login_form(url3)
      values$.process_query(paste0(
        "?code=",
        utils::URLencode(res3$code),
        "&state=",
        utils::URLencode(res3$state_payload)
      ))
      session$flushReact()
      testthat::expect_true(isTRUE(values$authenticated))

      # The consumed state entry (flow 3) is removed from the store
      consumed <- client@state_store$get(si3$key, missing = NULL)
      testthat::expect_null(consumed)

      # But flows 1 and 2's state store entries are still intact
      # (they were never consumed)
      still1 <- client@state_store$get(si1$key, missing = NULL)
      still2 <- client@state_store$get(si2$key, missing = NULL)
      testthat::expect_true(is.list(still1))
      testthat::expect_true(is.list(still2))
    }
  )
})

testthat::test_that("Concurrent flows: parallel sessions with same client config don't interfere", {
  skip_common()
  local_test_options()

  prov <- make_provider()

  # Two separate client instances (same config, different state stores)
  client_1 <- make_public_client(prov)
  client_2 <- make_public_client(prov)

  # Session 1 builds URL and logs in
  url_1 <- NULL
  res_1 <- NULL

  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client_1),
    expr = {
      url_1 <<- values$build_auth_url()
      res_1 <<- perform_login_form(url_1)
    }
  )

  # Session 2 builds URL and logs in
  url_2 <- NULL
  res_2 <- NULL

  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client_2),
    expr = {
      url_2 <<- values$build_auth_url()
      res_2 <<- perform_login_form(url_2)
    }
  )

  # Now process callbacks — each session gets its own code+state
  # Session 1
  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client_1),
    expr = {
      # Re-build URL to populate internal state (since testServer is stateless)
      # Actually, the state was already stored in client_1's state_store,
      # and the sealed payload is in res_1$state_payload, so we can process directly
      values$.process_query(paste0(
        "?code=",
        utils::URLencode(res_1$code),
        "&state=",
        utils::URLencode(res_1$state_payload)
      ))
      session$flushReact()
      testthat::expect_true(isTRUE(values$authenticated))
      testthat::expect_null(values$error)
    }
  )

  # Session 2
  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client_2),
    expr = {
      values$.process_query(paste0(
        "?code=",
        utils::URLencode(res_2$code),
        "&state=",
        utils::URLencode(res_2$state_payload)
      ))
      session$flushReact()
      testthat::expect_true(isTRUE(values$authenticated))
      testthat::expect_null(values$error)
    }
  )
})

testthat::test_that("Concurrent flows: alice and bob login simultaneously without interference", {
  skip_common()
  local_test_options()

  prov <- make_provider()

  client_alice <- make_public_client(prov)
  client_bob <- make_public_client(prov)

  # Alice and Bob each build their own auth URL and login in independent sessions
  res_alice <- NULL
  res_bob <- NULL

  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client_alice),
    expr = {
      url_a <- values$build_auth_url()
      res_alice <<- perform_login_form_as(url_a, "alice", "alice")
    }
  )

  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client_bob),
    expr = {
      url_b <- values$build_auth_url()
      res_bob <<- perform_login_form_as(url_b, "bob", "bob")
    }
  )

  # Process alice's callback
  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client_alice),
    expr = {
      values$.process_query(paste0(
        "?code=",
        utils::URLencode(res_alice$code),
        "&state=",
        utils::URLencode(res_alice$state_payload)
      ))
      session$flushReact()
      testthat::expect_true(isTRUE(values$authenticated))
      testthat::expect_identical(
        values$token@userinfo$preferred_username,
        "alice"
      )
    }
  )

  # Process bob's callback
  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client_bob),
    expr = {
      values$.process_query(paste0(
        "?code=",
        utils::URLencode(res_bob$code),
        "&state=",
        utils::URLencode(res_bob$state_payload)
      ))
      session$flushReact()
      testthat::expect_true(isTRUE(values$authenticated))
      testthat::expect_identical(
        values$token@userinfo$preferred_username,
        "bob"
      )
    }
  )
})

testthat::test_that("Concurrent flows: swapped callbacks fail (alice's code in bob's session)", {
  skip_common()
  local_test_options()

  prov <- make_provider()
  client_alice <- make_public_client(prov)
  client_bob <- make_public_client(prov)

  res_alice <- NULL

  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client_alice),
    expr = {
      url_a <- values$build_auth_url()
      res_alice <<- perform_login_form_as(url_a, "alice", "alice")
    }
  )

  # Try to process alice's callback in bob's session
  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client_bob),
    expr = {
      # Alice's state is in client_alice's store, not client_bob's
      values$.process_query(paste0(
        "?code=",
        utils::URLencode(res_alice$code),
        "&state=",
        utils::URLencode(res_alice$state_payload)
      ))
      session$flushReact()
      testthat::expect_false(isTRUE(values$authenticated))
      testthat::expect_true(!is.null(values$error))
    }
  )
})
