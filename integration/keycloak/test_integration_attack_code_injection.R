## Attack vector: cross-user authorization flow substitution
##
## These are headless protocol-integration tests. They do not exercise the real
## browser cookie boundary; browser-boundary coverage lives in the *_browser*.R
## and *_e2e.R tests.
##
## One scenario intentionally demonstrates login CSRF/account substitution:
## if Bob completes Alice's started authorization request, OAuth authenticates
## the IdP user who actually logged in (Bob). The package therefore needs to
## expose verified subject and claim surfaces so the app can reject unexpected
## identities. Separate-session state injection, wrong-verifier exchange, and
## cross-client code swaps must still fail closed.

# Shared helpers (auto-sourced by testthat::test_dir; explicit for standalone use)
if (!exists("make_provider", mode = "function")) {
  source(file.path(dirname(sys.frame(1)$ofile %||% "."), "helper-keycloak.R"))
}

testthat::test_that("Login CSRF/account substitution: bob can finish alice's started flow and authenticate as bob", {
  skip_common()
  local_test_options()

  # If Bob authenticates against Alice's started flow, the PKCE verifier still
  # belongs to Alice's session, so the callback succeeds. The authenticated
  # identity is therefore Bob, and the app must compare the verified subject to
  # whatever user it expected at the application layer.

  prov <- make_provider()
  client <- make_public_client(prov)

  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client),
    expr = {
      # Alice's session builds auth URL
      url <- values$build_auth_url()

      # Bob authenticates through Alice's auth URL
      # (same PKCE challenge, same state — but bob's credentials)
      res_bob <- perform_login_form_as(
        url,
        username = "bob",
        password = "bob"
      )

      # Process the callback in Alice's module session
      values$.process_query(callback_query(res_bob))
      session$flushReact()

      expect_keycloak_module_login_invariants(
        authenticated = values$authenticated,
        error = values$error,
        error_description = values$error_description,
        error_uri = values$error_uri,
        token = values$token,
        client = client,
        expected_username = "bob"
      )

      testthat::expect_identical(
        values$token@userinfo$sub,
        values$token@id_token_claims$sub
      )
    }
  )
})

testthat::test_that("Login CSRF/account substitution: app can compare the verified subject and reject the wrong account", {
  skip_common()
  local_test_options()

  prov <- make_provider()
  expected_alice_sub <- NULL
  client_alice <- make_public_client(prov)

  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client_alice),
    expr = {
      url <- values$build_auth_url()
      res <- perform_login_form_as(url, username = "alice", password = "alice")

      values$.process_query(callback_query(res))
      session$flushReact()

      expect_keycloak_module_login_invariants(
        authenticated = values$authenticated,
        error = values$error,
        error_description = values$error_description,
        error_uri = values$error_uri,
        token = values$token,
        client = client_alice,
        expected_username = "alice"
      )

      expected_alice_sub <<- values$token@userinfo$sub
    }
  )

  testthat::expect_true(
    is.character(expected_alice_sub) &&
      length(expected_alice_sub) == 1L &&
      !is.na(expected_alice_sub) &&
      nzchar(expected_alice_sub)
  )

  client <- make_public_client(prov)

  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client),
    expr = {
      url <- values$build_auth_url()
      res_bob <- perform_login_form_as(url, username = "bob", password = "bob")

      values$.process_query(callback_query(res_bob))
      session$flushReact()

      expect_keycloak_module_login_invariants(
        authenticated = values$authenticated,
        error = values$error,
        error_description = values$error_description,
        error_uri = values$error_uri,
        token = values$token,
        client = client,
        expected_username = "bob"
      )

      testthat::expect_false(
        identical(values$token@userinfo$sub, expected_alice_sub)
      )
    }
  )
})

testthat::test_that("Cross-session code+state injection is rejected in alice's session", {
  skip_common()
  local_test_options()

  prov <- make_provider()

  # Bob completes an INDEPENDENT flow in his own session
  client_bob <- make_public_client(prov)
  bob_login <- NULL

  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client_bob),
    expr = {
      url_bob <- values$build_auth_url()
      bob_login <<- perform_login_form_as(url_bob, "bob", "bob")
    }
  )

  # Alice's session — separate client, separate state store
  client_alice <- make_public_client(prov)

  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client_alice),
    expr = {
      # Attacker injects bob's code + bob's state into alice's session
      values$.process_query(callback_query(bob_login))
      session$flushReact()

      # Must fail: bob's state is not in alice's state store
      testthat::expect_false(isTRUE(values$authenticated))
      testthat::expect_identical(values$error, "invalid_state")
      testthat::expect_null(values$token)
      testthat::expect_match(
        paste(values$error, values$error_description),
        "state|decrypt|validation|store",
        ignore.case = TRUE
      )
    }
  )
})

testthat::test_that("PKCE prevents stolen code exchange with wrong verifier", {
  skip_common()
  local_test_options()

  prov <- make_provider()
  client <- make_public_client(prov)

  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client),
    expr = {
      # Alice builds auth URL (generates code_challenge / code_verifier pair)
      url <- values$build_auth_url()
      # Complete login to get a valid code bound to alice's code_challenge
      res <- perform_login_form(url)
      code_alice <- res$code

      # Attacker intercepts the code and tries to exchange it directly
      # with their own (wrong) code_verifier
      attacker_verifier <- paste0(
        sample(c(letters, LETTERS, 0:9, "-", "_", ".", "~"), 64, TRUE),
        collapse = ""
      )

      token_url <- prov@token_url
      direct_resp <- httr2::request(token_url) |>
        httr2::req_body_form(
          grant_type = "authorization_code",
          client_id = "shiny-public",
          code = code_alice,
          redirect_uri = "http://localhost:3000/callback",
          code_verifier = attacker_verifier
        ) |>
        httr2::req_error(is_error = function(resp) FALSE) |>
        httr2::req_perform()

      # Keycloak rejects: the attacker's verifier doesn't match the challenge
      testthat::expect_true(httr2::resp_status(direct_resp) >= 400)
      body <- httr2::resp_body_json(direct_resp)
      testthat::expect_true(grepl(
        "invalid_grant|PKCE|code.verifier",
        paste(body$error, body$error_description),
        ignore.case = TRUE
      ))
    }
  )
})

testthat::test_that("Code injection: bob's code with alice's state but different client_id", {
  skip_common()
  local_test_options()

  prov <- make_provider()

  # Alice uses the confidential client
  client_alice <- make_confidential_client(prov)

  # Bob uses the public client — code issued to a different client_id
  client_bob <- make_public_client(prov)
  bob_code <- NULL

  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client_bob),
    expr = {
      url_bob <- values$build_auth_url()
      res_bob <- perform_login_form_as(url_bob, "bob", "bob")
      bob_code <<- res_bob$code
    }
  )

  # Alice's session tries to exchange bob's code (issued for shiny-public)
  # with alice's client (shiny-confidential)
  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client_alice),
    expr = {
      url_alice <- values$build_auth_url()
      # Get alice's state (valid for alice's session)
      state_alice <- parse_query_param(url_alice, "state")

      # We can't directly inject bob's code with alice's state through the
      # module (the module validates state first), but let's try the direct
      # token endpoint to show Keycloak also rejects cross-client codes
      token_url <- prov@token_url
      direct_resp <- httr2::request(token_url) |>
        httr2::req_body_form(
          grant_type = "authorization_code",
          client_id = "shiny-confidential",
          client_secret = "secret",
          code = bob_code,
          redirect_uri = "http://localhost:3000/callback"
        ) |>
        httr2::req_error(is_error = function(resp) FALSE) |>
        httr2::req_perform()

      # Keycloak rejects: code was issued for shiny-public, not shiny-confidential
      testthat::expect_true(httr2::resp_status(direct_resp) >= 400)
      body <- httr2::resp_body_json(direct_resp)
      testthat::expect_true(grepl(
        "invalid_grant|unauthorized_client",
        paste(body$error, body$error_description),
        ignore.case = TRUE
      ))
    }
  )
})
