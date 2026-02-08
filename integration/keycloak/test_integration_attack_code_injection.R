## Attack vector: Cross-User Authorization Code Injection
##
## Verifies that an attacker cannot inject their own authorization code into
## another user's session to impersonate them, and that PKCE prevents stolen
## codes from being exchanged by a different party.
## Defense mechanisms tested:
##   1. Per-session state stores — attacker's state not in victim's store
##   2. PKCE binding — code bound to the original code_challenge; a different
##      code_verifier causes Keycloak to reject with invalid_grant
##   3. State encryption binding — code + state from different sessions don't mix

# Shared helpers (auto-sourced by testthat::test_dir; explicit for standalone use)
if (!exists("make_provider", mode = "function")) {
  source(file.path(dirname(sys.frame(1)$ofile %||% "."), "helper-keycloak.R"))
}

testthat::test_that("Code injection: bob's code with alice's state succeeds but authenticates as bob", {
  skip_common()
  local_test_options()

  # This test demonstrates that if an attacker (bob) can somehow log in through

  # alice's auth URL (same PKCE challenge), the resulting token will be for bob.
  # The defense here is that the application must verify the identity claim in the
  # token/userinfo matches the expected user at the application level.
  # At the OAuth level, the code is bound to whoever authenticates at the IdP.

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
      values$.process_query(paste0(
        "?code=",
        utils::URLencode(res_bob$code),
        "&state=",
        utils::URLencode(res_bob$state_payload)
      ))
      session$flushReact()

      # The flow succeeds because PKCE verifier matches (alice's session owns
      # the verifier), but the resulting token is for BOB.
      testthat::expect_true(isTRUE(values$authenticated))
      # The token's identity is bob, not alice
      testthat::expect_identical(
        values$token@userinfo$preferred_username,
        "bob"
      )
    }
  )
})

testthat::test_that("Code injection: bob's independent code+state rejected in alice's session", {
  skip_common()
  local_test_options()

  prov <- make_provider()

  # Bob completes an INDEPENDENT flow in his own session
  client_bob <- make_public_client(prov)
  bob_code <- NULL
  bob_state <- NULL

  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client_bob),
    expr = {
      url_bob <- values$build_auth_url()
      res_bob <- perform_login_form_as(url_bob, "bob", "bob")
      bob_code <<- res_bob$code
      bob_state <<- res_bob$state_payload
    }
  )

  # Alice's session — separate client, separate state store
  client_alice <- make_public_client(prov)

  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client_alice),
    expr = {
      # Attacker injects bob's code + bob's state into alice's session
      values$.process_query(paste0(
        "?code=",
        utils::URLencode(bob_code),
        "&state=",
        utils::URLencode(bob_state)
      ))
      session$flushReact()

      # Must fail: bob's state is not in alice's state store
      testthat::expect_false(isTRUE(values$authenticated))
      testthat::expect_true(!is.null(values$error))
      combo <- paste(values$error, values$error_description)
      testthat::expect_true(grepl(
        "state|State|decrypt|validation|store",
        combo,
        ignore.case = TRUE
      ))
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
