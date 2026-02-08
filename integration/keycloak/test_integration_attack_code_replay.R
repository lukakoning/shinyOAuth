## Attack vector: Authorization Code Replay
##
## Verifies that replaying an already-used authorization code fails.
## Defense mechanisms tested:
##   1. Single-use state store (state_store_get_remove) — second callback with
##      the same state fails because the entry was already consumed.
##   2. Keycloak server-side code single-use — even if the attacker somehow
##      bypasses the client, Keycloak rejects replayed codes with invalid_grant.

# Shared helpers (auto-sourced by testthat::test_dir; explicit for standalone use)
if (!exists("make_provider", mode = "function")) {
  source(file.path(dirname(sys.frame(1)$ofile %||% "."), "helper-keycloak.R"))
}

testthat::test_that("Code replay: second callback with same code+state is rejected (state consumed)", {
  skip_common()
  local_test_options()

  prov <- make_provider()
  client <- make_public_client(prov)

  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client),
    expr = {
      # Complete a successful flow
      url <- values$build_auth_url()
      res <- perform_login_form(url)
      values$.process_query(paste0(
        "?code=",
        utils::URLencode(res$code),
        "&state=",
        utils::URLencode(res$state_payload)
      ))
      session$flushReact()
      testthat::expect_true(isTRUE(values$authenticated))

      # Now replay: same code + state again
      # The state store entry was consumed on the first call; the second
      # call should fail because the state cannot be looked up.
      # Reset authenticated to detect the failure path
      values$logout()
      session$flushReact()
      # Restore browser token (logout clears it; no JS to regenerate in testServer)
      values$browser_token <- "__SKIPPED__"
      testthat::expect_false(isTRUE(values$authenticated))

      values$.process_query(paste0(
        "?code=",
        utils::URLencode(res$code),
        "&state=",
        utils::URLencode(res$state_payload)
      ))
      session$flushReact()

      # Must NOT be authenticated after replay
      testthat::expect_false(isTRUE(values$authenticated))
      testthat::expect_true(!is.null(values$error))
      # Error should reference state
      combo <- paste(values$error, values$error_description)
      testthat::expect_true(grepl(
        "state|State|decryption|validation",
        combo,
        ignore.case = TRUE
      ))
    }
  )
})

testthat::test_that("Code replay: Keycloak rejects already-exchanged code at token endpoint", {
  skip_common()
  local_test_options()

  prov <- make_provider()
  client <- make_public_client(prov)

  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client),
    expr = {
      # Complete a successful flow to exchange the code
      url <- values$build_auth_url()
      res <- perform_login_form(url)

      # Peek at the state to learn the code_verifier before the store is consumed
      si <- get_state_info(client, url)
      orig <- client@state_store$get(si$key, missing = NULL)
      code_verifier <- orig$pkce_code_verifier

      values$.process_query(paste0(
        "?code=",
        utils::URLencode(res$code),
        "&state=",
        utils::URLencode(res$state_payload)
      ))
      session$flushReact()
      testthat::expect_true(isTRUE(values$authenticated))

      # Now try to exchange the same code directly at the token endpoint.
      # This bypasses the module entirely and goes straight to Keycloak.
      token_url <- prov@token_url
      direct_resp <- httr2::request(token_url) |>
        httr2::req_body_form(
          grant_type = "authorization_code",
          client_id = "shiny-public",
          code = res$code,
          redirect_uri = "http://localhost:3000/callback",
          code_verifier = code_verifier %||% ""
        ) |>
        httr2::req_error(is_error = function(resp) FALSE) |>
        httr2::req_perform()

      # Keycloak should reject with 400 (invalid_grant) because the code
      # was already consumed during the first exchange
      testthat::expect_true(httr2::resp_status(direct_resp) >= 400)
      body <- httr2::resp_body_json(direct_resp)
      testthat::expect_true(grepl(
        "invalid_grant|Code not valid",
        body$error %||% body$error_description %||% "",
        ignore.case = TRUE
      ))
    }
  )
})
