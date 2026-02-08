## Attack vector: Cross-Client Code Swap
##
## Verifies that an authorization code issued for one client_id cannot be
## exchanged by a different client. This prevents mix-up attacks where an
## attacker redirects a code intended for one relying party to another.
## Defense mechanisms tested:
##   1. Keycloak server-side binding of code to client_id (invalid_grant)
##   2. State payload client_id binding (client mismatch detected locally)
##   3. Provider fingerprint binding in the state payload

# Shared helpers (auto-sourced by testthat::test_dir; explicit for standalone use)
if (!exists("make_provider", mode = "function")) {
  source(file.path(dirname(sys.frame(1)$ofile %||% "."), "helper-keycloak.R"))
}

testthat::test_that("Cross-client: code from public client rejected by confidential client at Keycloak", {
  skip_common()
  local_test_options()

  prov <- make_provider()

  # Get a code issued for shiny-public
  client_public <- make_public_client(prov)
  captured_code <- NULL

  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client_public),
    expr = {
      url <- values$build_auth_url()
      res <- perform_login_form(url)
      captured_code <<- res$code
    }
  )

  # Try to exchange it at the token endpoint as shiny-confidential
  token_url <- prov@token_url
  direct_resp <- httr2::request(token_url) |>
    httr2::req_body_form(
      grant_type = "authorization_code",
      client_id = "shiny-confidential",
      client_secret = "secret",
      code = captured_code,
      redirect_uri = "http://localhost:3000/callback"
    ) |>
    httr2::req_error(is_error = function(resp) FALSE) |>
    httr2::req_perform()

  # Keycloak rejects: code was issued for shiny-public
  testthat::expect_true(httr2::resp_status(direct_resp) >= 400)
  body <- httr2::resp_body_json(direct_resp)
  testthat::expect_true(grepl(
    "invalid_grant|unauthorized_client",
    paste(body$error, body$error_description),
    ignore.case = TRUE
  ))
})

testthat::test_that("Cross-client: code from confidential client rejected by public client at Keycloak", {
  skip_common()
  local_test_options()

  prov <- make_provider()

  # Get a code issued for shiny-confidential
  client_conf <- make_confidential_client(prov)
  captured_code <- NULL

  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client_conf),
    expr = {
      url <- values$build_auth_url()
      res <- perform_login_form(url)
      captured_code <<- res$code
    }
  )

  # Try to exchange it at the token endpoint as shiny-public (no secret)
  token_url <- prov@token_url
  direct_resp <- httr2::request(token_url) |>
    httr2::req_body_form(
      grant_type = "authorization_code",
      client_id = "shiny-public",
      code = captured_code,
      redirect_uri = "http://localhost:3000/callback",
      code_verifier = "irrelevant_since_code_was_not_issued_for_this_client"
    ) |>
    httr2::req_error(is_error = function(resp) FALSE) |>
    httr2::req_perform()

  # Keycloak rejects: code was issued for shiny-confidential
  testthat::expect_true(httr2::resp_status(direct_resp) >= 400)
  body <- httr2::resp_body_json(direct_resp)
  testthat::expect_true(grepl(
    "invalid_grant|unauthorized_client",
    paste(body$error, body$error_description),
    ignore.case = TRUE
  ))
})

testthat::test_that("Cross-client via module: state from client A fails in client B (client_id binding)", {
  skip_common()
  local_test_options()

  prov <- make_provider()

  # Client A (public) builds auth URL and logs in
  client_a <- make_public_client(prov)
  state_a <- NULL
  code_a <- NULL

  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client_a),
    expr = {
      url <- values$build_auth_url()
      res <- perform_login_form(url)
      state_a <<- res$state_payload
      code_a <<- res$code
    }
  )

  # Client B (confidential) — trying to use client A's code+state
  # Even if we somehow put client A's state into client B's state store,
  # the encrypted payload contains client_id = "shiny-public" which won't
  # match client B's "shiny-confidential" → payload_verify_client_binding fails
  client_b <- make_confidential_client(prov)

  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client_b),
    expr = {
      values$.process_query(paste0(
        "?code=",
        utils::URLencode(code_a),
        "&state=",
        utils::URLencode(state_a)
      ))
      session$flushReact()

      # Either state decryption fails (different state_key) or client binding
      # check fails (client_id mismatch in payload)
      testthat::expect_false(isTRUE(values$authenticated))
      testthat::expect_true(!is.null(values$error))
    }
  )
})
