## Integration tests: RFC 9207 authorization response issuer handling
##
## Keycloak advertises `authorization_response_iss_parameter_supported`; the
## module must accept the real `iss` callback parameter and reject missing or
## mismatched issuers before it consumes state or exchanges the code.

if (!exists("make_provider", mode = "function")) {
  source(file.path(dirname(sys.frame(1)$ofile %||% "."), "helper-keycloak.R"))
}

expect_callback_issuer_support <- function(prov, client) {
  testthat::expect_true(
    isTRUE(prov@authorization_response_iss_parameter_supported),
    info = "Keycloak discovery should advertise RFC 9207 callback issuer support"
  )
  testthat::expect_true(
    isTRUE(client@enforce_callback_issuer),
    info = "Clients for RFC 9207 providers should enforce callback issuer"
  )
}

run_callback_issuer_rejection_then_retry <- function(iss, expected_error) {
  prov <- make_provider()
  client <- make_public_client(prov)
  expect_callback_issuer_support(prov, client)

  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client),
    expr = {
      url <- values$build_auth_url()
      login <- perform_login_form(url, redirect_uri = client@redirect_uri)
      state_info <- get_state_info(client, url)

      values$.process_query(callback_query(login, iss = iss))
      session$flushReact()

      testthat::expect_false(isTRUE(values$authenticated))
      testthat::expect_identical(values$error, expected_error)
      testthat::expect_false(
        is.null(client@state_store$get(state_info$key, missing = NULL)),
        info = "Issuer rejection must happen before state is consumed"
      )

      values$error <- NULL
      values$error_description <- NULL
      values$error_uri <- NULL

      values$.process_query(callback_query(login))
      session$flushReact()

      testthat::expect_true(isTRUE(values$authenticated))
      testthat::expect_null(values$error)
      testthat::expect_null(
        client@state_store$get(state_info$key, missing = NULL),
        info = "Accepted callback should consume state after token exchange"
      )
    }
  )
}

testthat::test_that("Keycloak callback issuer is accepted on the happy path", {
  skip_common()
  local_test_options()

  prov <- make_provider()
  client <- make_public_client(prov)
  expect_callback_issuer_support(prov, client)

  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client),
    expr = {
      url <- values$build_auth_url()
      login <- perform_login_form(url, redirect_uri = client@redirect_uri)
      callback_iss <- parse_query_param(
        login$callback_url,
        "iss",
        decode = TRUE
      )

      testthat::expect_identical(callback_iss, prov@issuer)

      values$.process_query(callback_query(login))
      session$flushReact()

      testthat::expect_true(isTRUE(values$authenticated))
      testthat::expect_null(values$error)
      testthat::expect_false(is.null(values$token))
      testthat::expect_true(nzchar(values$token@access_token))
    }
  )
})

testthat::test_that("mismatched callback issuer is rejected before state or code use", {
  skip_common()
  local_test_options()

  run_callback_issuer_rejection_then_retry(
    iss = "http://localhost:8080/realms/attacker",
    expected_error = "issuer_mismatch"
  )
})

testthat::test_that("missing callback issuer is rejected before state or code use", {
  skip_common()
  local_test_options()

  run_callback_issuer_rejection_then_retry(
    iss = NA_character_,
    expected_error = "issuer_missing"
  )
})
