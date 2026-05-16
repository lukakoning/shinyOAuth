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

run_callback_issuer_rejection_then_retry <- function(
  prov,
  client,
  iss,
  expected_error,
  success_assert = NULL
) {
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

      if (is.null(success_assert)) {
        expect_keycloak_module_login_invariants(
          authenticated = values$authenticated,
          error = values$error,
          error_description = values$error_description,
          error_uri = values$error_uri,
          token = values$token,
          client = client,
          expected_username = "alice"
        )
      } else {
        success_assert(values = values, client = client)
      }
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

      expect_keycloak_module_login_invariants(
        authenticated = values$authenticated,
        error = values$error,
        error_description = values$error_description,
        error_uri = values$error_uri,
        token = values$token,
        client = client,
        expected_username = "alice"
      )
    }
  )
})

testthat::test_that("mismatched callback issuer is rejected before state or code use", {
  skip_common()
  local_test_options()

  prov <- make_provider()
  client <- make_public_client(prov)

  run_callback_issuer_rejection_then_retry(
    prov = prov,
    client = client,
    iss = "http://localhost:8080/realms/attacker",
    expected_error = "issuer_mismatch"
  )
})

testthat::test_that("missing callback issuer is rejected before state or code use", {
  skip_common()
  local_test_options()

  prov <- make_provider()
  client <- make_public_client(prov)

  run_callback_issuer_rejection_then_retry(
    prov = prov,
    client = client,
    iss = NA_character_,
    expected_error = "issuer_missing"
  )
})

testthat::test_that("mismatched callback issuer is rejected before state or code use in a PAR flow", {
  skip_common()
  local_test_options()

  prov <- make_provider(use_par = TRUE)
  client <- make_public_client(prov)

  run_callback_issuer_rejection_then_retry(
    prov = prov,
    client = client,
    iss = "http://localhost:8080/realms/attacker",
    expected_error = "issuer_mismatch"
  )
})

testthat::test_that("mismatched callback issuer is rejected before state or code use in a JAR flow", {
  skip_common()
  local_test_options()

  prov <- make_provider(token_auth_style = "private_key_jwt")
  client <- make_private_key_jar_client(prov)
  testthat::skip_if(is.null(client), "private_key_jwt test key not available")

  run_callback_issuer_rejection_then_retry(
    prov = prov,
    client = client,
    iss = "http://localhost:8080/realms/attacker",
    expected_error = "issuer_mismatch"
  )
})

testthat::test_that("mismatched callback issuer is rejected before state or code use in a JAR over PAR flow", {
  skip_common()
  local_test_options()

  prov <- make_provider(token_auth_style = "private_key_jwt", use_par = TRUE)
  client <- make_private_key_jar_client(prov)
  testthat::skip_if(is.null(client), "private_key_jwt test key not available")

  run_callback_issuer_rejection_then_retry(
    prov = prov,
    client = client,
    iss = "http://localhost:8080/realms/attacker",
    expected_error = "issuer_mismatch"
  )
})

testthat::test_that("mismatched callback issuer is rejected before state or code use in a mTLS PAR flow", {
  skip_mtls_common()
  local_test_options()

  prov <- make_mtls_provider(
    token_auth_style = "tls_client_auth",
    use_par = TRUE
  )
  client <- make_mtls_confidential_client(prov)

  run_callback_issuer_rejection_then_retry(
    prov = prov,
    client = client,
    iss = "https://localhost:8443/realms/attacker",
    expected_error = "issuer_mismatch",
    success_assert = function(values, client) {
      testthat::expect_true(isTRUE(values$authenticated))
      testthat::expect_null(values$error)
      testthat::expect_null(values$error_description)
      testthat::expect_null(values$error_uri)
      testthat::expect_false(is.null(values$token))
      testthat::expect_true(nzchar(values$token@access_token %||% ""))
      testthat::expect_identical(
        values$token@userinfo$preferred_username,
        "alice"
      )
    }
  )
})
