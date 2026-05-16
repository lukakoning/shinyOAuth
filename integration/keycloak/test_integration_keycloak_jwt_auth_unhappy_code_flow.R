## Integration tests: JWT client authentication failures in full code flow
##
## Existing unhappy-path auth-style tests target introspection. These tests
## drive a real authorization-code login first, then assert token endpoint JWT
## client-auth failures are surfaced by the module and consume state.

if (!exists("make_provider", mode = "function")) {
  source(file.path(dirname(sys.frame(1)$ofile %||% "."), "helper-keycloak.R"))
}

expect_jwt_auth_code_flow_failure <- function(client, description_pattern) {
  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client),
    expr = {
      auth_url <- values$build_auth_url()
      state_info <- get_state_info(client, auth_url)
      login <- perform_login_form(auth_url, redirect_uri = client@redirect_uri)
      query <- callback_query(login)

      testthat::expect_true(nzchar(login$code %||% ""))

      values$.process_query(query)
      session$flushReact()

      testthat::expect_false(isTRUE(values$authenticated))
      testthat::expect_identical(values$error, "token_exchange_error")
      testthat::expect_match(
        values$error_description %||% "",
        description_pattern,
        ignore.case = TRUE
      )
      testthat::expect_null(values$token)
      testthat::expect_null(
        client@state_store$get(state_info$key, missing = NULL),
        info = "State should be single-use even when token exchange fails"
      )

      values$error <- NULL
      values$error_description <- NULL
      values$error_uri <- NULL

      values$.process_query(query)
      session$flushReact()

      testthat::expect_identical(values$error, "invalid_state")
      testthat::expect_match(
        values$error_description %||% "",
        "state",
        ignore.case = TRUE
      )
    }
  )
}

make_bad_client_secret_jwt_client <- function(prov) {
  shinyOAuth::oauth_client(
    provider = prov,
    client_id = "shiny-csjwt",
    client_secret = paste0(
      "1",
      substr(
        get_client_secret_jwt_secret(),
        2L,
        nchar(get_client_secret_jwt_secret())
      )
    ),
    redirect_uri = "http://localhost:3000/callback",
    scopes = c("openid"),
    client_assertion_alg = "HS256"
  )
}

make_bad_client_secret_jwt_aud_client <- function(prov) {
  shinyOAuth::oauth_client(
    provider = prov,
    client_id = "shiny-csjwt",
    client_secret = get_client_secret_jwt_secret(),
    redirect_uri = "http://localhost:3000/callback",
    scopes = c("openid"),
    client_assertion_alg = "HS256",
    client_assertion_audience = "https://example.com/not-keycloak"
  )
}

make_bad_client_secret_jwt_alg_client <- function(prov) {
  shinyOAuth::oauth_client(
    provider = prov,
    client_id = "shiny-csjwt",
    client_secret = get_client_secret_jwt_secret(),
    redirect_uri = "http://localhost:3000/callback",
    scopes = c("openid"),
    client_assertion_alg = "HS384"
  )
}

make_bad_private_key_jwt_client <- function(prov) {
  shinyOAuth::oauth_client(
    provider = prov,
    client_id = "shiny-pjwt",
    client_secret = "",
    redirect_uri = "http://localhost:3000/callback",
    scopes = c("openid"),
    client_private_key = openssl::rsa_keygen(bits = 2048),
    client_private_key_kid = NA_character_,
    client_assertion_alg = NA_character_
  )
}

testthat::test_that("code flow fails with wrong client_secret_jwt secret", {
  skip_common()
  local_test_options()

  prov <- make_provider(token_auth_style = "client_secret_jwt")
  client <- make_bad_client_secret_jwt_client(prov)

  expect_jwt_auth_code_flow_failure(
    client,
    "Token exchange failed|invalid_client|401"
  )
})

testthat::test_that("code flow fails with wrong client_secret_jwt audience", {
  skip_common()
  local_test_options()

  prov <- make_provider(token_auth_style = "client_secret_jwt")
  client <- make_bad_client_secret_jwt_aud_client(prov)

  expect_jwt_auth_code_flow_failure(
    client,
    "Token exchange failed|invalid_client|aud|401"
  )
})

testthat::test_that("code flow fails with client_secret_jwt alg not allowed by client", {
  skip_common()
  local_test_options()

  prov <- make_provider(token_auth_style = "client_secret_jwt")
  client <- make_bad_client_secret_jwt_alg_client(prov)

  expect_jwt_auth_code_flow_failure(
    client,
    "Token exchange failed|invalid_client|alg|401"
  )
})

testthat::test_that("code flow fails with wrong private_key_jwt key", {
  skip_common()
  local_test_options()
  testthat::skip_if_not_installed("openssl")

  prov <- make_provider(token_auth_style = "private_key_jwt")
  client <- make_bad_private_key_jwt_client(prov)

  expect_jwt_auth_code_flow_failure(
    client,
    "Token exchange failed|invalid_client|jwt|401"
  )
})
