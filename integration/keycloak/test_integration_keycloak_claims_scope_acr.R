## Integration tests: live Keycloak scope, claims, and ACR validation
##
## These tests exercise OIDC Core claims handling, RFC 6749 scope reconciliation,
## and required ACR enforcement against real Keycloak authorization-code tokens.

if (!exists("make_provider", mode = "function")) {
  source(file.path(dirname(sys.frame(1)$ofile %||% "."), "helper-keycloak.R"))
}

make_validation_public_client <- function(
  prov,
  scopes = c("openid"),
  claims = list(),
  claims_validation = "none",
  required_acr_values = character(0),
  introspect = FALSE,
  introspect_elements = character(0)
) {
  shinyOAuth::oauth_client(
    provider = prov,
    client_id = "shiny-public",
    client_secret = "",
    redirect_uri = "http://localhost:3000/callback",
    scopes = scopes,
    claims = claims,
    claims_validation = claims_validation,
    required_acr_values = required_acr_values,
    introspect = introspect,
    introspect_elements = introspect_elements
  )
}

validation_login_via_module <- function(client, username = "alice") {
  result <- NULL

  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client),
    expr = {
      auth_url <- values$build_auth_url()
      login <- perform_login_form_as(
        auth_url,
        username = username,
        password = username,
        redirect_uri = client@redirect_uri
      )
      values$.process_query(callback_query(login))
      session$flushReact()

      result <<- list(
        auth_url = auth_url,
        login = login,
        authenticated = isTRUE(values$authenticated),
        error = values$error,
        error_description = values$error_description,
        token = values$token
      )
    }
  )

  result
}

exchange_keycloak_code_for_token_set <- function(client, auth_url, login) {
  state <- get_state_store_entry(client, auth_url)
  params <- list(
    grant_type = "authorization_code",
    code = login$code,
    redirect_uri = client@redirect_uri,
    code_verifier = state$entry$pkce_code_verifier,
    client_id = client@client_id
  )
  if (is.character(client@client_secret) && nzchar(client@client_secret)) {
    params$client_secret <- client@client_secret
  }

  req <- httr2::request(client@provider@token_url) |>
    req_apply_keycloak_ca() |>
    httr2::req_headers(Accept = "application/json") |>
    httr2::req_error(is_error = function(resp) FALSE)
  req <- do.call(httr2::req_body_form, c(list(req), params))
  resp <- httr2::req_perform(req)

  testthat::expect_identical(httr2::resp_status(resp), 200L)
  httr2::resp_body_json(resp, simplifyVector = TRUE)
}

testthat::test_that("Keycloak satisfies essential userinfo claims on happy path", {
  skip_common()
  local_test_options()

  prov <- make_provider()
  client <- make_validation_public_client(
    prov,
    scopes = c("openid", "profile", "email"),
    claims = list(
      userinfo = list(
        email = list(essential = TRUE)
      )
    ),
    claims_validation = "strict"
  )

  result <- validation_login_via_module(client)
  claims_param <- parse_query_param(result$auth_url, "claims", decode = TRUE)

  testthat::expect_true(nzchar(claims_param))
  testthat::expect_match(claims_param, "email")
  testthat::expect_true(isTRUE(result$authenticated))
  testthat::expect_null(result$error)
  testthat::expect_identical(result$token@userinfo$email, "alice@example.com")
})

testthat::test_that("Keycloak missing essential ID token claim fails closed", {
  skip_common()
  local_test_options()

  prov <- make_provider()
  client <- make_validation_public_client(
    prov,
    scopes = c("openid", "profile"),
    claims = list(
      id_token = list(
        website = list(essential = TRUE)
      )
    ),
    claims_validation = "strict"
  )

  result <- validation_login_via_module(client)

  testthat::expect_false(isTRUE(result$authenticated))
  testthat::expect_identical(result$error, "token_exchange_error")
  testthat::expect_match(
    result$error_description %||% "",
    "website|claim",
    ignore.case = TRUE
  )
  testthat::expect_null(result$token)
})

testthat::test_that("Keycloak ACR downgrade fails required_acr_values enforcement", {
  skip_common()
  local_test_options()

  prov <- make_provider()
  required_acr <- "urn:shinyoauth:test:phishing-resistant"
  client <- make_validation_public_client(
    prov,
    scopes = c("openid"),
    required_acr_values = required_acr
  )

  result <- validation_login_via_module(client)
  acr_values <- parse_query_param(result$auth_url, "acr_values", decode = TRUE)

  testthat::expect_identical(acr_values, required_acr)
  testthat::expect_false(isTRUE(result$authenticated))
  testthat::expect_identical(result$error, "token_exchange_error")
  testthat::expect_match(
    result$error_description %||% "",
    "acr|required_acr_values",
    ignore.case = TRUE
  )
  testthat::expect_null(result$token)
})

testthat::test_that("strict scope validation rejects a real Keycloak token set missing a required scope", {
  skip_common()
  local_test_options()

  prov <- make_provider()
  client <- make_validation_public_client(
    prov,
    scopes = c("openid")
  )
  client@scope_validation <- "strict"

  auth_url <- shinyOAuth::prepare_call(
    client,
    browser_token = "__SKIPPED__"
  )
  login <- perform_login_form(auth_url, redirect_uri = client@redirect_uri)
  state <- get_state_store_entry(client, auth_url)
  token_set <- exchange_keycloak_code_for_token_set(client, auth_url, login)

  testthat::skip_if(
    is.null(token_set$scope) || !nzchar(token_set$scope),
    "Keycloak token response omitted scope; RFC 6749 treats this as unchanged"
  )

  testthat::expect_error(
    shinyOAuth:::verify_token_set(
      client,
      token_set = token_set,
      nonce = state$entry$nonce,
      requested_scopes = c("openid", "shinyoauth-withheld-scope")
    ),
    regexp = "Granted scopes missing|scope_validation",
    class = "shinyOAuth_token_error"
  )
})
