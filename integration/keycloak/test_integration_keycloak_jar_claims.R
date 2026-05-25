## Integration tests: live Keycloak JAR claim handling quirks

if (!exists("make_provider", mode = "function")) {
  source(file.path(dirname(sys.frame(1)$ofile %||% "."), "helper-keycloak.R"))
}

valid_browser_token <- function() {
  paste(rep("ab", 64), collapse = "")
}

callback_iss <- function(login_result) {
  parse_query_param(login_result$callback_url, "iss", decode = TRUE)
}

expect_no_callback_error <- function(login_result) {
  callback_error <- parse_query_param(
    login_result$callback_url,
    "error",
    decode = TRUE
  )
  callback_description <- parse_query_param(
    login_result$callback_url,
    "error_description",
    decode = TRUE
  )

  testthat::expect_true(is.na(callback_error) || !nzchar(callback_error))
  testthat::expect_true(
    is.na(callback_description) || !nzchar(callback_description)
  )
}

tamper_signed_request_object <- function(auth_url, mutate_claims) {
  request_jwt <- parse_query_param(auth_url, "request", decode = TRUE)
  claims <- as.list(shinyOAuth:::parse_jwt_payload(request_jwt))
  header <- shinyOAuth:::parse_jwt_header(request_jwt)
  claims <- mutate_claims(claims)

  stopifnot(is.list(claims))

  tampered <- jose::jwt_encode_sig(
    do.call(jose::jwt_claim, claims),
    key = get_pjwt_key(),
    header = header
  )

  sub(
    "request=.*$",
    paste0("request=", utils::URLencode(tampered, reserved = TRUE)),
    auth_url
  )
}

complete_jar_callback <- function(client, login_result, browser_token) {
  shinyOAuth:::handle_callback(
    oauth_client = client,
    code = login_result$code,
    payload = login_result$state_payload,
    browser_token = browser_token,
    iss = callback_iss(login_result)
  )
}

testthat::test_that("Keycloak currently accepts a signed request object with a wrong aud claim", {
  skip_common()
  local_test_options()

  provider <- make_provider(token_auth_style = "private_key_jwt")
  client <- make_private_key_jar_client(provider)
  testthat::skip_if(is.null(client), "private_key_jwt test key not available")

  browser_token <- valid_browser_token()
  auth_url <- shinyOAuth::prepare_call(client, browser_token = browser_token)
  tampered_url <- tamper_signed_request_object(auth_url, function(claims) {
    claims[["aud"]] <- "https://localhost:8443/realms/attacker"
    claims
  })

  login <- perform_login_form_as(
    tampered_url,
    redirect_uri = client@redirect_uri
  )
  expect_no_callback_error(login)

  token <- complete_jar_callback(client, login, browser_token)

  testthat::expect_true(S7::S7_inherits(token, shinyOAuth::OAuthToken))
  testthat::expect_identical(token@userinfo[["preferred_username"]], "alice")
})

testthat::test_that("Keycloak currently accepts a signed request object with a wrong iss claim", {
  skip_common()
  local_test_options()

  provider <- make_provider(token_auth_style = "private_key_jwt")
  client <- make_private_key_jar_client(provider)
  testthat::skip_if(is.null(client), "private_key_jwt test key not available")

  browser_token <- valid_browser_token()
  auth_url <- shinyOAuth::prepare_call(client, browser_token = browser_token)
  tampered_url <- tamper_signed_request_object(auth_url, function(claims) {
    claims[["iss"]] <- "attacker-client"
    claims
  })

  login <- perform_login_form_as(
    tampered_url,
    redirect_uri = client@redirect_uri
  )
  expect_no_callback_error(login)

  token <- complete_jar_callback(client, login, browser_token)

  testthat::expect_true(S7::S7_inherits(token, shinyOAuth::OAuthToken))
  testthat::expect_identical(token@userinfo[["preferred_username"]], "alice")
})

testthat::test_that("Keycloak currently accepts a signed request object with an expired exp claim", {
  skip_common()
  local_test_options()

  provider <- make_provider(token_auth_style = "private_key_jwt")
  client <- make_private_key_jar_client(provider)
  testthat::skip_if(is.null(client), "private_key_jwt test key not available")

  browser_token <- valid_browser_token()
  auth_url <- shinyOAuth::prepare_call(client, browser_token = browser_token)
  tampered_url <- tamper_signed_request_object(auth_url, function(claims) {
    now <- floor(as.numeric(Sys.time()))
    claims[["iat"]] <- now - 120
    claims[["exp"]] <- now - 60
    claims
  })

  login <- perform_login_form_as(
    tampered_url,
    redirect_uri = client@redirect_uri
  )
  expect_no_callback_error(login)

  token <- complete_jar_callback(client, login, browser_token)

  testthat::expect_true(S7::S7_inherits(token, shinyOAuth::OAuthToken))
  testthat::expect_identical(token@userinfo[["preferred_username"]], "alice")
})

testthat::test_that("Keycloak replays the same signed request object but shinyOAuth rejects the second callback", {
  skip_common()
  local_test_options()

  provider <- make_provider(token_auth_style = "private_key_jwt")
  client <- make_private_key_jar_client(provider)
  testthat::skip_if(is.null(client), "private_key_jwt test key not available")

  browser_token <- valid_browser_token()
  auth_url <- shinyOAuth::prepare_call(client, browser_token = browser_token)

  first_login <- perform_login_form_as(
    auth_url,
    redirect_uri = client@redirect_uri
  )
  second_login <- perform_login_form_as(
    auth_url,
    redirect_uri = client@redirect_uri
  )

  expect_no_callback_error(first_login)
  expect_no_callback_error(second_login)

  testthat::expect_true(nzchar(first_login$code %||% ""))
  testthat::expect_true(nzchar(second_login$code %||% ""))
  testthat::expect_false(identical(first_login$code, second_login$code))

  first_token <- complete_jar_callback(client, first_login, browser_token)
  testthat::expect_true(S7::S7_inherits(first_token, shinyOAuth::OAuthToken))
  testthat::expect_identical(
    first_token@userinfo[["preferred_username"]],
    "alice"
  )

  testthat::expect_error(
    complete_jar_callback(client, second_login, browser_token),
    class = "shinyOAuth_state_error",
    regexp = "State store entry is missing or malformed"
  )
})
