## Integration tests: JWT client-assertion replay against live Keycloak

if (!exists("make_provider", mode = "function")) {
  source(file.path(dirname(sys.frame(1)$ofile %||% "."), "helper-keycloak.R"))
}

build_raw_par_params <- function(client) {
  scopes <- shinyOAuth:::effective_client_scopes(client)
  state <- shinyOAuth:::random_urlsafe(n = client@state_entropy %||% 64)
  shinyOAuth:::validate_state(state)

  pkce_code_verifier <- NULL
  pkce_code_challenge <- NULL
  pkce_method <- NULL
  if (isTRUE(client@provider@use_pkce)) {
    pkce_code_verifier <- shinyOAuth:::gen_code_verifier(64)
    pkce_code_challenge <- shinyOAuth:::base64url_encode(
      openssl::sha256(charToRaw(pkce_code_verifier))
    )
    pkce_method <- client@provider@pkce_method %||% "S256"
  }

  nonce <- NULL
  if (isTRUE(client@provider@use_nonce)) {
    nonce <- shinyOAuth:::random_urlsafe(n = 32)
  }

  payload <- shinyOAuth:::compact_list(list(
    state = state,
    client_id = client@client_id,
    redirect_uri = client@redirect_uri,
    scopes = scopes,
    provider = shinyOAuth:::provider_fingerprint(client@provider),
    client_policy = shinyOAuth:::state_client_policy_fingerprint(client),
    issued_at = as.numeric(Sys.time()),
    trace_id = shinyOAuth:::gen_trace_id()
  )) |>
    shinyOAuth:::state_encrypt_gcm(key = client@state_key)

  shinyOAuth:::build_authorization_params(
    oauth_client = client,
    payload = payload,
    scopes = scopes,
    pkce_code_challenge = pkce_code_challenge,
    pkce_method = pkce_method,
    nonce = nonce
  )
}

build_prepared_client_assertion_request <- function(
  client,
  endpoint,
  params,
  context
) {
  req <- httr2::request(endpoint) |>
    req_apply_keycloak_ca() |>
    httr2::req_error(is_error = function(resp) FALSE) |>
    httr2::req_headers(Accept = "application/json") |>
    httr2::req_method("POST")

  prepared <- shinyOAuth:::apply_direct_client_auth(
    req = req,
    params = params,
    client = client,
    context = context
  )

  client_assertion <- prepared$params$client_assertion %||% NA_character_
  assertion_payload <- if (keycloak_nonempty_string(client_assertion)) {
    shinyOAuth:::parse_jwt_payload(client_assertion)
  } else {
    list()
  }

  list(
    req = do.call(httr2::req_body_form, c(list(prepared$req), prepared$params)),
    client_assertion = client_assertion,
    assertion_payload = assertion_payload
  )
}

build_prepared_par_request <- function(client) {
  build_prepared_client_assertion_request(
    client = client,
    endpoint = client@provider@par_url,
    params = build_raw_par_params(client),
    context = "pushed_authorization_request"
  )
}

build_prepared_token_request <- function(client, scope = "openid") {
  params <- list(
    grant_type = "client_credentials",
    client_id = client@client_id,
    scope = scope
  )

  build_prepared_client_assertion_request(
    client = client,
    endpoint = client@provider@token_url,
    params = params,
    context = "token"
  )
}

perform_prepared_client_assertion_request <- function(prepared_request) {
  httr2::req_perform(prepared_request$req)
}

expect_distinct_client_assertion_jti <- function(
  first_request,
  second_request
) {
  first_jti <- first_request$assertion_payload$jti %||% NA_character_
  second_jti <- second_request$assertion_payload$jti %||% NA_character_

  testthat::expect_true(keycloak_nonempty_string(first_jti))
  testthat::expect_true(keycloak_nonempty_string(second_jti))
  testthat::expect_false(identical(first_jti, second_jti))
}

expect_successful_par_response <- function(resp) {
  body <- safe_resp_body_json(resp)

  testthat::expect_identical(httr2::resp_status(resp), 201L)
  testthat::expect_match(
    body[["request_uri"]] %||% "",
    "^urn:ietf:params:oauth:request_uri:"
  )
  testthat::expect_true(is.numeric(body[["expires_in"]]))

  invisible(body)
}

expect_replayed_par_assertion_rejected <- function(resp) {
  body <- safe_resp_body_json(resp)

  testthat::expect_identical(httr2::resp_status(resp), 401L)
  testthat::expect_identical(body[["error"]], "invalid_request")
  testthat::expect_match(
    body[["error_description"]] %||% "",
    "Authentication failed",
    fixed = TRUE
  )

  invisible(body)
}

expect_successful_token_response <- function(resp) {
  body <- safe_resp_body_json(resp)

  testthat::expect_identical(httr2::resp_status(resp), 200L)
  testthat::expect_true(keycloak_nonempty_string(
    body[["access_token"]] %||% NA_character_
  ))
  testthat::expect_identical(body[["token_type"]], "Bearer")

  invisible(body)
}

expect_replayed_token_assertion_rejected <- function(resp) {
  body <- safe_resp_body_json(resp)

  testthat::expect_identical(httr2::resp_status(resp), 400L)
  testthat::expect_identical(body[["error"]], "invalid_client")
  testthat::expect_match(
    body[["error_description"]] %||% "",
    "Token reuse detected",
    fixed = TRUE
  )

  invisible(body)
}

testthat::test_that("Keycloak PAR rejects replayed client_secret_jwt assertions and shinyOAuth rotates jti", {
  skip_common()
  local_test_options()

  prov <- make_provider(token_auth_style = "client_secret_jwt", use_par = TRUE)
  client <- make_client_secret_jwt_client(prov)

  first_request <- build_prepared_par_request(client)
  second_request <- build_prepared_par_request(client)

  expect_distinct_client_assertion_jti(first_request, second_request)
  expect_successful_par_response(
    perform_prepared_client_assertion_request(first_request)
  )
  expect_replayed_par_assertion_rejected(
    perform_prepared_client_assertion_request(first_request)
  )
})

testthat::test_that("Keycloak PAR rejects replayed private_key_jwt assertions and shinyOAuth rotates jti", {
  skip_common()
  local_test_options()

  prov <- make_provider(token_auth_style = "private_key_jwt", use_par = TRUE)
  client <- make_private_key_jwt_client(prov)
  testthat::skip_if(is.null(client), "private_key_jwt test key not available")

  first_request <- build_prepared_par_request(client)
  second_request <- build_prepared_par_request(client)

  expect_distinct_client_assertion_jti(first_request, second_request)
  expect_successful_par_response(
    perform_prepared_client_assertion_request(first_request)
  )
  expect_replayed_par_assertion_rejected(
    perform_prepared_client_assertion_request(first_request)
  )
})

testthat::test_that("Keycloak token endpoint rejects replayed client_secret_jwt assertions and shinyOAuth rotates jti", {
  skip_common()
  local_test_options()

  prov <- make_provider(token_auth_style = "client_secret_jwt")
  client <- make_client_secret_jwt_client(prov)

  first_request <- build_prepared_token_request(client)
  second_request <- build_prepared_token_request(client)

  expect_distinct_client_assertion_jti(first_request, second_request)
  expect_successful_token_response(
    perform_prepared_client_assertion_request(first_request)
  )
  expect_replayed_token_assertion_rejected(
    perform_prepared_client_assertion_request(first_request)
  )
})

testthat::test_that("Keycloak token endpoint rejects replayed private_key_jwt assertions and shinyOAuth rotates jti", {
  skip_common()
  local_test_options()

  prov <- make_provider(token_auth_style = "private_key_jwt")
  client <- make_private_key_jwt_client(prov)
  testthat::skip_if(is.null(client), "private_key_jwt test key not available")

  first_request <- build_prepared_token_request(client)
  second_request <- build_prepared_token_request(client)

  expect_distinct_client_assertion_jti(first_request, second_request)
  expect_successful_token_response(
    perform_prepared_client_assertion_request(first_request)
  )
  expect_replayed_token_assertion_rejected(
    perform_prepared_client_assertion_request(first_request)
  )
})
