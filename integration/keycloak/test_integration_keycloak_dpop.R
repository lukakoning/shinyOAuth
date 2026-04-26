## Integration tests: Keycloak DPoP token issuance, userinfo, and refresh

if (!exists("make_provider", mode = "function")) {
  source(file.path(dirname(sys.frame(1)$ofile %||% "."), "helper-keycloak.R"))
}

perform_dpop_login <- function(
  client,
  username = "alice",
  password = username
) {
  result <- NULL

  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client),
    expr = {
      auth_url <- values$build_auth_url()
      login <- perform_login_form_as(
        auth_url,
        username = username,
        password = password
      )
      values$.process_query(paste0(
        "?code=",
        utils::URLencode(login$code),
        "&state=",
        utils::URLencode(login$state_payload)
      ))
      session$flushReact()

      result <<- list(
        authenticated = isTRUE(values$authenticated),
        error = values$error,
        error_description = values$error_description,
        token = values$token
      )
    }
  )

  result
}

expect_refresh_failure <- function(client, token) {
  err <- testthat::expect_error(
    shinyOAuth::refresh_token(client, token),
    regexp = "Token refresh failed",
    class = "shinyOAuth_http_error"
  )
  testthat::expect_match(conditionMessage(err), "Token refresh failed")
  invisible(err)
}

perform_auth_code_login <- function(
  client,
  username = "alice",
  password = username
) {
  auth_url <- shinyOAuth::prepare_call(
    client,
    browser_token = "__SKIPPED__"
  )
  login <- perform_login_form_as(
    auth_url,
    username = username,
    password = password
  )
  state <- get_state_store_entry(client, auth_url)

  list(
    auth_url = auth_url,
    code = login$code,
    state_payload = login$state_payload,
    state = state,
    code_verifier = state$entry$pkce_code_verifier,
    browser_token = state$entry$browser_token
  )
}

perform_raw_token_exchange <- function(client, code_login, dpop = NULL) {
  params <- list(
    grant_type = "authorization_code",
    code = code_login$code,
    redirect_uri = client@redirect_uri,
    code_verifier = code_login$code_verifier,
    client_id = client@client_id
  )

  if (
    is.character(client@client_secret) &&
      length(client@client_secret) == 1L &&
      nzchar(client@client_secret)
  ) {
    params$client_secret <- client@client_secret
  }

  req <- httr2::request(client@provider@token_url) |>
    httr2::req_error(is_error = function(resp) FALSE) |>
    httr2::req_method("POST")

  if (nzchar(dpop %||% "")) {
    req <- httr2::req_headers(req, DPoP = dpop)
  }

  req <- do.call(httr2::req_body_form, c(list(req), params))
  req |> httr2::req_perform()
}

expect_keycloak_token_endpoint_rejection <- function(
  resp,
  expected_description
) {
  testthat::expect_identical(httr2::resp_status(resp), 400L)

  body <- httr2::resp_body_json(resp, simplifyVector = TRUE)
  testthat::expect_null(body$access_token)
  testthat::expect_identical(body$error, "invalid_request")
  testthat::expect_match(
    body$error_description %||% "",
    expected_description,
    fixed = TRUE
  )
  testthat::expect_no_match(
    paste(body$error %||% "", body$error_description %||% ""),
    "invalid_grant",
    ignore.case = TRUE
  )

  invisible(resp)
}

perform_raw_userinfo_request <- function(prov, authorization, dpop = NULL) {
  req <- httr2::request(prov@userinfo_url) |>
    httr2::req_error(is_error = function(resp) FALSE) |>
    httr2::req_headers(Authorization = authorization)

  if (nzchar(dpop %||% "")) {
    req <- httr2::req_headers(req, DPoP = dpop)
  }

  req |> httr2::req_perform()
}

expect_keycloak_dpop_rejection <- function(resp) {
  testthat::expect_identical(httr2::resp_status(resp), 401L)

  challenge <- httr2::resp_header(resp, "www-authenticate") %||% ""
  testthat::expect_match(challenge, "DPoP|Bearer", ignore.case = TRUE)
  testthat::expect_match(challenge, "invalid_token", fixed = TRUE)
}

testthat::test_that("Keycloak token endpoint rejects missing and malformed DPoP proofs", {
  skip_common()
  local_test_options()

  prov <- make_provider(allowed_token_types = c("Bearer", "DPoP"))
  client <- make_dpop_public_client(prov)

  missing_proof_login <- perform_auth_code_login(client)
  missing_proof_resp <- perform_raw_token_exchange(
    client,
    missing_proof_login
  )
  expect_keycloak_token_endpoint_rejection(
    missing_proof_resp,
    "DPoP proof is missing"
  )

  wrong_htm_login <- perform_auth_code_login(client)
  wrong_htm_proof <- shinyOAuth:::build_dpop_proof(
    client,
    method = "GET",
    url = client@provider@token_url
  )
  wrong_htm_resp <- perform_raw_token_exchange(
    client,
    wrong_htm_login,
    dpop = wrong_htm_proof
  )
  expect_keycloak_token_endpoint_rejection(
    wrong_htm_resp,
    "DPoP HTTP method mismatch"
  )

  wrong_htu_login <- perform_auth_code_login(client)
  wrong_htu_proof <- shinyOAuth:::build_dpop_proof(
    client,
    method = "POST",
    url = sub("/token$", "/userinfo", client@provider@token_url)
  )
  wrong_htu_resp <- perform_raw_token_exchange(
    client,
    wrong_htu_login,
    dpop = wrong_htu_proof
  )
  expect_keycloak_token_endpoint_rejection(
    wrong_htu_resp,
    "DPoP HTTP URL mismatch"
  )
})

testthat::test_that("Keycloak DPoP auth-code flow binds tokens and protects userinfo", {
  skip_common()
  local_test_options()

  prov <- make_provider(allowed_token_types = c("Bearer", "DPoP"))
  client <- make_dpop_public_client(prov)

  login <- perform_dpop_login(client)

  testthat::expect_true(isTRUE(login$authenticated))
  testthat::expect_null(login$error)
  testthat::expect_false(is.null(login$token))
  testthat::expect_identical(login$token@token_type, "DPoP")
  testthat::expect_true(nzchar(login$token@access_token))
  access_jkt <- access_token_cnf_jkt(login$token@access_token)
  testthat::expect_true(nzchar(access_jkt))

  userinfo <- shinyOAuth::get_userinfo(client, login$token)

  testthat::expect_true(is.list(userinfo))
  testthat::expect_identical(userinfo$sub, login$token@userinfo$sub)
  testthat::expect_true(isTRUE(prov@use_pkce))

  missing_proof_resp <- perform_raw_userinfo_request(
    prov,
    authorization = paste("DPoP", login$token@access_token)
  )
  expect_keycloak_dpop_rejection(missing_proof_resp)

  bearer_downgrade_resp <- perform_raw_userinfo_request(
    prov,
    authorization = paste("Bearer", login$token@access_token)
  )
  expect_keycloak_dpop_rejection(bearer_downgrade_resp)

  attacker_client <- make_dpop_public_client(
    prov,
    dpop_private_key = make_dpop_private_key()
  )
  wrong_key_resp <- shinyOAuth::client_bearer_req(
    login$token,
    prov@userinfo_url,
    oauth_client = attacker_client
  ) |>
    httr2::req_error(is_error = function(resp) FALSE) |>
    httr2::req_perform()
  expect_keycloak_dpop_rejection(wrong_key_resp)
})

testthat::test_that("DPoP strict guard fails closed on a real Keycloak Bearer response", {
  skip_common()
  local_test_options()

  prov <- make_provider(allowed_token_types = c("Bearer", "DPoP"))
  bearer_client <- make_public_client(prov)
  login <- perform_auth_code_login(bearer_client)
  bearer_resp <- perform_raw_token_exchange(bearer_client, login)
  token_set <- httr2::resp_body_json(bearer_resp, simplifyVector = TRUE)

  testthat::expect_identical(httr2::resp_status(bearer_resp), 200L)
  testthat::expect_identical(token_set$token_type, "Bearer")

  strict_client <- make_public_client(
    prov,
    dpop_private_key = make_dpop_private_key(),
    dpop_require_access_token = TRUE
  )

  testthat::expect_error(
    shinyOAuth:::verify_token_type_allowlist(strict_client, token_set),
    regexp = "Expected token_type = DPoP",
    class = "shinyOAuth_token_error"
  )
})

testthat::test_that("Keycloak DPoP refresh succeeds only with the original bound key", {
  skip_common()
  local_test_options()

  prov <- make_provider(allowed_token_types = c("Bearer", "DPoP"))

  bound_key <- make_dpop_private_key()
  ok_client <- make_dpop_shortlived_public_client(
    prov,
    dpop_private_key = bound_key
  )
  ok_login <- perform_dpop_login(ok_client)

  testthat::expect_true(isTRUE(ok_login$authenticated))
  testthat::expect_true(nzchar(ok_login$token@refresh_token %||% ""))
  original_jkt <- access_token_cnf_jkt(ok_login$token@access_token)
  testthat::expect_true(nzchar(original_jkt))

  refreshed <- shinyOAuth::refresh_token(ok_client, ok_login$token)

  testthat::expect_identical(refreshed@token_type, "DPoP")
  refreshed_jkt <- access_token_cnf_jkt(refreshed@access_token)
  testthat::expect_true(nzchar(refreshed_jkt))
  testthat::expect_identical(refreshed_jkt, original_jkt)

  missing_proof_login <- perform_dpop_login(ok_client)
  missing_proof_client <- make_shortlived_public_client(
    prov,
    client_id = "shiny-dpop-shortlived"
  )

  testthat::expect_true(isTRUE(missing_proof_login$authenticated))
  expect_refresh_failure(missing_proof_client, missing_proof_login$token)

  wrong_key_login <- perform_dpop_login(ok_client)
  wrong_key_client <- make_dpop_shortlived_public_client(
    prov,
    dpop_private_key = make_dpop_private_key()
  )

  testthat::expect_true(isTRUE(wrong_key_login$authenticated))
  expect_refresh_failure(wrong_key_client, wrong_key_login$token)
})
