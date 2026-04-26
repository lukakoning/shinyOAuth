## Attack vector: DPoP-protected resource token replay and key mismatch

if (!exists("make_provider", mode = "function")) {
  source(file.path(dirname(sys.frame(1)$ofile %||% "."), "helper-keycloak.R"))
}
if (!exists("start_dpop_protected_resource", mode = "function")) {
  source(file.path(
    dirname(sys.frame(1)$ofile %||% "."),
    "helper-dpop-resource.R"
  ))
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

perform_raw_resource_request <- function(url, authorization, dpop = NULL) {
  req <- httr2::request(url) |>
    httr2::req_error(is_error = function(resp) FALSE) |>
    httr2::req_headers(Authorization = authorization)

  if (nzchar(dpop %||% "")) {
    req <- httr2::req_headers(req, DPoP = dpop)
  }

  req |> httr2::req_perform()
}

testthat::test_that("DPoP-protected resource accepts the bound key and rejects stolen or replayed proofs", {
  skip_common()
  local_test_options()
  testthat::skip_if_not_installed("webfakes")

  prov <- make_provider(allowed_token_types = c("Bearer", "DPoP"))
  client <- make_dpop_public_client(prov)
  login <- perform_dpop_login(client)

  testthat::expect_true(isTRUE(login$authenticated))
  testthat::expect_identical(login$token@token_type, "DPoP")

  resource <- start_dpop_protected_resource()
  on.exit(try(resource$server$stop(), silent = TRUE), add = TRUE)

  valid_resp <- shinyOAuth::client_bearer_req(
    login$token,
    resource$url,
    oauth_client = client
  ) |>
    httr2::req_perform()
  valid_body <- httr2::resp_body_json(valid_resp, simplifyVector = TRUE)

  testthat::expect_identical(httr2::resp_status(valid_resp), 200L)
  testthat::expect_true(isTRUE(valid_body$ok))
  testthat::expect_identical(
    valid_body$token_jkt,
    access_token_cnf_jkt(login$token@access_token)
  )

  missing_proof_resp <- perform_raw_resource_request(
    resource$url,
    authorization = paste("DPoP", login$token@access_token)
  )
  missing_proof_body <- httr2::resp_body_json(
    missing_proof_resp,
    simplifyVector = TRUE
  )

  testthat::expect_identical(httr2::resp_status(missing_proof_resp), 401L)
  testthat::expect_identical(
    missing_proof_body$error,
    "missing_dpop_proof"
  )

  attacker_client <- make_dpop_public_client(
    prov,
    dpop_private_key = make_dpop_private_key()
  )
  wrong_key_resp <- shinyOAuth::client_bearer_req(
    login$token,
    resource$url,
    oauth_client = attacker_client
  ) |>
    httr2::req_error(is_error = function(resp) FALSE) |>
    httr2::req_perform()
  wrong_key_body <- httr2::resp_body_json(wrong_key_resp, simplifyVector = TRUE)

  testthat::expect_identical(httr2::resp_status(wrong_key_resp), 401L)
  testthat::expect_identical(wrong_key_body$error, "dpop_key_mismatch")

  replay_req <- shinyOAuth::client_bearer_req(
    login$token,
    resource$url,
    oauth_client = client
  )
  replay_dry <- httr2::req_dry_run(
    replay_req,
    quiet = TRUE,
    redact_headers = FALSE
  )
  replay_auth <- replay_dry$headers$authorization
  replay_proof <- replay_dry$headers$dpop

  first_replay_resp <- perform_raw_resource_request(
    resource$url,
    authorization = replay_auth,
    dpop = replay_proof
  )
  second_replay_resp <- perform_raw_resource_request(
    resource$url,
    authorization = replay_auth,
    dpop = replay_proof
  )
  second_replay_body <- httr2::resp_body_json(
    second_replay_resp,
    simplifyVector = TRUE
  )

  testthat::expect_identical(httr2::resp_status(first_replay_resp), 200L)
  testthat::expect_identical(httr2::resp_status(second_replay_resp), 401L)
  testthat::expect_identical(second_replay_body$error, "dpop_jti_replay")
})
