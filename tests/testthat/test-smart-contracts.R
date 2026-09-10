smart_contract_fixture <- function(name) {
  paste(readLines(test_path("fixtures", "smart", name)), collapse = "\n")
}

smart_contract_response <- function(req, name) {
  httr2::response(
    url = req$url, status = 200,
    headers = list("content-type" = "application/json"),
    body = charToRaw(smart_contract_fixture(name))
  )
}

test_that("SMART-looking scopes do not select a profile on ordinary clients", {
  client <- make_test_client(scopes = c("launch/patient", "patient/Patient.rs"))
  url <- prepare_call(client, valid_browser_token())
  expect_identical(parse_query_param(url, "scope", TRUE),
                   "launch/patient patient/Patient.rs")
  expect_true(is.na(parse_query_param(url, "aud")))
  expect_true(is.na(parse_query_param(url, "launch")))
  expect_true(is.na(parse_query_param(url, "nonce")))
  expect_identical(parse_query_param(url, "code_challenge_method"), "S256")
  expect_false(shinyOAuth:::provider_uses_oidc(client@provider))
})

test_that("ordinary clients retain literal scope comparison for SMART syntax", {
  client <- make_test_client(scopes = c("launch/patient", "patient/Patient.rs"))
  client@scope_validation <- "strict"
  local_mocked_bindings(
    req_with_retry = function(req, ...) smart_contract_response(req, "launch-token.json"),
    .package = "shinyOAuth"
  )
  state <- parse_query_param(prepare_call(client, valid_browser_token()), "state")
  expect_error(
    handle_callback(client, "synthetic-code", state, valid_browser_token()),
    class = "shinyOAuth_token_error"
  )
})

test_that("raw SMART context snapshots survive refresh without identity inference", {
  client <- make_test_client(scopes = c(
    "launch/patient", "patient/Patient.r", "patient/Patient.s"
  ))
  response_name <- "launch-token.json"
  local_mocked_bindings(
    req_with_retry = function(req, ...) smart_contract_response(req, response_name),
    .package = "shinyOAuth"
  )
  state <- parse_query_param(prepare_call(client, valid_browser_token()), "state")
  token <- handle_callback(client, "synthetic-code", state, valid_browser_token())
  initial <- token@initial_extra_fields
  expect_identical(initial$patient, "synthetic-patient-a")
  expect_true("encounter" %in% names(initial))
  expect_null(initial$encounter)
  expect_false(initial$need_patient_banner)
  expect_false(token@id_token_validated)
  expect_identical(token@userinfo, list())
  response_name <- "refresh-token.json"
  token <- refresh_token(client, token)
  expect_identical(token@initial_extra_fields, initial)
  expect_identical(token@extra_fields, list())
  expect_identical(token@refresh_token, "synthetic-refresh-a-rotated")
  expect_false(grepl("synthetic-", paste(format(token), collapse = "\n")))
})

test_that("a new legacy Shiny session starts without the preceding session's token", {
  client <- make_test_client(scopes = c(
    "launch/patient", "patient/Patient.r", "patient/Patient.s"
  ))
  local_options(shinyOAuth.skip_browser_token = TRUE)
  local_mocked_bindings(
    req_with_retry = function(req, ...) smart_contract_response(req, "launch-token.json"),
    .package = "shinyOAuth"
  )
  shiny::testServer(oauth_module_server,
    args = list(id = "auth", client = client, auto_redirect = FALSE, async = FALSE),
    expr = {
      state <- parse_query_param(values$build_auth_url(), "state")
      values$.process_query(paste0("?code=synthetic-code&state=", state))
      session$flushReact()
      expect_true(values$authenticated)
      expect_identical(values$token@extra_fields$patient, "synthetic-patient-a")
    }
  )
  shiny::testServer(oauth_module_server,
    args = list(id = "auth", client = client, auto_redirect = FALSE, async = FALSE),
    expr = {
      expect_false(values$authenticated)
      expect_null(values$token)
    }
  )
})

test_that("legacy callback classification does not accept an EHR launch", {
  response <- oauth_ui(shiny::fluidPage("App"), id = "auth", client = make_test_client())(
    list(REQUEST_METHOD = "GET", PATH_INFO = "/", QUERY_STRING =
      "iss=https%3A%2F%2Fapi.site-a.example%2Ffhir%2FR4&launch=synthetic-launch",
      rook.url_scheme = "http", HTTP_HOST = "localhost:8100")
  )
  expect_identical(response$status, 400L)
  expect_false(grepl("synthetic-launch", response$content, fixed = TRUE))
})
