extra_fields_test_callback <- function(client) {
  browser_token <- valid_browser_token()
  payload <- parse_query_param(
    prepare_call(client, browser_token = browser_token),
    "state"
  )
  handle_callback(
    client,
    code = "example-code",
    payload = payload,
    browser_token = browser_token
  )
}

test_that("additional token fields default to empty lists", {
  token <- OAuthToken(access_token = "example-access")
  expect_identical(token@extra_fields, list())
  expect_identical(token@initial_extra_fields, list())
})

test_that("login preserves provider extras separately from token metadata", {
  client <- make_test_client(scopes = c("launch/patient", "patient/Patient.r"))
  body <- paste0(
    '{"access_token":"example-access","token_type":"Bearer",',
    '"refresh_token":"example-refresh","expires_in":3600,',
    '"scope":"launch/patient patient/Patient.r","cnf":{},',
    '"patient":"synthetic-patient","encounter":null,',
    '"need_patient_banner":false,',
    '"fhirContext":[{"reference":"Observation/example",',
    '"codes":["one","two"],"optional":null}],',
    '"authorization_details":[{"type":"smart_on_fhir",',
    '"locations":["https://example.com/fhir"],"patient":"other-id"}],',
    '"https://example.com/custom":{"enabled":true},',
    '"id_token_validated":true,".id_token_validated":true,',
    '"granted_scopes":["custom"],"granted_scopes_verified":false,',
    '"userinfo":{"name":"synthetic-name"},',
    '"extra_fields":{"patient":"nested-id"},',
    '"initial_extra_fields":{"patient":"nested-initial-id"}}'
  )
  events <- list()
  local_options(shinyOAuth.audit_hook = function(event) {
    events[[length(events) + 1L]] <<- event
  })
  local_mocked_bindings(
    req_with_retry = function(req, ...) {
      httr2::response(
        url = req$url,
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw(body)
      )
    },
    .package = "shinyOAuth"
  )

  token <- extra_fields_test_callback(client)
  expect_identical(token@extra_fields$patient, "synthetic-patient")
  expect_true("encounter" %in% names(token@extra_fields))
  expect_null(token@extra_fields$encounter)
  expect_identical(token@extra_fields$need_patient_banner, FALSE)
  expect_identical(token@extra_fields$fhirContext, list(list(
    reference = "Observation/example",
    codes = list("one", "two"),
    optional = NULL
  )))
  expect_identical(
    token@extra_fields$authorization_details[[1]]$locations,
    list("https://example.com/fhir")
  )
  expect_identical(
    token@extra_fields[["https://example.com/custom"]],
    list(enabled = TRUE)
  )
  expect_false(any(c(
    "access_token", "refresh_token", "token_type", "id_token",
    "expires_in", "scope", "cnf"
  ) %in% names(token@extra_fields)))
  expect_true(token@extra_fields$id_token_validated)
  expect_true(token@extra_fields[[".id_token_validated"]])
  expect_false(token@id_token_validated)
  expect_identical(token@userinfo, list())
  expect_identical(token@granted_scopes, c("launch/patient", "patient/Patient.r"))
  expect_true(token@granted_scopes_verified)
  expect_identical(token@extra_fields$extra_fields$patient, "nested-id")
  expect_identical(
    token@extra_fields$initial_extra_fields$patient,
    "nested-initial-id"
  )
  expect_identical(token@initial_extra_fields, token@extra_fields)

  # The initial snapshot and worker/session serialization retain all values.
  restored <- unserialize(serialize(token, NULL))
  expect_identical(restored@initial_extra_fields, token@extra_fields)
  token@extra_fields$patient <- "changed-locally"
  expect_identical(token@initial_extra_fields$patient, "synthetic-patient")
  expect_gt(length(events), 0L)
  expect_false(any(grepl(
    "synthetic-patient|synthetic-name|nested-initial-id",
    capture.output(str(events))
  )))
})

test_that("login handles form extras and does not expose generated metadata", {
  client <- make_test_client()
  body <- "access_token=example-access&token_type=Bearer&expires_in=3600&patient=00123"
  local_mocked_bindings(
    req_with_retry = function(req, ...) {
      httr2::response(
        url = req$url,
        status = 200,
        headers = list("content-type" = "application/x-www-form-urlencoded"),
        body = charToRaw(body)
      )
    },
    .package = "shinyOAuth"
  )
  token <- extra_fields_test_callback(client)
  expect_identical(token@extra_fields, list(patient = "00123"))
  expect_identical(token@initial_extra_fields, token@extra_fields)

  body <- "access_token=next-access&token_type=Bearer&expires_in=3600"
  next_token <- extra_fields_test_callback(client)
  expect_identical(next_token@extra_fields, list())
  expect_identical(next_token@initial_extra_fields, list())
})

test_that("refresh replaces extras while retaining the original launch context", {
  client <- make_test_client()
  initial <- list(patient = "initial-patient", encounter = "initial-encounter")
  token <- OAuthToken(
    access_token = "initial-access",
    refresh_token = "example-refresh",
    extra_fields = initial,
    initial_extra_fields = initial
  )
  response_extras <- list()
  local_mocked_bindings(
    req_with_retry = function(req, ...) {
      httr2::response(
        url = req$url,
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw(jsonlite::toJSON(c(
          list(access_token = "next-access", token_type = "Bearer", expires_in = 3600),
          response_extras
        ), auto_unbox = TRUE, null = "null"))
      )
    },
    .package = "shinyOAuth"
  )

  for (extras in list(
    list(),
    list(patient = "new-patient"),
    list(patient = NULL),
    list(need_patient_banner = FALSE),
    list()
  )) {
    response_extras <- extras
    token <- refresh_token(client, token)
    expect_identical(token@extra_fields, extras)
    expect_identical(token@initial_extra_fields, initial)
  }

  # A manually constructed token's latest extras are not a known login response.
  manual <- OAuthToken(
    access_token = "manual-access",
    refresh_token = "manual-refresh",
    extra_fields = list(patient = "manual-patient")
  )
  refreshed <- refresh_token(client, manual)
  expect_identical(refreshed@initial_extra_fields, list())
})

test_that("rejected refresh cannot publish replacement extra fields", {
  client <- make_test_client()
  client@provider@introspection_url <- "https://example.com/introspect"
  client@introspect <- TRUE
  initial <- list(patient = "initial-patient")
  token <- OAuthToken(
    access_token = "initial-access",
    refresh_token = "example-refresh",
    extra_fields = initial,
    initial_extra_fields = initial
  )
  local_mocked_bindings(
    req_with_retry = function(req, ...) {
      httr2::response(
        url = req$url,
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw(paste0(
          '{"access_token":"rejected-access","token_type":"Bearer",',
          '"expires_in":3600,"patient":"rejected-patient"}'
        ))
      )
    },
    introspect_token = function(...) {
      list(supported = TRUE, status = "ok", active = FALSE, raw = list(active = FALSE))
    },
    .package = "shinyOAuth"
  )
  expect_error(refresh_token(client, token), class = "shinyOAuth_token_error")
  expect_identical(token@access_token, "initial-access")
  expect_identical(token@extra_fields, initial)
  expect_identical(token@initial_extra_fields, initial)
})

test_that("the module exposes extras and clears them with the login session", {
  local_options(shinyOAuth.skip_browser_token = TRUE)
  response_body <- new.env(parent = emptyenv())
  response_body$value <- paste0(
    '{"access_token":"first-access","token_type":"Bearer",',
    '"expires_in":3600,"patient":"first-patient"}'
  )
  local_mocked_bindings(
    req_with_retry = function(req, ...) {
      httr2::response(
        url = req$url,
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw(response_body$value)
      )
    },
    revoke_token = function(...) invisible(NULL),
    .package = "shinyOAuth"
  )
  shiny::testServer(
    oauth_module_server,
    args = list(id = "auth", client = make_test_client(), auto_redirect = FALSE, async = FALSE),
    expr = {
      state <- parse_query_param(values$build_auth_url(), "state")
      values$.process_query(paste0("?code=first&state=", state))
      session$flushReact()
      expect_true(values$authenticated)
      expect_identical(values$token@extra_fields$patient, "first-patient")
      expect_identical(values$token@initial_extra_fields$patient, "first-patient")

      values$logout()
      session$flushReact()
      expect_null(values$token)
      expect_false(values$authenticated)

      response_body$value <- paste0(
        '{"access_token":"second-access","token_type":"Bearer",',
        '"expires_in":3600}'
      )
      values$browser_token <- "__SKIPPED__"
      state <- parse_query_param(values$build_auth_url(), "state")
      values$.process_query(paste0("?code=second&state=", state))
      session$flushReact()
      expect_true(values$authenticated)
      expect_identical(values$token@extra_fields, list())
      expect_identical(values$token@initial_extra_fields, list())
    }
  )
})

test_that("token printing redacts additional parameter names and values", {
  token <- OAuthToken(
    access_token = "example-access",
    extra_fields = list(`private-field-name` = list(patient = "private-patient")),
    initial_extra_fields = list(patient = "private-initial-patient")
  )
  for (output in c(format(token), capture.output(print(token)))) {
    expect_false(grepl("private-field-name|private-patient|private-initial-patient", output))
  }
  expect_match(paste(format(token), collapse = "\n"), "extra_fields", fixed = TRUE)
})
