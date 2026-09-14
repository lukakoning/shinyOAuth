smart_details_entry <- function(base, ...) {
  c(list(type = "smart_on_fhir", locations = list(base), fhirVersions = list("4.0.1")), list(...))
}

smart_details_callback <- function(client) {
  browser <- valid_browser_token()
  state <- parse_query_param(prepare_call(client, browser), "state")
  handle_callback(client, "synthetic-code", state, browser)
}

test_that("initial SMART context and scopes use only the configured location", {
  client <- smart_client(smart_client_fixture(), "example", "https://app.example/callback",
    scopes = c("user/Patient.rs", "user/Observation.r"), required_scopes = "user/Patient.r")
  body <- list(access_token = "synthetic-access", refresh_token = "synthetic-refresh",
    token_type = "Bearer", expires_in = 300, scope = "user/Patient.rs user/Observation.r",
    patient = "top-patient", encounter = "top-encounter", authorization_details = list(
      smart_details_entry("https://other.example/fhir", patient = "other-patient"),
      smart_details_entry(client@smart$fhir_base, patient = "local-patient",
        scope = "user/Patient.r")))
  local_mocked_bindings(req_with_retry = function(req, ...) {
    httr2::response(url = req$url, status = 200, headers = list("content-type" = "application/json"),
      body = charToRaw(jsonlite::toJSON(body, auto_unbox = TRUE, null = "null")))
  }, .package = "shinyOAuth")
  token <- smart_details_callback(client)
  expect_identical(token@smart_context$patient, "local-patient")
  expect_identical(token@smart_context$encounter, "top-encounter")
  expect_identical(token@granted_scopes, "user/Patient.r")
  expect_identical(token@extra_fields$patient, "top-patient")
  expect_identical(token@extra_fields$authorization_details, body$authorization_details)
  record <- list(client = client, token = token)
  ref <- OAuthConnection$new("location-reference", client, function() record)
  local_mocked_bindings(perform_resource_req = function(token, url, ...) url$url,
    .package = "shinyOAuth")
  expect_identical(smart_patient(ref), paste0(client@smart$fhir_base, "/Patient/local-patient"))
  expect_error(ref$request("fhir", "Observation/example", required_scopes = "user/Observation.r"),
    "grant does not cover")
  expect_error(ref$request("fhir", "https://other.example/fhir/Patient/other-patient"), "approved base")
  expect_identical(client@resource_bases, c(fhir = client@smart$fhir_base))
  body$authorization_details[[2]]$scope <- NULL
  body$authorization_details[[2]]$patient <- NULL
  fallback <- smart_details_callback(client)
  expect_identical(fallback@smart_context$patient, "top-patient")
  expect_setequal(fallback@granted_scopes, c("user/Patient.rs", "user/Observation.r"))
  body$authorization_details[[2]]["encounter"] <- list(NULL)
  expect_null(smart_details_callback(client)@smart_context$encounter)
  body$authorization_details <- body$authorization_details[1]
  expect_identical(smart_details_callback(client)@smart_context$patient, "top-patient")
  body$authorization_details <- list(smart_details_entry(paste0(client@smart$fhir_base, "/"),
    patient = "local-patient", encounter = "local-encounter"))
  canonical <- smart_details_callback(client)
  expect_identical(canonical@smart_context$patient, "local-patient")
  expect_identical(canonical@smart_context$encounter, "local-encounter")
})

test_that("refresh applies location overrides before scope and context acceptance", {
  client <- smart_client(smart_client_fixture(), "example", "https://app.example/callback",
    scopes = "user/Patient.rs", required_scopes = "user/Patient.r")
  body <- list(access_token = "synthetic-access", refresh_token = "synthetic-refresh",
    token_type = "Bearer", expires_in = 300, scope = "user/Patient.rs",
    patient = "top-patient", encounter = "top-encounter")
  local_mocked_bindings(req_with_retry = function(req, ...) {
    httr2::response(url = req$url, status = 200, headers = list("content-type" = "application/json"),
      body = charToRaw(jsonlite::toJSON(body, auto_unbox = TRUE, null = "null")))
  }, .package = "shinyOAuth")
  initial <- smart_details_callback(client)
  body$refresh_token <- "rotated-refresh"
  body$encounter <- NULL
  body$authorization_details <- list(smart_details_entry(client@smart$fhir_base,
    patient = "local-patient", scope = "user/Patient.r"))
  narrowed <- refresh_token_dispatch(client, initial, scope_request =
    refresh_scope_request(client, initial, "user/Patient.r"))
  expect_identical(narrowed@granted_scopes, "user/Patient.r")
  expect_identical(narrowed@smart_context$patient, "local-patient")
  expect_null(narrowed@smart_context$encounter)
  expect_identical(narrowed@smart_context$revision, 2L)
  expect_identical(narrowed@refresh_token, "rotated-refresh")
  expect_identical(initial@smart_context$patient, "top-patient")
  body$authorization_details[[1]]$patient <- "Patient/invalid"
  expect_error(refresh_token(client, narrowed), "resource ID")
  expect_identical(narrowed@smart_context$patient, "local-patient")
  body$authorization_details[[1]]$patient <- "local-patient"
  body$authorization_details[[1]]$scope <- "user/Patient.rs"
  expect_error(refresh_token(client, narrowed), "exceeds|prior grant")
  body$scope <- "user/Patient.r"
  body$authorization_details[[1]]$scope <- NULL
  body$authorization_details[[1]]$patient <- NULL
  fallback <- refresh_token(client, narrowed)
  expect_identical(fallback@smart_context$patient, "top-patient")
  expect_identical(fallback@granted_scopes, "user/Patient.r")
  body$patient <- NULL
  body$authorization_details <- NULL
  omitted <- refresh_token(client, narrowed)
  expect_identical(omitted@smart_context$patient, "local-patient")
  expect_identical(omitted@smart_context$revision, 2L)
})

test_that("invalid or ambiguous local authorization details are rejected", {
  client <- smart_client(smart_client_fixture(), "example", "https://app.example/callback",
    scopes = c("launch/patient", "patient/Patient.r"), required_scopes = "patient/Patient.r")
  base <- list(access_token = "synthetic-access", token_type = "Bearer", expires_in = 300,
    scope = "patient/Patient.r", patient = "top-patient")
  entry <- smart_details_entry(client@smart$fhir_base, patient = "local-patient")
  for (details in list(NULL, "unsupported", entry, list(list(type = "smart_on_fhir")),
      list(entry, entry), list(smart_details_entry(paste0(client@smart$fhir_base, "/../R4"))))) {
    expect_error(verify_token_set(client, c(base, list(authorization_details = details)), NULL),
      "authorization_details")
  }
  for (scope in list(NULL, 42, "", "user/Patient.r")) {
    entry["scope"] <- list(scope)
    expect_error(verify_token_set(client, c(base, list(authorization_details = list(entry))), NULL),
      "scope|permissions")
  }
  entry$scope <- NULL
  entry["patient"] <- list(NULL)
  token <- OAuthToken(access_token = "synthetic-access", token_type = "Bearer",
    granted_scopes = "patient/Patient.r", granted_scopes_verified = TRUE,
    extra_fields = list(patient = "top-patient", authorization_details = list(entry)))
  expect_error(smart_update_token_context(client, token), "patient context")
  for (field in c("type", "locations", "fhirVersions")) {
    malformed <- smart_details_entry(client@smart$fhir_base)
    names(malformed)[names(malformed) == field] <- paste0(field, "_hint")
    expect_error(verify_token_set(client, c(base, list(authorization_details = list(malformed))), NULL),
      "authorization_details")
  }
  ordinary <- make_test_client(scopes = "read")
  ordinary@scope_validation <- "none"
  response <- base[setdiff(names(base), "scope")]
  response$scope_hint <- "write"
  verified <- verify_token_set(ordinary, response, NULL)
  expect_identical(verified$granted_scopes, "read")
  expect_false(verified$granted_scopes_verified)
})
