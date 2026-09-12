smart_context_fixture <- function(patient = "example-patient", scopes = "patient/Patient.r") {
  client <- smart_client(smart_client_fixture(), "example", "https://app.example/callback",
    scopes = c("launch/patient", scopes), required_scopes = scopes)
  token <- OAuthToken(access_token = "example-access", refresh_token = "example-refresh",
    token_type = "Bearer", expires_at = as.numeric(Sys.time()) + 300,
    granted_scopes = scopes, granted_scopes_verified = TRUE,
    extra_fields = list(patient = patient, encounter = "example-encounter", need_patient_banner = TRUE))
  list(client = client, token = smart_update_token_context(client, token))
}

test_that("SMART context requires actual patient evidence and validates scalar types", {
  record <- smart_context_fixture()
  expect_identical(record$token@smart_context$patient, "example-patient")
  expect_identical(record$token@smart_context$revision, 1L)
  expect_false(record$token@smart_context$changed)
  for (bad in list(NULL, "", 42, "Patient/example", "../example", strrep("x", 65))) {
    token <- record$token
    token@extra_fields <- list(patient = bad)
    expect_error(smart_update_token_context(record$client, token),
      "patient context|resource ID")
  }
  token <- record$token
  token@extra_fields <- list(patient = "example", need_patient_banner = "false")
  expect_error(smart_update_token_context(record$client, token), "boolean")
  expect_no_error(smart_context_fixture(patient = "001.abc-123"))
})

test_that("refresh carries omitted context but distinguishes clear and change", {
  record <- smart_context_fixture()
  previous <- record$token
  token <- previous
  token@extra_fields <- list()
  next_token <- smart_update_token_context(record$client, token, previous)
  expect_identical(next_token@smart_context, previous@smart_context)
  token@extra_fields <- list(patient = "second-patient", encounter = NULL, need_patient_banner = FALSE)
  changed <- smart_update_token_context(record$client, token, previous)
  expect_identical(changed@smart_context$patient, "second-patient")
  expect_null(changed@smart_context$encounter)
  expect_false(changed@smart_context$need_patient_banner)
  expect_identical(changed@smart_context$revision, 2L)
  expect_true(changed@smart_context$changed)
  token@extra_fields <- list(patient = NULL)
  expect_error(smart_update_token_context(record$client, token, previous), "patient context")
  expect_identical(previous@smart_context$patient, "example-patient")
  previous@smart_context <- list()
  expect_error(smart_update_token_context(record$client, token, previous), "original interpreted")
})

test_that("SMART context and rotating credentials are accepted together", {
  record <- smart_context_fixture()
  body <- list(access_token = "next-access", refresh_token = "next-refresh",
    token_type = "Bearer", expires_in = 60, scope = "patient/Patient.r")
  local_mocked_bindings(req_with_retry = function(req, ...) {
    httr2::response(url = req$url, status = 200,
      headers = list("content-type" = "application/json"),
      body = charToRaw(jsonlite::toJSON(body, auto_unbox = TRUE, null = "null")))
  }, .package = "shinyOAuth")
  token <- refresh_token(record$client, record$token)
  expect_identical(token@smart_context$patient, "example-patient")
  expect_identical(token@refresh_token, "next-refresh")
  body$patient <- "second-patient"
  changed <- refresh_token(record$client, token)
  expect_identical(changed@smart_context$revision, 2L)
  expect_identical(changed@smart_context$patient, "second-patient")
  expect_null(changed@smart_context$encounter)
  expect_identical(changed@refresh_token, "next-refresh")
  body$patient <- 42
  expect_error(refresh_token(record$client, changed), "resource ID")
  expect_identical(changed@smart_context$patient, "second-patient")
})

test_that("patient changes clear only an omitted dependent encounter", {
  record <- smart_context_fixture(scopes = "user/Patient.r")
  previous <- record$token
  for (patient in list("second-patient", NULL)) {
    token <- previous
    token@extra_fields <- list(patient = patient)
    changed <- smart_update_token_context(record$client, token, previous)
    expect_identical(changed@smart_context$patient, patient)
    expect_null(changed@smart_context$encounter)
    expect_identical(changed@smart_context$revision, 2L)
  }
  token@extra_fields <- list(patient = "second-patient", encounter = "second-encounter")
  changed <- smart_update_token_context(record$client, token, previous)
  expect_identical(changed@smart_context$encounter, "second-encounter")
  token@extra_fields <- list(patient = previous@smart_context$patient)
  unchanged <- smart_update_token_context(record$client, token, previous)
  expect_identical(unchanged@smart_context, previous@smart_context)
})

test_that("SMART helpers restrict requests and redact general summaries", {
  record <- smart_context_fixture()
  ref <- OAuthConnection$new("example-reference", record$client, function() record)
  expect_identical(smart_context(ref)$patient, "example-patient")
  expect_false(any(grepl("example-patient|example-encounter", unlist(ref$summary()))))
  called <- FALSE
  local_mocked_bindings(perform_resource_req = function(token, url, ...) {
    called <<- TRUE
    url$url
  }, .package = "shinyOAuth")
  expect_identical(smart_patient(ref), "https://ehr.example/fhir/R4/Patient/example-patient")
  expect_true(called)
  called <- FALSE
  record$token@granted_scopes <- "patient/Observation.r"
  expect_error(smart_patient(ref), "unavailable")
  expect_false(called)
  record <- smart_context_fixture(scopes = "user/Practitioner.r")
  record$token@smart_context$fhirUser <- "https://other.example/Practitioner/example"
  record$token@id_token <- jose::jwt_encode_sig(jose::jwt_claim(sub = "example-user"),
    openssl::rsa_keygen(2048))
  record$token@id_token_validated <- TRUE
  foreign <- OAuthConnection$new("another-reference", record$client, function() record)
  expect_error(smart_fhir_user(foreign), "outside")
  expect_false(called)
  record$token@smart_context$fhirUser <- "https://ehr.example/fhir/R4/Practitioner/example"
  expect_identical(smart_fhir_user(foreign), record$token@smart_context$fhirUser)
  record$token@smart_context$fhirUser <- "Practitioner/example"
  expect_identical(smart_fhir_user(foreign), "https://ehr.example/fhir/R4/Practitioner/example")
})

test_that("SMART read helpers negotiate FHIR JSON while generic requests keep their defaults", {
  skip_if_not_installed("webfakes")
  app <- webfakes::new_app()
  app$get("/fhir/R4/:type/:id", function(req, res) {
    if (identical(req$get_header("Accept"), "application/fhir+json")) {
      res$set_header("Content-Type", "application/fhir+json")$send(
        paste0('{"resourceType":"', req$params$type, '","id":"', req$params$id, '"}'))
    } else {
      res$set_header("Content-Type", "application/fhir+xml")$send(
        '<Patient xmlns="http://hl7.org/fhir"><id value="example-patient"/></Patient>')
    }
  })
  process <- webfakes::local_app_process(app)
  record <- smart_identity_fixture()
  site <- smart_client_fixture(oidc = TRUE)
  site$fhir_base <- process$url("/fhir/R4")
  site$allow_http_loopback <- TRUE
  record$client <- smart_client(site, "example", "https://app.example/callback",
    scopes = "user/Patient.r", identity = "fhirUser")
  record$token@granted_scopes <- c("openid", "fhirUser", "user/Patient.r")
  record$token@extra_fields <- list(patient = "example-patient")
  record$token <- smart_update_token_context(record$client, record$token)
  ref <- OAuthConnection$new("json-negotiation", record$client, function() record)
  patient <- smart_patient(ref)
  expect_identical(httr2::resp_content_type(patient), "application/fhir+json")
  expect_identical(httr2::resp_body_json(patient)$resourceType, "Patient")
  user <- smart_fhir_user(ref)
  expect_identical(httr2::resp_content_type(user), "application/fhir+json")
  expect_identical(httr2::resp_body_json(user)$resourceType, "Practitioner")
  generic <- ref$request("fhir", "Patient/example-patient")
  expect_identical(httr2::resp_content_type(generic), "application/fhir+xml")
})

test_that("retained credentials preserve interpreted context without plaintext", {
  record <- smart_context_fixture()
  key <- openssl::rand_bytes(32)
  owner <- strrep("a", 32)
  id <- strrep("b", 32)
  sealed <- connection_credentials_seal(record$token, owner, id, record$client, key, 1000)
  expect_false(grepl("example-patient|example-encounter", sealed))
  opened <- connection_credentials_open(sealed, owner, id, record$client, key)
  expect_identical(opened$token@smart_context, record$token@smart_context)
})

test_that("Patient identity reads accept only the matching patient context", {
  record <- smart_context_fixture()
  record$token@id_token <- jose::jwt_encode_sig(jose::jwt_claim(sub = "example-user"),
    openssl::rsa_keygen(2048))
  record$token@id_token_validated <- TRUE
  ref <- OAuthConnection$new("patient-identity", record$client, function() record)
  local_mocked_bindings(perform_resource_req = function(token, url, follow_redirect, ...) {
    expect_identical(follow_redirect, FALSE)
    url$url
  }, .package = "shinyOAuth")
  for (reference in c("Patient/example-patient",
      "https://ehr.example/fhir/R4/Patient/example-patient")) {
    record$token@smart_context$fhirUser <- reference
    expect_identical(smart_fhir_user(ref), smart_patient(ref))
  }
  record$token@smart_context$fhirUser <- "Patient/someone-else"
  expect_error(smart_fhir_user(ref), "does not cover")
  record$token@smart_context$fhirUser <- "Practitioner/example-patient"
  expect_error(smart_fhir_user(ref), "does not cover")
})

test_that("identity scopes authorize the signed same-base fhirUser reference", {
  record <- smart_identity_fixture()
  ref <- OAuthConnection$new("signed-identity", record$client, function() record)
  local_mocked_bindings(perform_resource_req = function(token, url, follow_redirect, ...) {
    expect_identical(follow_redirect, FALSE)
    url$url
  }, .package = "shinyOAuth")
  expect_identical(smart_fhir_user(ref), "https://ehr.example/fhir/R4/Practitioner/example")
  record <- smart_identity_fixture("https://ehr.example/fhir/R4/identity/example")
  ref <- OAuthConnection$new("signed-identity", record$client, function() record)
  expect_identical(smart_fhir_user(ref), record$token@smart_context$fhirUser)
  record <- smart_identity_fixture("https://other.example/identity/example")
  ref <- OAuthConnection$new("signed-identity", record$client, function() record)
  expect_error(smart_fhir_user(ref), "outside")
  record$token@id_token_validated <- FALSE
  expect_error(smart_fhir_user(ref), "validated")
})

test_that("signed refresh identity continuity compares resolved FHIR references", {
  relative <- "Practitioner/example"
  absolute <- "https://ehr.example/fhir/R4/Practitioner/example"
  for (references in list(c(relative, absolute), c(absolute, relative),
      rep("https://other.example/identity/example", 2))) {
    record <- smart_identity_fixture(references[[1L]])
    local_mocked_bindings(fetch_jwks = function(...) record$jwks, .package = "shinyOAuth")
    claims <- record$claims
    claims$fhirUser <- references[[2L]]
    claims$nonce <- NULL
    response <- function() {
      list(access_token = "refreshed-access", refresh_token = "rotated-refresh",
        token_type = "Bearer", expires_in = 300, scope = "openid fhirUser",
        id_token = jose::jwt_encode_sig(do.call(jose::jwt_claim, claims), record$key))
    }
    local_mocked_bindings(req_with_retry = function(req, ...) {
      httr2::response(url = req$url, status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw(jsonlite::toJSON(response(), auto_unbox = TRUE)))
    }, .package = "shinyOAuth")
    refreshed <- refresh_token(record$client, record$token)
    expect_identical(refreshed@smart_context, record$token@smart_context)
    expect_identical(refreshed@id_token_claims$fhirUser, references[[2L]])
    expect_identical(refreshed@id_token_validated, TRUE)
    expect_identical(refreshed@refresh_token, "rotated-refresh")
    claims$fhirUser <- "Practitioner/someone-else"
    expect_error(refresh_token(record$client, refreshed), "fhirUser changed")
    claims$fhirUser <- references[[2L]]
    claims$sub <- "different-user"
    expect_error(refresh_token(record$client, refreshed), class = "shinyOAuth_id_token_error")
    claims$sub <- record$claims$sub
    claims$iss <- "https://different.example"
    expect_error(refresh_token(record$client, refreshed), class = "shinyOAuth_id_token_error")
  }
})
