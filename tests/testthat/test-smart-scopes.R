smart_scope_test_client <- function(
    required = "patient/Patient.r", scopes = c(required, "patient/Observation.rs"),
    allow_v1 = FALSE) {
  client <- make_test_client(scopes = scopes)
  S7::props(client) <- list(scope_policy = list(
    profile = "smart", version = 1L, allow_v1 = allow_v1
  ), required_scopes = required)
  client
}

test_that("SMART v2 covers unions, interaction subsets and resource wildcards", {
  coverage <- function(want, have) {
    evaluate_scope_coverage(want, have, profile = "smart")$status
  }
  cases <- list(
    list("patient/Observation.rs", c("patient/Observation.r", "patient/Observation.s"), "covered"),
    list("patient/Observation.r", "patient/*.rs", "covered"),
    list("patient/*.rs", c("patient/Patient.rs", "patient/Observation.rs"), "insufficient"),
    list("patient/*.rs", c("patient/*.r", "patient/*.s"), "covered"),
    list("patient/Observation.cruds", c("patient/Observation.rs", "patient/Observation.cud"), "covered"),
    list("patient/Observation.r", "user/*.cruds", "insufficient"),
    list("user/Observation.r", "system/*.cruds", "insufficient"),
    list("user/Observation.r", "patient/*.cruds", "insufficient"),
    list("patient/Observation.r", "patient/Observation.cud", "insufficient"),
    list("patient/Observation.rs", "patient/Observation.r", "insufficient"),
    list(c("openid", "fhirUser"), "openid", "insufficient"),
    list("launch/patient", "launch", "insufficient"),
    list("custom_permission", "custom_permission", "covered"),
    list("patient/Observation.dus", "patient/Observation.dus", "indeterminate"),
    list("patient/Observation.rr", "patient/Observation.rr", "indeterminate"),
    list("patient/Observation.", "patient/*.cruds", "indeterminate"),
    list("patient/Observation.read", "patient/Observation.read", "indeterminate"),
    list("patient/observation.r", "patient/*.r", "indeterminate")
  )
  for (case in cases) {
    expect_identical(coverage(case[[1]], case[[2]]), case[[3]],
      info = paste(case[[1]], collapse = " ")
    )
  }
  expect_identical(coverage(character(), character()), "covered")
  expect_identical(coverage("patient/Patient.r", character()), "insufficient")
  expect_error(coverage(rep("x", 257L), paste0("x", seq_len(257))), "size limit")
})

test_that("SMART v1 aliases require explicit policy and keep wire spellings", {
  requested <- c("patient/Observation.read", "patient/Patient.write")
  granted <- c("patient/Observation.rs", "patient/Patient.cud")
  expect_identical(evaluate_scope_coverage(requested, granted,
    profile = "smart", allow_v1 = TRUE
  )$status, "covered")
  expect_identical(evaluate_scope_coverage("patient/Patient.cruds", "patient/*.*",
    profile = "smart", allow_v1 = TRUE
  )$status, "covered")
  client <- smart_scope_test_client(
    required = requested,
    scopes = requested, allow_v1 = TRUE
  )
  url <- prepare_call(client, browser_token = valid_browser_token())
  expect_setequal(strsplit(utils::URLdecode(parse_query_param(url, "scope")), " ")[[1L]], requested)
  expect_error(
    evaluate_scope_coverage("r", "r", profile = "smart", version = 2L),
    "Unsupported"
  )
})

test_that("granular scope comparisons never guess query implication", {
  scope <- "patient/Observation.rs?category=http://example.org|laboratory"
  same_parts <- c(
    "patient/Observation.r?category=http://example.org|laboratory",
    "patient/Observation.s?category=http://example.org|laboratory"
  )
  expect_identical(smart_scope_coverage(scope, same_parts)$status, "covered")
  expect_identical(smart_scope_coverage(scope, "patient/*.rs")$status, "covered")
  expect_identical(
    smart_scope_coverage("patient/Observation.rs", scope)$status,
    "insufficient"
  )
  other <- "patient/Observation.rs?category=http://example.org|vital-signs"
  result <- smart_scope_coverage(scope, other)
  expect_identical(result$status, "indeterminate")
  expect_identical(result$indeterminate, scope)
  expect_identical(result$missing, character())
  for (query in c("code:in=x", "patient.birthdate=1990", "_filter=x", "code=%zz", "code=", "")) {
    unknown <- paste0("patient/Observation.rs?", query)
    expect_identical(smart_scope_coverage(unknown, unknown)$status, "indeterminate")
  }
  expect_identical(
    smart_scope_coverage(
      "patient/Observation.rs?a=1&b=2", "patient/Observation.rs?b=2&a=1"
    )$status,
    "indeterminate"
  )
})

test_that("SMART response scope is explicit, including the empty grant", {
  client <- smart_scope_test_client(required = character())
  base <- list(access_token = "example", token_type = "Bearer", expires_in = 60)
  for (mode in c("none", "warn", "strict")) {
    client@scope_validation <- mode
    expect_error(verify_token_set(client, base, nonce = NULL), "explicit scope")
    expect_error(verify_token_set(client, base,
      nonce = NULL, is_refresh = TRUE,
      prior_granted_scopes = character()
    ), "explicit scope")
    verified <- verify_token_set(client, c(base, list(scope = "")), nonce = NULL)
    expect_identical(verified$granted_scopes, character())
    expect_true(verified$granted_scopes_verified)
  }
  for (bad in list(NULL, NA_character_, c("a", "b"), list("a"), 1, "a  b", "a\tb")) {
    expect_error(verify_token_set(client, c(base, list(scope = bad)), nonce = NULL),
      class = "shinyOAuth_token_error"
    )
  }
  required <- smart_scope_test_client()
  expect_error(
    verify_token_set(required, c(base, list(scope = "")), nonce = NULL),
    "required permissions"
  )
})

test_that("SMART parsing accepts empty scope only with explicit opt-in", {
  for (kind in c("application/json", "application/x-www-form-urlencoded", "text/plain")) {
    body <- if (kind == "application/x-www-form-urlencoded") {
      "access_token=example&token_type=Bearer&scope="
    } else {
      '{"access_token":"example","token_type":"Bearer","scope":""}'
    }
    response <- httr2::response(
      status = 200, body = charToRaw(body),
      headers = list("content-type" = kind)
    )
    expect_error(parse_token_response(response), "Response scope")
    expect_identical(parse_token_response(response, allow_empty_scope = TRUE)$scope, "")
  }
  for (value in c("null", "[]", "[\"x\"]", "false", "42")) {
    body <- paste0('{"scope":', value, "}")
    expect_error(parse_token_response_json(body, allow_empty_scope = TRUE),
      class = "shinyOAuth_parse_error"
    )
  }
  expect_error(parse_token_response_json('{"scope":"","scope":"x"}',
    allow_empty_scope = TRUE
  ), "duplicate")
})

test_that("SMART required permissions and refresh continuity use semantics", {
  client <- smart_scope_test_client()
  base <- list(access_token = "example", token_type = "Bearer", expires_in = 60)
  initial <- verify_token_set(client,
    c(base, list(scope = "patient/Patient.rs")),
    nonce = NULL
  )
  expect_identical(initial$granted_scopes, "patient/Patient.rs")
  expect_true(initial$granted_scopes_verified)
  smaller <- c(base, list(scope = "patient/Patient.r"))
  expect_no_warning(verify_token_set(client, smaller,
    nonce = NULL,
    is_refresh = TRUE, prior_granted_scopes = initial$granted_scopes
  ))
  for (scope in c("patient/Patient.cruds", "patient/*.rs", "patient/Patient.r custom")) {
    expect_error(verify_token_set(client, c(base, list(scope = scope)),
      nonce = NULL,
      is_refresh = TRUE, prior_granted_scopes = initial$granted_scopes
    ), "prior grant")
  }
  expect_error(verify_token_set(client, c(base, list(scope = "patient/Observation.rs")),
    nonce = NULL
  ), "required permissions")
})

test_that("SMART policy binds transactions and connection permissions", {
  client <- smart_scope_test_client()
  generic <- make_test_client(scopes = client@scopes)
  expect_false(identical(
    state_client_policy_fingerprint(client),
    state_client_policy_fingerprint(generic)
  ))
  changed <- client
  changed@scope_policy <- list(
    profile = "smart", version = 1L,
    allow_v1 = TRUE
  )
  expect_false(identical(
    state_client_policy_fingerprint(client),
    state_client_policy_fingerprint(changed)
  ))
  client <- connection_test_client(client, c(fhir = "https://example.com/fhir"),
    required_scopes = "patient/Patient.r"
  )
  token <- OAuthToken(
    access_token = "example", expires_at = as.numeric(Sys.time()) + 60,
    granted_scopes = "patient/Patient.rs", granted_scopes_verified = TRUE
  )
  record <- list(client = client, token = token)
  expect_identical(connection_record_status(record), "limited")
  record$token@granted_scopes <- c("patient/Patient.r", "patient/Observation.r", "patient/Observation.s")
  expect_identical(connection_record_status(record), "active")
  record$token@granted_scopes_verified <- FALSE
  expect_identical(connection_record_status(record), "insufficient_scope")
  record$token <- token
  called <- FALSE
  local_mocked_bindings(perform_resource_req = function(...) {
    called <<- TRUE
    "response"
  }, .package = "shinyOAuth")
  expect_identical(connection_record_request(
    record, "fhir", "Patient/example",
    NULL, "GET", "patient/Patient.r"
  ), "response")
  expect_true(called)
  called <- FALSE
  expect_error(connection_record_request(
    record, "fhir", "Observation",
    NULL, "GET", "patient/Observation.s"
  ), "Current grant")
  expect_false(called)
})

test_that("SMART scope evidence survives the actual callback and refresh paths", {
  client <- smart_scope_test_client(
    required = character(),
    scopes = "patient/Patient.rs"
  )
  response_scope <- "patient/Patient.r patient/Patient.s"
  local_mocked_bindings(req_with_retry = function(req, ...) {
    fields <- list(
      access_token = "example-access", refresh_token = "rotated-refresh",
      token_type = "Bearer", expires_in = 60
    )
    if (!is.null(response_scope)) fields$scope <- response_scope
    httr2::response(
      url = req$url, status = 200,
      headers = list("content-type" = "application/json"),
      body = charToRaw(jsonlite::toJSON(fields, auto_unbox = TRUE))
    )
  }, .package = "shinyOAuth")
  browser <- valid_browser_token()
  state <- parse_query_param(prepare_call(client, browser_token = browser), "state")
  token <- handle_callback(client,
    code = "example-code", payload = state,
    browser_token = browser
  )
  expect_setequal(token@granted_scopes, c("patient/Patient.r", "patient/Patient.s"))
  expect_true(token@granted_scopes_verified)
  response_scope <- "patient/Patient.r"
  refreshed <- refresh_token(client, token)
  expect_identical(refreshed@granted_scopes, response_scope)
  expect_true(refreshed@granted_scopes_verified)
  expect_identical(refreshed@refresh_token, "rotated-refresh")
  response_scope <- NULL
  expect_error(refresh_token(client, refreshed), "explicit scope")
  expect_identical(refreshed@granted_scopes, "patient/Patient.r")
  response_scope <- "patient/Patient.rs"
  expect_error(refresh_token(client, refreshed), "prior grant")
  response_scope <- ""
  empty <- refresh_token(client, refreshed)
  expect_identical(empty@granted_scopes, character())
  expect_true(empty@granted_scopes_verified)
  response_scope <- "patient/Patient.r"
  expect_error(refresh_token(client, empty), "prior grant")
})

test_that("SMART introspection cannot supply missing evidence or widen a grant", {
  client <- smart_scope_test_client(scopes = c("patient/Patient.rs", "patient/Observation.rs"))
  client@provider@introspection_url <- "https://example.com/introspect"
  client@introspect <- TRUE
  client@introspect_elements <- "scope"
  client@scope_validation <- "none"
  token <- OAuthToken(
    access_token = "example", granted_scopes = "patient/Patient.rs",
    granted_scopes_verified = TRUE
  )
  check <- function(scope) {
    enforce_token_introspection_policy(client, token,
      list(supported = TRUE, active = TRUE, raw = list(scope = scope)),
      phase = "exchange_code"
    )
  }
  expect_error(check(NULL), "Response scope")
  expect_error(
    enforce_token_introspection_policy(client, token,
      list(supported = TRUE, active = TRUE, raw = list()),
      phase = "exchange_code"
    ),
    "explicit scope"
  )
  expect_error(check(""), "required permissions")
  expect_error(check("patient/*.rs"), "prior grant")
  expect_error(check("patient/Patient.r patient/Observation.rs"), "prior grant")
  reduced <- check("patient/Patient.r")
  expect_identical(reduced@granted_scopes, "patient/Patient.r")
  expect_true(reduced@granted_scopes_verified)
  expect_identical(token@granted_scopes, "patient/Patient.rs")
})
