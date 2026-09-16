test_that("SMART openid identity is explicit and does not require fhirUser", {
  site <- smart_client_fixture(oidc = TRUE)
  client <- smart_client(
    site,
    "example",
    "https://app.example/callback",
    scopes = character(),
    identity = "openid"
  )
  expect_identical(client@scopes, "openid")
  expect_identical(client@required_scopes, "openid")
  expect_true(provider_uses_oidc(client@provider))
  expect_true(client@provider@id_token_validation)
  expect_true(client@provider@id_token_required)
  expect_true(client@provider@use_nonce)
  query <- httr2::url_parse(prepare_call(client, valid_browser_token()))[[
    "query"
  ]]
  expect_identical(query[["scope"]], "openid")
  expect_true(is_valid_string(query[["nonce"]]))
  expect_error(client@required_scopes <- character(), "identity validation")
  expect_error(
    client@provider@id_token_validation <- FALSE,
    "identity validation|id_token_validation"
  )
  expect_error(
    client@scopes <- c("openid", "fhirUser"),
    "Identity scopes require"
  )
  expect_error(
    smart_client(
      site,
      "example",
      "https://app.example/callback",
      scopes = "fhirUser",
      identity = "openid"
    ),
    "Identity scopes require"
  )
  expect_error(
    smart_client(
      smart_client_fixture(),
      "example",
      "https://app.example/callback",
      scopes = character(),
      identity = "openid"
    ),
    "sso-openid-connect"
  )
  none <- smart_client(
    site,
    "example",
    "https://app.example/callback",
    scopes = "user/Patient.r"
  )
  expect_false(provider_uses_oidc(none@provider))
  expect_false("openid" %in% none@scopes)
})

test_that("openid-only SMART callbacks and refresh expose a validated OIDC subject", {
  fixture <- smart_identity_fixture()
  client <- smart_client(
    smart_client_fixture(oidc = TRUE),
    "example",
    "https://app.example/callback",
    scopes = character(),
    identity = "openid"
  )
  claims <- fixture[["claims"]]
  claims[["fhirUser"]] <- NULL
  response <- NULL
  local_mocked_bindings(
    fetch_jwks = function(...) fixture[["jwks"]],
    req_with_retry = function(req, ...) {
      httr2::response(
        url = req[["url"]],
        status = 200L,
        headers = list("content-type" = "application/json"),
        body = charToRaw(jsonlite::toJSON(response, auto_unbox = TRUE))
      )
    }
  )
  browser <- valid_browser_token()
  url <- prepare_call(client, browser)
  claims[["nonce"]] <- parse_query_param(url, "nonce")
  response <- list(
    access_token = "example-access",
    refresh_token = "example-refresh",
    token_type = "Bearer",
    expires_in = 300,
    scope = "openid",
    id_token = jose::jwt_encode_sig(
      do.call(jose::jwt_claim, claims),
      fixture[["key"]]
    )
  )
  token <- handle_callback(
    client,
    code = "example-code",
    state = parse_query_param(url, "state"),
    browser_token = browser
  )
  expect_true(token@id_token_validated)
  expect_identical(token@id_token_claims[["sub"]], "example-user")
  expect_null(token@smart_context[["fhirUser"]])
  response[["id_token"]] <- NULL
  response[["access_token"]] <- "refreshed-access"
  refreshed <- refresh_token(client, token)
  expect_true(refreshed@id_token_validated)
  expect_identical(refreshed@id_token_claims[["sub"]], "example-user")
  expect_null(refreshed@smart_context[["fhirUser"]])
  expect_identical(refreshed@access_token, "refreshed-access")

  # Even a signed unsolicited FHIR reference is outside the selected mode.
  claims[["fhirUser"]] <- "not-a-fhir-reference"
  response[["id_token"]] <- jose::jwt_encode_sig(
    do.call(jose::jwt_claim, claims),
    fixture[["key"]]
  )
  refreshed <- refresh_token(client, refreshed)
  expect_null(refreshed@smart_context[["fhirUser"]])
  manager <- oauth_connections(list(hospital = client), "https://app.example")
  oauth_connections_ui(shiny::fluidPage("App"), "health", manager)
  shiny::testServer(
    oauth_connections_server,
    session = manager_test_session(),
    args = list(id = "health", manager = manager),
    {
      id <- manager_test_accept(controller, "hospital", refreshed)
      connection <- session[["returned"]][["connection"]](id)
      expect_identical(
        connection[["identity"]]()[["id_token_claims"]],
        list(iss = "https://ehr.example", sub = "example-user")
      )
      expect_null(smart_context(connection)[["fhirUser"]])
      expect_error(smart_fhir_user(connection), "No validated SMART fhirUser")
    }
  )
})

test_that("openid-only SMART keeps normal ID-token validation requirements", {
  fixture <- smart_identity_fixture()
  client <- smart_client(
    smart_client_fixture(oidc = TRUE),
    "example",
    "https://app.example/callback",
    scopes = character(),
    identity = "openid"
  )
  local_mocked_bindings(fetch_jwks = function(...) fixture[["jwks"]])
  for (invalid in c("missing", "nonce", "iss", "aud", "signature")) {
    claims <- fixture[["claims"]]
    claims[["fhirUser"]] <- NULL
    if (invalid %in% c("nonce", "iss", "aud")) {
      claims[[invalid]] <- "unexpected"
    }
    key <- if (invalid == "signature") {
      openssl::rsa_keygen(2048)
    } else {
      fixture[["key"]]
    }
    response <- list(
      access_token = "example-access",
      token_type = "Bearer",
      expires_in = 300,
      scope = "openid"
    )
    if (invalid != "missing") {
      response[["id_token"]] <- jose::jwt_encode_sig(
        do.call(jose::jwt_claim, claims),
        key
      )
    }
    expect_error(
      verify_token_set(client, response, nonce = "expected-nonce"),
      class = "shinyOAuth_error"
    )
  }
})
