test_that("SMART extension URLs never become credential destinations", {
  local_options(shinyOAuth.allowed_hosts = NULL)
  metadata <- smart_client_fixture()[["metadata"]]
  metadata[[
    "revocation_endpoint_extension"
  ]] <- "https://unapproved.example/revoke"
  metadata[["issuerAlias"]] <- "https://unapproved.example"
  metadata[["jwks_uriAlias"]] <- "https://unapproved.example/keys"
  requests <- list()
  local_mocked_bindings(
    req_with_retry = function(req, ...) {
      requests[[length(requests) + 1L]] <<- req
      httr2::response(
        url = req[["url"]],
        status = 200L,
        headers = list("content-type" = "application/json"),
        body = charToRaw(jsonlite::toJSON(
          metadata,
          auto_unbox = TRUE,
          null = "null"
        ))
      )
    },
    .package = "shinyOAuth"
  )
  site <- smart_discover("https://ehr.example/fhir/R4")
  expect_identical(site[["metadata"]], metadata)
  expect_length(requests, 1L)
  client <- smart_client(
    site,
    "example",
    "https://app.example/callback",
    scopes = "user/Patient.r",
    token_auth_style = "header",
    client_secret = "example-client-secret"
  )
  expect_identical(client@provider@revocation_url, NA_character_)
  expect_identical(client@provider@issuer, NA_character_)
  expect_identical(client@provider@jwks_uri, NA_character_)
  token <- OAuthToken(
    access_token = "example-access",
    refresh_token = "example-refresh"
  )
  requests <- list()
  result <- revoke_token(client, token, token_kind = "refresh", async = FALSE)
  expect_identical(result[["status"]], "revocation_unsupported")
  expect_false(result[["supported"]])
  expect_length(requests, 0L)

  # An exact endpoint still has to pass the host policy, even with an extension.
  site[["metadata"]][[
    "revocation_endpoint"
  ]] <- "https://unapproved.example/revoke"
  expect_error(
    smart_client(
      site,
      "example",
      "https://app.example/callback",
      scopes = "user/Patient.r"
    ),
    "outside endpoint_hosts",
    class = "shinyOAuth_config_error"
  )
  site[["metadata"]][["revocation_endpoint"]] <- "https://ehr.example/revoke"
  client <- smart_client(
    site,
    "example",
    "https://app.example/callback",
    scopes = "user/Patient.r",
    token_auth_style = "header",
    client_secret = "example-client-secret"
  )
  requests <- list()
  expect_true(revoke_token(
    client,
    token,
    token_kind = "refresh",
    async = FALSE
  )[[
    "revoked"
  ]])
  expect_length(requests, 1L)
  expect_identical(requests[[1L]][["url"]], "https://ehr.example/revoke")
  expect_identical(
    as.character(requests[[1L]][["body"]][["data"]][["token"]]),
    "example-refresh"
  )
  authorization <- requests[[1L]][["headers"]][["Authorization"]]
  if (typeof(authorization) == "weakref") {
    authorization <- rlang::wref_value(authorization)
  }
  expect_identical(
    authorization,
    paste0(
      "Basic ",
      openssl::base64_encode(charToRaw("example:example-client-secret"))
    )
  )
})

test_that("SMART policy extensions do not enable protocol requirements", {
  for (field in c(
    "require_pushed_authorization_requests",
    "require_signed_request_object",
    "authorization_response_iss_parameter_supported"
  )) {
    site <- smart_client_fixture()
    site[["metadata"]][[paste0(field, "Alias")]] <- TRUE
    client <- smart_client(
      site,
      "example",
      "https://app.example/callback",
      scopes = "user/Patient.r"
    )
    expect_false(client@provider@authorization_response_iss_parameter_supported)
    site[["metadata"]][field] <- list(NULL)
    expect_no_error(smart_client(
      site,
      "example",
      "https://app.example/callback",
      scopes = "user/Patient.r"
    ))
    site[["metadata"]][[field]] <- TRUE
    if (field == "authorization_response_iss_parameter_supported") {
      exact <- smart_client(
        site,
        "example",
        "https://app.example/callback",
        scopes = "user/Patient.r"
      )
      expect_true(exact@provider@authorization_response_iss_parameter_supported)
    } else {
      expect_error(
        smart_client(
          site,
          "example",
          "https://app.example/callback",
          scopes = "user/Patient.r"
        ),
        "required PAR/JAR"
      )
    }
  }
})

test_that("SMART snapshots and required metadata require exact member names", {
  site <- smart_client_fixture(oidc = TRUE)
  for (field in c(
    "smart_version",
    "metadata",
    "allow_http_loopback",
    "fhir_base",
    "endpoint_hosts"
  )) {
    altered <- site
    names(altered)[names(altered) == field] <- paste0(field, "Alias")
    expect_error(
      smart_client(
        altered,
        "example",
        "https://app.example/callback",
        scopes = "user/Patient.r"
      ),
      class = if (field == "allow_http_loopback") {
        "shinyOAuth_input_error"
      } else {
        "shinyOAuth_config_error"
      }
    )
  }
  for (field in c(
    "authorization_endpoint",
    "token_endpoint",
    "issuer",
    "jwks_uri",
    "capabilities",
    "grant_types_supported",
    "code_challenge_methods_supported",
    "scopes_supported",
    "token_endpoint_auth_methods_supported",
    "token_endpoint_auth_signing_alg_values_supported"
  )) {
    altered <- site
    names(altered[["metadata"]])[
      names(altered[["metadata"]]) == field
    ] <- paste0(field, "Alias")
    expect_error(
      smart_client(
        altered,
        "example",
        "https://app.example/callback",
        scopes = "user/Patient.r",
        identity = "fhirUser"
      ),
      class = "shinyOAuth_parse_error"
    )
  }
})

test_that("SMART token checks require exact type and lifetime members", {
  client <- smart_client(
    smart_client_fixture(),
    "example",
    "https://app.example/callback",
    scopes = "user/Patient.r"
  )
  response <- list(
    access_token = "example-access",
    token_type = "Bearer",
    expires_in = 300,
    scope = "user/Patient.r"
  )
  for (refresh in c(FALSE, TRUE)) {
    for (field in c("token_type", "expires_in")) {
      altered <- response
      names(altered)[names(altered) == field] <- paste0(field, "Alias")
      expect_error(
        verify_token_set(
          client,
          altered,
          nonce = NULL,
          is_refresh = refresh,
          prior_granted_scopes = "user/Patient.r"
        ),
        field,
        class = "shinyOAuth_token_error"
      )
      altered[field] <- list(NULL)
      expect_error(
        verify_token_set(
          client,
          altered,
          nonce = NULL,
          is_refresh = refresh,
          prior_granted_scopes = "user/Patient.r"
        ),
        field,
        class = "shinyOAuth_token_error"
      )
    }
  }
})

test_that("callback lifetime policy cannot be supplied by a near-match extension", {
  local_mocked_bindings(
    req_with_retry = function(req, ...) {
      httr2::response(
        url = req[["url"]],
        status = 200L,
        headers = list("content-type" = "application/json"),
        body = charToRaw(jsonlite::toJSON(
          list(
            access_token = "example-access",
            token_type = "Bearer",
            expires_in_hint = 300,
            scope = "user/Patient.r"
          ),
          auto_unbox = TRUE
        ))
      )
    },
    .package = "shinyOAuth"
  )
  for (lifetime in list(NULL, 90)) {
    client <- smart_client(
      smart_client_fixture(),
      "example",
      "https://app.example/callback",
      scopes = "user/Patient.r",
      initial_expires_in_fallback = lifetime
    )
    browser <- valid_browser_token()
    state <- parse_query_param(
      prepare_call(client, browser_token = browser),
      "state"
    )
    callback <- function() {
      handle_callback(
        client,
        code = "example-code",
        state = state,
        browser_token = browser
      )
    }
    if (is.null(lifetime)) {
      expect_error(callback(), "expires_in", class = "shinyOAuth_token_error")
    } else {
      before <- as.numeric(Sys.time())
      token <- callback()
      expect_gte(token@expires_at, before + 85)
      expect_lte(token@expires_at, as.numeric(Sys.time()) + 90)
      expect_identical(token@extra_fields[["expires_in_hint"]], 300L)
    }
  }
})

test_that("a signed near-match fhirUser claim fails the complete callback", {
  fixture <- smart_identity_fixture()
  client <- fixture[["client"]]
  browser <- valid_browser_token()
  url <- prepare_call(client, browser_token = browser)
  claims <- fixture[["claims"]]
  claims[["nonce"]] <- parse_query_param(url, "nonce")
  names(claims)[names(claims) == "fhirUser"] <- "fhirUser_hint"
  signed <- jose::jwt_encode_sig(
    do.call(jose::jwt_claim, claims),
    fixture[["key"]]
  )
  fetched <- FALSE
  local_mocked_bindings(
    fetch_jwks = function(...) {
      fetched <<- TRUE
      fixture[["jwks"]]
    },
    req_with_retry = function(req, ...) {
      httr2::response(
        url = req[["url"]],
        status = 200L,
        headers = list("content-type" = "application/json"),
        body = charToRaw(jsonlite::toJSON(
          list(
            access_token = "example-access",
            token_type = "Bearer",
            expires_in = 300,
            scope = "openid fhirUser",
            id_token = signed
          ),
          auto_unbox = TRUE
        ))
      )
    },
    .package = "shinyOAuth"
  )
  expect_error(
    handle_callback(
      client,
      code = "example-code",
      state = parse_query_param(url, "state"),
      browser_token = browser
    ),
    "fhirUser",
    class = "shinyOAuth_id_token_error"
  )
  expect_true(fetched)
})

test_that("a signed fhirUser extension cannot establish or refresh SMART identity", {
  record <- smart_identity_fixture()
  local_mocked_bindings(
    fetch_jwks = function(...) record[["jwks"]],
    .package = "shinyOAuth"
  )
  claims <- record[["claims"]]
  names(claims)[names(claims) == "fhirUser"] <- "fhirUserAlias"
  signed <- function() {
    jose::jwt_encode_sig(do.call(jose::jwt_claim, claims), record[["key"]])
  }
  response <- function() {
    list(
      access_token = "rotated-access",
      refresh_token = "rotated-refresh",
      token_type = "Bearer",
      expires_in = 300,
      scope = "openid fhirUser",
      id_token = signed()
    )
  }
  expect_error(
    verify_token_set(record[["client"]], response(), nonce = "expected-nonce"),
    "fhirUser",
    class = "shinyOAuth_id_token_error"
  )
  unverified <- response()
  unverified[[".id_token_validatedAlias"]] <- TRUE
  expect_error(
    smart_verify_identity(record[["client"]], unverified, is_refresh = FALSE),
    "validated ID token",
    class = "shinyOAuth_id_token_error"
  )

  # Exercise context extraction independently of the first acceptance check.
  token <- record[["token"]]
  token@id_token <- signed()
  token@id_token_validated <- TRUE
  expect_error(
    smart_update_token_context(record[["client"]], token),
    "requires fhirUser",
    class = "shinyOAuth_token_error"
  )
  expect_error(
    smart_update_token_context(record[["client"]], token, record[["token"]]),
    "requires fhirUser",
    class = "shinyOAuth_token_error"
  )

  claims[["nonce"]] <- NULL
  local_mocked_bindings(
    req_with_retry = function(req, ...) {
      httr2::response(
        url = req[["url"]],
        status = 200L,
        headers = list("content-type" = "application/json"),
        body = charToRaw(jsonlite::toJSON(
          response(),
          auto_unbox = TRUE,
          null = "null"
        ))
      )
    },
    .package = "shinyOAuth"
  )
  expect_error(
    refresh_token(record[["client"]], record[["token"]]),
    "fhirUser",
    class = "shinyOAuth_id_token_error"
  )
  expect_identical(record[["token"]]@refresh_token, "example-refresh")
  expect_identical(
    record[["token"]]@smart_context[["fhirUser"]],
    "Practitioner/example"
  )

  # A valid exact claim wins; explicit null never falls back to the extension.
  claims[["fhirUser"]] <- "Practitioner/example"
  claims[["fhirUserAlias"]] <- "Practitioner/someone-else"
  accepted <- refresh_token(record[["client"]], record[["token"]])
  expect_identical(accepted@smart_context[["fhirUser"]], "Practitioner/example")
  expect_identical(
    accepted@id_token_claims[["fhirUserAlias"]],
    "Practitioner/someone-else"
  )
  # jose::jwt_claim drops R NULLs; NA is encoded as an explicit JSON null.
  claims[["fhirUser"]] <- NA_character_
  null_claims <- parse_jwt_payload(signed())
  expect_true("fhirUser" %in% names(null_claims))
  expect_null(null_claims[["fhirUser"]])
  expect_error(
    refresh_token(record[["client"]], accepted),
    "fhirUser",
    class = "shinyOAuth_id_token_error"
  )
})

test_that("SMART ID token extensions do not replace an omitted refresh ID token", {
  record <- smart_identity_fixture()
  local_mocked_bindings(
    req_with_retry = function(req, ...) {
      httr2::response(
        url = req[["url"]],
        status = 200L,
        headers = list("content-type" = "application/json"),
        body = charToRaw(jsonlite::toJSON(
          list(
            access_token = "rotated-access",
            token_type = "Bearer",
            expires_in = 300,
            scope = "openid fhirUser",
            id_tokenAlias = "uninterpreted-extension"
          ),
          auto_unbox = TRUE
        ))
      )
    },
    .package = "shinyOAuth"
  )
  accepted <- refresh_token(record[["client"]], record[["token"]])
  expect_identical(accepted@smart_context, record[["token"]]@smart_context)
  expect_identical(accepted@id_token, record[["token"]]@id_token)
  expect_identical(
    accepted@extra_fields[["id_tokenAlias"]],
    "uninterpreted-extension"
  )
})

test_that("SMART context and launch parameters do not accept similarly named extensions", {
  client <- smart_client(
    smart_client_fixture(),
    "example",
    "https://app.example/callback",
    scopes = c("launch/patient", "patient/Patient.r")
  )
  token <- OAuthToken(
    access_token = "example-access",
    token_type = "Bearer",
    granted_scopes = "patient/Patient.r",
    granted_scopes_verified = TRUE,
    extra_fields = list(
      patientAlias = "example-patient",
      encounterAlias = "example-encounter",
      need_patient_bannerAlias = TRUE
    )
  )
  expect_error(
    smart_update_token_context(client, token),
    "require patient context"
  )
  token@extra_fields[["patient"]] <- "exact-patient"
  context <- smart_update_token_context(client, token)@smart_context
  expect_identical(context[["patient"]], "exact-patient")
  expect_null(context[["encounter"]])
  expect_null(context[["need_patient_banner"]])
  for (query in c(
    "issAlias=https://ehr.example/fhir/R4&launch=example",
    "iss=https://ehr.example/fhir/R4&launchAlias=example"
  )) {
    expect_error(smart_launch_query(query), "exact scalar parameters")
  }
})
