test_that("SMART property edits retain transport and discovery host policy", {
  client <- smart_client(
    smart_client_fixture(),
    "example",
    "https://app.example/callback",
    scopes = "user/Patient.r",
    required_scopes = character()
  )
  expect_error(
    client@redirect_uri <- "http://localhost/callback",
    "requires HTTPS"
  )
  expect_error(
    client@provider@token_url <- "http://localhost/token",
    "requires HTTPS"
  )
  for (field in c(
    "auth_url",
    "token_url",
    "revocation_url",
    "introspection_url",
    "userinfo_url"
  )) {
    provider <- client@provider
    S7::prop(provider, field) <- "https://outside.example/endpoint"
    expect_error(client@provider <- provider, "outside endpoint_hosts")
  }
  expect_no_error({
    client@provider@token_url <- "https://ehr.example/another-token"
  })
  expect_no_error({
    client@redirect_uri <- "https://another-app.example/callback"
  })
  site <- smart_client_fixture()
  site[["allow_http_loopback"]] <- TRUE
  site[["endpoint_hosts"]] <- c("ehr.example", "localhost")
  dev <- smart_client(
    site,
    "example",
    "http://localhost/callback",
    scopes = "user/Patient.r"
  )
  expect_no_error({
    dev@provider@token_url <- "http://localhost/token"
  })
})

test_that("SMART scope edits retain app launch and advertised capabilities", {
  site <- smart_client_fixture()
  client <- smart_client(
    site,
    "example",
    "https://app.example/callback",
    scopes = "user/Patient.r",
    required_scopes = character(),
    allow_v1_scopes = TRUE
  )
  for (scope in c(
    "system/Patient.r",
    "patient/Patient.r",
    "launch",
    "openid",
    "fhirUser",
    "offline_access",
    "launch/encounter"
  )) {
    expect_error(client@scopes <- scope, "SMART|Standalone|capability|Identity")
  }
  expect_no_error({
    client@scopes <- c("launch/patient", "patient/Patient.r")
  })
  ehr <- smart_client(
    site,
    "example",
    "https://app.example/callback",
    scopes = "user/Patient.r",
    required_scopes = character(),
    launch = "ehr"
  )
  expect_error(ehr@scopes <- "user/Patient.r", "require launch scope")
  expect_no_error({
    ehr@scopes <- c("launch", "user/Observation.r")
  })
  site[["metadata"]][["capabilities"]] <- as.list(setdiff(
    unlist(site[["metadata"]][["capabilities"]]),
    "permission-v1"
  ))
  v2 <- smart_client(
    site,
    "example",
    "https://app.example/callback",
    scopes = "user/Patient.r",
    required_scopes = character(),
    allow_v1_scopes = TRUE
  )
  expect_error(v2@scopes <- "user/Patient.read", "permission-v1")
})

test_that("SMART authentication edits retain capability and method advertisements", {
  site <- smart_client_fixture()
  site[["metadata"]][["capabilities"]] <- as.list(setdiff(
    unlist(site[["metadata"]][["capabilities"]]),
    "client-confidential-symmetric"
  ))
  client <- smart_client(
    site,
    "example",
    "https://app.example/callback",
    scopes = "user/Patient.r"
  )
  provider <- client@provider
  provider@token_auth_style <- "header"
  expect_error(
    S7::props(client) <- list(
      provider = provider,
      client_secret = "example-secret"
    ),
    "client-confidential-symmetric"
  )
  tampered <- client@smart
  tampered[["discovery"]][["endpoint_hosts"]] <- c(
    "ehr.example",
    "outside.example"
  )
  expect_error(client@smart <- tampered, "reviewed snapshot")
})

test_that("SMART operations revalidate configuration restored without S7 setters", {
  client <- smart_client(
    smart_client_fixture(),
    "example",
    "https://app.example/callback",
    scopes = "user/Patient.r",
    required_scopes = character()
  )
  invalid <- client
  attr(invalid, "scopes") <- "system/Patient.r"
  expect_identical(invalid@scopes, "system/Patient.r")
  expect_error(prepare_call(invalid, valid_browser_token()), "backend system")
  provider <- client@provider
  attr(provider, "token_url") <- "http://localhost/token"
  attr(client, "provider") <- provider
  local_mocked_bindings(
    req_with_retry = function(...) stop("Unexpected transport"),
    .package = "shinyOAuth"
  )
  expect_error(
    swap_code_for_token_set(client, "example-code", strrep("v", 64)),
    "requires HTTPS"
  )
})

test_that("SMART rejects claims through property edits and restored configuration", {
  claims <- list(id_token = list(auth_time = list(essential = TRUE)))
  for (supported in list(FALSE, TRUE, NULL)) {
    site <- smart_client_fixture(oidc = TRUE)
    site[["metadata"]][["claims_parameter_supported"]] <- supported
    client <- smart_client(
      site,
      "example",
      "https://app.example/callback",
      scopes = "user/Patient.r",
      identity = "openid"
    )
    for (value in list(
      claims,
      as.character(jsonlite::toJSON(claims, auto_unbox = TRUE))
    )) {
      expect_error(
        client@claims <- value,
        "SMART claims requests are not supported"
      )
      restored <- client
      attr(restored, "claims") <- value
      expect_error(
        prepare_call(restored, valid_browser_token()),
        "SMART claims requests are not supported"
      )
      expect_error(
        prepare_authorization_request(restored, valid_browser_token()),
        "SMART claims requests are not supported"
      )

      ordinary <- make_test_client(scopes = "openid")
      expect_no_error({
        ordinary@claims <- value
      })
      prepared <- prepare_call(ordinary, valid_browser_token())
      fields <- decode_form_pairs(url_raw_query(prepared), "test")
      expect_identical(
        jsonlite::fromJSON(fields[["claims"]], simplifyVector = FALSE),
        claims
      )
    }
  }
})
