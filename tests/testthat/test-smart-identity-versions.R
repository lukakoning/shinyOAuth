test_that("signed refreshes update resource versions without changing logical identity", {
  for (references in list(
    c("Practitioner/example/_history/2", "Practitioner/example/_history/3"),
    c(
      "Practitioner/example/_history/2",
      "https://ehr.example/fhir/R4/Practitioner/example/_history/3"
    ),
    c("Practitioner/example", "Practitioner/example/_history/3"),
    c("Practitioner/example/_history/2", "Practitioner/example")
  )) {
    record <- smart_identity_fixture(references[[1L]])
    claims <- record[["claims"]]
    claims[["nonce"]] <- NULL
    claims[["fhirUser"]] <- references[[2L]]
    local_mocked_bindings(
      fetch_jwks = function(...) record[["jwks"]],
      req_with_retry = function(req, ...) {
        httr2::response(
          url = req[["url"]],
          status = 200L,
          headers = list("content-type" = "application/json"),
          body = charToRaw(jsonlite::toJSON(
            list(
              access_token = "next-access",
              refresh_token = "next-refresh",
              token_type = "Bearer",
              expires_in = 300,
              scope = "openid fhirUser",
              id_token = jose::jwt_encode_sig(
                do.call(jose::jwt_claim, claims),
                record[["key"]]
              )
            ),
            auto_unbox = TRUE
          ))
        )
      },
      .package = "shinyOAuth"
    )
    refreshed <- refresh_token(record[["client"]], record[["token"]])
    expect_identical(refreshed@smart_context[["fhirUser"]], references[[2L]])
    expect_identical(refreshed@smart_context[["revision"]], 2L)
    expect_true(refreshed@smart_context[["changed"]])
    expect_identical(refreshed@refresh_token, "next-refresh")
    for (bad in c(
      "Practitioner/other/_history/3",
      "Patient/example/_history/3",
      "https://other.example/fhir/R4/Practitioner/example/_history/3"
    )) {
      claims[["fhirUser"]] <- bad
      expect_error(
        refresh_token(record[["client"]], refreshed),
        "fhirUser changed"
      )
    }
  }
})

test_that("arbitrary identity URL suffixes are not interpreted as FHIR versions", {
  expect_identical(
    smart_identity_logical_reference(
      "https://ehr.example/identity/example/_history/3"
    ),
    "https://ehr.example/identity/example/_history/3"
  )
  expect_identical(
    smart_identity_logical_reference(
      "https://ehr.example/Practitioner/example/_history/3?view=one"
    ),
    "https://ehr.example/Practitioner/example/_history/3?view=one"
  )
  expect_identical(
    smart_identity_logical_reference(
      "https://ehr.example/identity?path=/Practitioner/example/_history/3"
    ),
    "https://ehr.example/identity?path=/Practitioner/example/_history/3"
  )
})
