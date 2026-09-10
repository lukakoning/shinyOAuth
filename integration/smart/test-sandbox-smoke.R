# These tests establish the external sandbox, not the unimplemented SMART APIs.
testthat::test_that("the sandbox serves local R4 metadata and synthetic patients", {
  urls <- smart_sandbox_urls()
  metadata <- smart_sandbox_json(paste0(urls$raw_fhir, "/metadata"))
  testthat::expect_identical(metadata$resourceType, "CapabilityStatement")
  testthat::expect_identical(metadata$fhirVersion, "4.0.1")
  patients <- smart_sandbox_json(paste0(urls$raw_fhir, "/Patient?_count=1"))
  testthat::expect_identical(patients$resourceType, "Bundle")
  testthat::expect_gte(length(patients$entry), 1L)
  patient <- patients$entry[[1]]$resource
  testthat::expect_identical(patient$resourceType, "Patient")
  testthat::expect_true(is.character(patient$id) && nzchar(patient$id))
})

testthat::test_that("SMART metadata and its FHIR proxy resolve to the local stack", {
  urls <- smart_sandbox_urls()
  smart <- smart_sandbox_json(paste0(
    urls$fhir,
    "/.well-known/smart-configuration"
  ))
  testthat::expect_identical(
    smart$authorization_endpoint,
    paste0(urls$launcher, "/v/r4/auth/authorize")
  )
  testthat::expect_identical(
    smart$token_endpoint,
    paste0(urls$launcher, "/v/r4/auth/token")
  )
  testthat::expect_true(all(
    c(
      "launch-standalone",
      "launch-ehr",
      "context-standalone-patient",
      "sso-openid-connect",
      "client-confidential-asymmetric",
      "permission-v2"
    ) %in%
      unlist(smart$capabilities)
  ))
  # SMART 2.2 requires these fields; the older launcher omitted both.
  testthat::expect_true(
    "authorization_code" %in% unlist(smart$grant_types_supported)
  )
  testthat::expect_identical(
    smart$code_challenge_methods_supported,
    list("S256")
  )
  testthat::expect_true(
    "private_key_jwt" %in% unlist(smart$token_endpoint_auth_methods_supported)
  )
  # SSO advertisement makes issuer and jwks_uri mandatory. This checks
  # discovery/key availability, not an ID-token or client-assertion exchange.
  testthat::expect_identical(smart$issuer, urls$fhir)
  testthat::expect_identical(smart$jwks_uri, paste0(urls$launcher, "/keys"))
  keys <- smart_sandbox_json(smart$jwks_uri)$keys
  testthat::expect_gte(length(keys), 1L)
  testthat::expect_true(all(vapply(
    keys,
    function(key) {
      identical(key$kty, "RSA") && nzchar(key$n) && nzchar(key$e)
    },
    logical(1)
  )))
  testthat::expect_false(any(
    c("d", "p", "q", "dp", "dq", "qi", "oth") %in%
      unlist(lapply(keys, names))
  ))
  metadata <- smart_sandbox_json(paste0(urls$fhir, "/metadata"))
  testthat::expect_identical(metadata$resourceType, "CapabilityStatement")
  testthat::expect_identical(metadata$fhirVersion, "4.0.1")
  # The launcher simulates authorization. This uncredentialed read checks only
  # proxy connectivity and must never be reported as token enforcement evidence.
  patients <- smart_sandbox_json(paste0(urls$fhir, "/Patient?_count=1"))
  testthat::expect_identical(patients$resourceType, "Bundle")
  testthat::expect_identical(
    patients$entry[[1]]$resource$resourceType,
    "Patient"
  )
})

testthat::test_that("the launcher and patient picker use the local R4 dataset", {
  urls <- smart_sandbox_urls()
  testthat::expect_identical(
    httr2::resp_status(smart_sandbox_get(urls$launcher)),
    200L
  )
  testthat::expect_identical(
    httr2::resp_status(smart_sandbox_get(urls$picker)),
    200L
  )
  config <- httr2::resp_body_string(smart_sandbox_get(paste0(
    urls$picker,
    "/config/r4.json5"
  )))
  testthat::expect_match(config, urls$raw_fhir, fixed = TRUE)
  env <- smart_sandbox_environment()
  testthat::expect_identical(env$PICKER_ORIGIN, urls$picker)
  testthat::expect_identical(env$FHIR_SERVER_R4, urls$raw_fhir)
  testthat::expect_identical(env$FHIR_SERVER_R2, "")
  testthat::expect_identical(env$FHIR_SERVER_R3, "")
})
