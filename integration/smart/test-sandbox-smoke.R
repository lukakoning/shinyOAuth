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
    c("launch-standalone", "launch-ehr", "context-standalone-patient") %in%
      unlist(smart$capabilities)
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
    "/config/r4-local.json5"
  )))
  testthat::expect_match(config, urls$raw_fhir, fixed = TRUE)
  env <- httr2::resp_body_string(smart_sandbox_get(paste0(
    urls$launcher,
    "/env.js"
  )))
  testthat::expect_match(env, urls$picker, fixed = TRUE)
  testthat::expect_match(env, "r4-local", fixed = TRUE)
})
