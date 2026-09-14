testthat::test_that("Inferno evidence requires every applicable upstream test exactly once", {
  for (style in c("public", "header", "private_key_jwt")) {
    expected <- inferno_expected_tests(style)
    results <- lapply(expected, function(id) list(test_id = id, result = "pass"))
    testthat::expect_true(inferno_verification_summary(results, expected)$passed)
    testthat::expect_false(inferno_verification_summary(list(), expected)$passed)
    testthat::expect_false(inferno_verification_summary(results[-1L], expected)$passed)
    testthat::expect_false(inferno_verification_summary(c(results, results[1L]), expected)$passed)
    duplicate <- results
    duplicate[[1L]] <- duplicate[[2L]]
    testthat::expect_false(inferno_verification_summary(duplicate, expected)$passed)
    unrelated <- results
    unrelated[[1L]]$test_id <- "different_test"
    testthat::expect_false(inferno_verification_summary(unrelated, expected)$passed)
    for (status in c("skip", "omit", "wait", "fail", "error", "running")) {
      unfinished <- results
      unfinished[[1L]]$result <- status
      testthat::expect_false(inferno_verification_summary(unfinished, expected)$passed)
    }
    # A passing aggregate cannot mask a failed leaf.
    testthat::expect_false(inferno_verification_summary(c(unfinished,
      list(list(test_suite_id = inferno_suite, result = "pass"))), expected)$passed)
  }
})

testthat::test_that("successful token use before refresh cannot mask stale or missing use afterwards", {
  base <- "https://inferno.example/custom/smart_client_stu2_2"
  stack <- list(fhir_base = paste0(base, "/fhir"))
  registration <- list(patient = "patient-b", practitioner = "practitioner-b", style = "public")
  request <- function(index, path, verb = "GET", body = "", token = NULL, response = "") {
    list(index = index, url = paste0(base, path), verb = verb, status = 200L,
      request_body = body, response_body = response,
      request_headers = if (is.null(token)) list() else list(list(name = "Authorization", value = paste("Bearer", token))))
  }
  response <- function(token) jsonlite::toJSON(list(access_token = token, scope = "patient/Patient.rs"), auto_unbox = TRUE)
  history <- list(
    request(1, paste0("/auth/authorization?aud=", utils::URLencode(stack$fhir_base, reserved = TRUE), "&code_challenge_method=S256")),
    request(2, "/auth/token", "POST", "grant_type=authorization_code", response = response("synthetic-initial")),
    request(3, "/fhir/Patient/patient-b", token = "synthetic-initial"),
    request(4, "/fhir/Practitioner/practitioner-b", token = "synthetic-initial"),
    request(5, "/fhir/Patient", token = "synthetic-initial"),
    request(6, "/auth/token", "POST", "grant_type=refresh_token", response = response("synthetic-refreshed")),
    request(7, "/fhir/Patient/patient-b", token = "synthetic-refreshed"),
    request(8, "/fhir/Practitioner/practitioner-b", token = "synthetic-refreshed"),
    request(9, "/fhir/Patient", token = "synthetic-refreshed"))
  check <- function(value) inferno_exchange_summary(stack, NULL, registration, "standalone", requests = value)
  testthat::expect_true(check(history)$every_issued_token_used_for_patient_and_user)
  testthat::expect_error(check(history[-6L]))
  testthat::expect_error(check(history[-7L]))
  stale <- history
  stale[[7L]]$request_headers[[1L]]$value <- "Bearer synthetic-initial"
  testthat::expect_error(check(stale))
  wrong_patient <- history
  wrong_patient[[7L]]$url <- paste0(base, "/fhir/Patient/patient-a")
  testthat::expect_error(check(wrong_patient))
})
