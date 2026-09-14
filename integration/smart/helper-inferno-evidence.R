# Shared evidence contract for the standalone driver and combined coverage gate.
inferno_suite <- "smart_client_stu2_2"

inferno_matrix <- function() expand.grid(profile = c("public", "basic", "rs384", "es384"),
  launch = c("standalone", "ehr"), async = c(FALSE, TRUE),
  authorization_method = c("GET", "POST"), stringsAsFactors = FALSE)

inferno_expected_tests <- function(style) {
  profile <- switch(style, public = "alp", header = "alcs", private_key_jwt = "alca")
  stopifnot(length(profile) == 1L)
  paste0(inferno_suite, "-", c(
    paste0("smart_client_registration_", profile, "-smart_client_registration_", profile, "_verification"),
    paste0("smart_client_access-smart_client_access_", profile, "_interaction"),
    paste0("smart_client_access-smart_client_authorization_request_", profile, "_verification"),
    paste0("smart_client_access-smart_client_token_request_", profile, "_verification"),
    "smart_client_access-smart_client_token_use_verification"))
}

inferno_verification_summary <- function(results, expected_tests) {
  tests <- Filter(function(result) !is.null(result$test_id), results)
  ids <- vapply(tests, function(result) result$test_id, character(1))
  summary <- lapply(tests, function(result) list(test_id = result$test_id, status = result$result))
  list(passed = length(ids) == length(expected_tests) && !anyDuplicated(ids) &&
    setequal(ids, expected_tests) && all(vapply(tests,
      function(result) identical(result$result, "pass"), logical(1))), tests = summary)
}

inferno_report_passed <- function(report) {
  tryCatch({
    stopifnot(identical(report$status, "passed"), isTRUE(report$complete_matrix),
      identical(report$suite_id, inferno_suite), identical(report$simulator_regressions, "passed"),
      isTRUE(report$simulator_modified), isTRUE(report$provenance$simulator_modified),
      isTRUE(report$provenance$upstream_verification_unchanged),
      identical(report$unmodified_external_interoperability, "not_established"))
    expected <- inferno_matrix()
    key <- function(row) paste(row$profile, row$launch, row$async, row$authorization_method, sep = "/")
    expected_keys <- vapply(seq_len(nrow(expected)), function(index) key(expected[index, ]), character(1))
    actual_keys <- vapply(report$scenarios, key, character(1))
    stopifnot(length(actual_keys) == length(expected_keys), !anyDuplicated(actual_keys),
      setequal(actual_keys, expected_keys))
    for (row in report$scenarios) {
      stopifnot(identical(row$status, "passed"), identical(row$app_flow, "passed"),
        identical(row$response_mode, "query"), length(row$inferno) == 2L,
        setequal(names(row$inferno), c("a", "b")))
      flags <- c("patient_read", "validated_fhir_user", "refresh_and_read", "two_sites_retained",
        "browser_owner_isolation", "narrowing_retained", "independent_refresh_and_disconnect", "logout")
      stopifnot(all(vapply(row[flags], isTRUE, logical(1))))
      style <- switch(row$profile, public = "public", basic = "header", "private_key_jwt")
      for (site in c("a", "b")) {
        value <- row$inferno[[site]]
        tests <- lapply(value$tests, function(test) list(test_id = test$test_id, result = test$status))
        stopifnot(isTRUE(value$passed), inferno_verification_summary(tests, inferno_expected_tests(style))$passed,
          isTRUE(value$driver_exchange_checks$every_issued_token_used_for_patient_and_user))
      }
      stopifnot(isTRUE(row$inferno$a$driver_exchange_checks$explicit_narrowing_preserved),
        isTRUE(row$inferno$b$driver_exchange_checks$untouched_grant_kept_search))
    }
    TRUE
  }, error = function(...) FALSE)
}
