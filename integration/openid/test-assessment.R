testthat::test_that("upstream completion counts every module independently of legacy coverage", {
  fixtures <- list(
    evidence_fixture("smoke"),
    evidence_fixture("basic"),
    configuration_fixture(),
    fapi_full_fixture("sync", "fapi-oauth-dpop"),
    fapi_full_fixture("sync", "fapi-oauth-dpop-reference"),
    mtls_evidence_fixture(),
    signing_report_fixture("sync")
  )
  for (i in seq_along(fixtures)) {
    f <- fixtures[[i]]
    check <- openid_check_report(f[["report"]], f[["context"]], f[["manifest"]])
    testthat::expect_true(check[["gate_passed"]], info = check[["reason"]])
    testthat::expect_identical(check[["upstream_plan_complete"]], i != 1L)
    counts <- check[["assessment"]][["module_counts"]]
    testthat::expect_identical(
      counts[["selected"]],
      length(f[["report"]][["results"]])
    )
    testthat::expect_identical(counts[["finished"]], counts[["selected"]])
    testthat::expect_identical(
      counts[["available"]],
      length(openid_plan_spec(f[["manifest"]], f[["context"]][["profile"]])[[
        "available_modules"
      ]])
    )
    assessment <- check[["assessment"]]
    testthat::expect_identical(assessment[["status"]], "validated")
    testthat::expect_identical(
      assessment[["certification_status"]],
      "not_assessed"
    )
    testthat::expect_identical(
      sum(unlist(assessment[["suite_verdict_counts"]])),
      counts[["finished"]]
    )
  }
})

testthat::test_that("local policy and state advisories retain exact raw verdicts and evidence", {
  basic <- evidence_fixture("basic")
  check <- openid_check_report(
    basic[["report"]],
    basic[["context"]],
    basic[["manifest"]]
  )
  assessment <- check[["assessment"]]
  testthat::expect_true(check[["coverage_complete"]])
  testthat::expect_identical(
    assessment[["suite_verdict_counts"]],
    list(PASSED = 13L, WARNING = 0L, SKIPPED = 1L)
  )
  testthat::expect_length(assessment[["accepted_non_passed_results"]], 1L)
  exception <- assessment[["accepted_non_passed_results"]][[1L]]
  testthat::expect_identical(
    exception[["module"]],
    "oidcc-client-test-idtoken-sig-none"
  )
  testthat::expect_identical(exception[["suite_result"]], "SKIPPED")
  testthat::expect_identical(exception[["policy"]], "reject_unsigned_id_token")

  f <- fapi_full_fixture("sync", "fapi-oauth-dpop")
  check <- openid_check_report(f[["report"]], f[["context"]], f[["manifest"]])
  assessment <- check[["assessment"]]
  testthat::expect_true(check[["upstream_plan_complete"]])
  testthat::expect_false(check[["coverage_complete"]])
  testthat::expect_identical(
    assessment[["suite_verdict_counts"]],
    list(PASSED = 8L, WARNING = 3L, SKIPPED = 0L)
  )
  testthat::expect_length(assessment[["accepted_non_passed_results"]], 3L)
  for (row in assessment[["accepted_non_passed_results"]]) {
    testthat::expect_identical(row[["suite_result"]], "WARNING")
    testthat::expect_identical(row[["policy"]], "state_length_over_128")
    testthat::expect_true(
      row[["suite_id"]] %in%
        vapply(
          f[["report"]][["results"]],
          function(result) result[["suite_id"]],
          character(1)
        )
    )
  }
  testthat::expect_identical(
    assessment[["limitations"]][["interoperability_advisories"]],
    list("oauth_state_length_over_128_warning")
  )
  testthat::expect_length(
    assessment[["limitations"]][["provider_limitations"]],
    0L
  )
  testthat::expect_contains(
    unlist(assessment[["limitations"]][["selection_scope"]]),
    "unsigned_authorization_server_metadata_only"
  )
  testthat::expect_identical(
    assessment[["limitations"]][["client_limitations"]],
    list("http_callback_rejection_retains_query")
  )
  for (verdict in c("PASSED", "REVIEW", "SKIPPED", "FAILED")) {
    changed <- f[["report"]]
    changed[["results"]][[1L]][["suite_result"]] <- verdict
    testthat::expect_false(openid_check_report(
      changed,
      f[["context"]],
      f[["manifest"]]
    )[["upstream_plan_complete"]])
  }
  changed <- f[["report"]]
  changed[["results"]][[1L]][["fapi"]][[
    "state_length_advisory_verified"
  ]] <- FALSE
  testthat::expect_false(openid_check_report(
    changed,
    f[["context"]],
    f[["manifest"]]
  )[["upstream_plan_complete"]])
})

testthat::test_that("provider limits remain separate from full upstream execution", {
  for (f in list(configuration_fixture(), mtls_evidence_fixture())) {
    check <- openid_check_report(f[["report"]], f[["context"]], f[["manifest"]])
    testthat::expect_true(check[["upstream_plan_complete"]])
    testthat::expect_false(check[["coverage_complete"]])
    limits <- check[["assessment"]][["limitations"]]
    testthat::expect_true(length(limits[["provider_limitations"]]) > 0L)
    testthat::expect_length(limits[["interoperability_advisories"]], 0L)
    testthat::expect_length(
      check[["assessment"]][["accepted_non_passed_results"]],
      if (identical(f[["context"]][["profile"]], "config")) 1L else 0L
    )
  }
  manifest <- openid_profiles("../..")
  limits <- lapply(manifest[["profiles"]], function(profile) {
    profile[["coverage_limitations"]]
  })
  testthat::expect_silent(openid_assessment_limitations(unlist(limits)))
  testthat::expect_error(
    openid_assessment_limitations("new_unreviewed_limit"),
    "Unclassified"
  )
  f <- evidence_fixture()
  f[["manifest"]][["profiles"]][["smoke"]][["coverage_limitations"]] <- list(
    "new_unreviewed_limit"
  )
  testthat::expect_false(openid_check_report(
    f[["report"]],
    f[["context"]],
    f[["manifest"]]
  )[["gate_passed"]])
})

testthat::test_that("assessment is recomputed and failure cannot preserve forged completion", {
  for (f in list(
    evidence_fixture("basic"),
    fapi_full_fixture("sync", "fapi-oauth-dpop")
  )) {
    original <- openid_check_report(
      f[["report"]],
      f[["context"]],
      f[["manifest"]]
    )
    changed <- f[["report"]]
    changed[["upstream_plan_complete"]] <- FALSE
    changed[["assessment"]] <- list(
      certification_status = "certified",
      module_counts = list(finished = 999L)
    )
    serialized <- jsonlite::fromJSON(
      jsonlite::toJSON(changed, auto_unbox = TRUE, null = "null"),
      simplifyVector = FALSE
    )
    testthat::expect_identical(
      openid_check_report(serialized, f[["context"]], f[["manifest"]]),
      original
    )
    changed[["upstream_plan_complete"]] <- TRUE
    changed[["results"]] <- changed[["results"]][-1L]
    failed <- openid_check_report(changed, f[["context"]], f[["manifest"]])
    testthat::expect_false(failed[["gate_passed"]])
    testthat::expect_false(failed[["selection_complete"]])
    testthat::expect_false(failed[["upstream_plan_complete"]])
    testthat::expect_identical(
      failed[["assessment"]],
      openid_failed_assessment()[["assessment"]]
    )
    changed <- f[["report"]]
    changed[["cleanup_verified"]] <- FALSE
    testthat::expect_false(openid_check_report(
      changed,
      f[["context"]],
      f[["manifest"]]
    )[["upstream_plan_complete"]])
  }
})

testthat::test_that("shared assessment sums validated selections without claiming full plans", {
  f <- shared_evidence_fixture()
  check <- openid_check_shared_report(
    f[["report"]],
    f[["context"]],
    f[["manifest"]]
  )
  testthat::expect_true(check[["gate_passed"]], info = check[["reason"]])
  testthat::expect_false(check[["upstream_plan_complete"]])
  assessment <- check[["assessment"]]
  testthat::expect_identical(assessment[["plan_count"]], 4L)
  testthat::expect_equal(assessment[["module_counts"]][["finished"]], 8L)
  testthat::expect_equal(assessment[["suite_verdict_counts"]][["PASSED"]], 8L)
  testthat::expect_length(assessment[["accepted_non_passed_results"]], 0L)
  testthat::expect_identical(
    assessment[["certification_status"]],
    "not_assessed"
  )
  testthat::expect_contains(
    unlist(assessment[["limitations"]][["provider_limitations"]]),
    "suite_public_variant_omits_none_in_discovery"
  )
  testthat::expect_contains(
    unlist(assessment[["limitations"]][["selection_scope"]]),
    "upstream_module_selection_only"
  )
  report <- f[["report"]]
  report[["assessment"]] <- list(certification_status = "certified")
  report[["selections"]][[1L]][["results"]] <- list()
  failed <- openid_check_shared_report(report, f[["context"]], f[["manifest"]])
  testthat::expect_false(failed[["gate_passed"]])
  testthat::expect_false(failed[["upstream_plan_complete"]])
  testthat::expect_identical(
    failed[["assessment"]],
    openid_failed_assessment()[["assessment"]]
  )
})
