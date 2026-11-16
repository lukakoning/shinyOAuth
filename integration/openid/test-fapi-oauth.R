testthat::test_that("compact OAuth state requires all eleven PASSED outcomes and actual reference proof", {
  for (backend in c("sync", "mirai")) {
    f <- fapi_full_fixture(backend, "fapi-oauth-dpop-reference")
    check <- function(report) {
      openid_check_report(report, f[["context"]], f[["manifest"]])
    }
    valid <- check(f[["report"]])
    testthat::expect_true(valid[["gate_passed"]], info = valid[["reason"]])
    testthat::expect_true(valid[["coverage_complete"]])
    testthat::expect_length(f[["report"]][["results"]], 11L)
    for (i in seq_len(11L)) {
      report <- f[["report"]]
      report[["results"]] <- report[["results"]][-i]
      testthat::expect_false(check(report)[["gate_passed"]])
      for (verdict in c("WARNING", "FAILED", "SKIPPED", "REVIEW")) {
        report <- f[["report"]]
        report[["results"]][[i]][["suite_result"]] <- verdict
        testthat::expect_false(check(report)[["gate_passed"]])
      }
      if (identical(f[["report"]][["results"]][[i]][["action"]], "discovery")) {
        next
      }
      for (mode in list(NULL, "encrypted")) {
        report <- f[["report"]]
        report[["results"]][[i]][["app"]][["state_transport"]] <- mode
        testthat::expect_false(check(report)[["gate_passed"]])
      }
      for (value in list(NULL, FALSE)) {
        report <- f[["report"]]
        report[["results"]][[i]][["fapi"]][["state_reference_valid"]] <- value
        testthat::expect_false(check(report)[["gate_passed"]])
      }
      for (size in list(NULL, 0L, 21L, 129L)) {
        report <- f[["report"]]
        report[["results"]][[i]][["fapi"]][["state_characters"]] <- size
        testthat::expect_false(check(report)[["gate_passed"]])
      }
    }
  }
})

testthat::test_that("compact-state evidence measures all actual PAR attempts without exporting state", {
  f <- fapi_logs_fixture(
    "fapi2-security-profile-final-client-test-happy-path",
    oauth_only = TRUE
  )
  proof <- openid_fapi_reference_evidence(f[["logs"]], f[["module"]])
  testthat::expect_identical(
    proof,
    list(state_characters = 64L, state_reference_valid = TRUE)
  )
  indices <- which(vapply(
    f[["logs"]],
    function(event) endsWith(event[["incoming_path"]] %||% "", "/par"),
    logical(1)
  ))
  for (value in list(
    NULL,
    "short",
    strrep("s", 129L),
    strrep("!", 64L)
  )) {
    logs <- f[["logs"]]
    logs[[indices[[1L]]]][["incoming_body_form_params"]][["state"]] <- value
    testthat::expect_false(openid_fapi_reference_evidence(logs, f[["module"]])[[
      "state_reference_valid"
    ]])
  }
  logs <- c(f[["logs"]], list(f[["logs"]][[indices[[1L]]]]))
  logs[[length(logs)]][["incoming_body_form_params"]][["state"]] <- strrep(
    "t",
    64L
  )
  testthat::expect_false(openid_fapi_reference_evidence(logs, f[["module"]])[[
    "state_reference_valid"
  ]])
  testthat::expect_false(openid_fapi_reference_evidence(list(), f[["module"]])[[
    "state_reference_valid"
  ]])
})

testthat::test_that("OAuth-only FAPI requires every resolved module in both transports", {
  for (backend in c("sync", "mirai")) {
    f <- fapi_full_fixture(backend, "fapi-oauth-dpop")
    check <- openid_check_report(f[["report"]], f[["context"]], f[["manifest"]])
    testthat::expect_true(check[["gate_passed"]], info = check[["reason"]])
    testthat::expect_false(check[["coverage_complete"]])
    testthat::expect_length(f[["report"]][["results"]], 11L)
    for (i in seq_len(11L)) {
      report <- f[["report"]]
      report[["results"]] <- report[["results"]][-i]
      testthat::expect_false(openid_check_report(
        report,
        f[["context"]],
        f[["manifest"]]
      )[["gate_passed"]])
    }
  }
})

testthat::test_that("OAuth-only token use earns no ID-token or UserInfo credit", {
  for (backend in c("sync", "mirai")) {
    f <- fapi_full_fixture(backend, "fapi-oauth-dpop")
    rejected <- function(report) {
      !isTRUE(openid_check_report(report, f[["context"]], f[["manifest"]])[[
        "gate_passed"
      ]])
    }
    for (name in c(
      "id_token_present",
      "id_token_validated",
      "userinfo_present"
    )) {
      for (value in list(NULL, TRUE)) {
        report <- f[["report"]]
        report[["results"]][[1L]][["app"]][[name]] <- value
        testthat::expect_true(rejected(report))
      }
    }
    for (name in c("oauth_scope_valid", "token_response_oauth_only")) {
      report <- f[["report"]]
      report[["results"]][[1L]][["fapi"]][[name]] <- NULL
      testthat::expect_true(rejected(report))
    }
    report <- f[["report"]]
    report[["results"]][[1L]][["app"]][["oauth_only_configured"]] <- FALSE
    testthat::expect_true(rejected(report))
    for (where in c("operations", "transport")) {
      report <- f[["report"]]
      if (identical(where, "operations")) {
        report[["results"]][[1L]][["app"]][[where]][["audit_userinfo"]] <- 1L
      } else {
        report[["results"]][[1L]][["fapi"]][["userinfo_request_count"]] <- 1L
      }
      testthat::expect_true(rejected(report))
    }
    manifest <- f[["manifest"]]
    manifest[["profiles"]][["fapi-oauth-dpop"]][["modules"]][[1L]][[
      "outcome"
    ]] <- "authenticated"
    testthat::expect_false(openid_check_report(
      f[["report"]],
      f[["context"]],
      manifest
    )[["gate_passed"]])
  }
})

testthat::test_that("state-length advisories stay specific and cannot establish complete coverage", {
  f <- fapi_full_fixture(profile = "fapi-oauth-dpop")
  manifest <- f[["manifest"]]
  manifest[["profiles"]][["fapi-oauth-dpop"]][["complete_profile"]] <- TRUE
  manifest[["profiles"]][["fapi-oauth-dpop"]][[
    "coverage_limitations"
  ]] <- list()
  check <- openid_check_report(f[["report"]], f[["context"]], manifest)
  testthat::expect_true(check[["gate_passed"]])
  testthat::expect_false(check[["coverage_complete"]])
  testthat::expect_contains(
    unlist(check[["coverage_limitations"]]),
    "oauth_state_length_over_128_warning"
  )
  for (verdict in c("PASSED", "FAILED", "SKIPPED", "REVIEW")) {
    report <- f[["report"]]
    report[["results"]][[1L]][["suite_result"]] <- verdict
    testthat::expect_false(openid_check_report(
      report,
      f[["context"]],
      f[["manifest"]]
    )[["gate_passed"]])
  }
  row <- f[["report"]][["results"]][[1L]]
  e <- f[["manifest"]][["profiles"]][["fapi-oauth-dpop"]][["modules"]][[1L]]
  data <- fapi_logs_fixture(
    row[["module"]],
    row[["suite_id"]],
    e,
    oauth_only = TRUE
  )
  warning_index <- which(vapply(
    data[["logs"]],
    function(event) identical(event[["src"]], "CheckStateLength"),
    logical(1)
  ))
  for (mutation in c(
    "missing",
    "extra",
    "message",
    "source",
    "severity",
    "short_state"
  )) {
    events <- data[["logs"]]
    if (mutation == "missing") {
      events <- events[-warning_index]
    }
    if (mutation == "extra") {
      events <- c(events, events[warning_index])
    }
    if (mutation %in% c("message", "source", "severity")) {
      events[[warning_index]][[switch(
        mutation,
        message = "msg",
        source = "src",
        severity = "result"
      )]] <- "wrong"
    }
    if (mutation == "short_state") {
      events[[1L]][["incoming_body_form_params"]][["state"]] <- "short"
    }
    row[["fapi"]] <- openid_fapi_evidence(
      events,
      data[["module"]],
      data[["plan"]],
      e
    )
    testthat::expect_false(openid_fapi_matches(row, e), info = mutation)
  }
  for (field in c("state_characters", "state_length_advisory_verified")) {
    report <- f[["report"]]
    report[["results"]][[1L]][["fapi"]][[field]] <- NULL
    testthat::expect_false(openid_check_report(
      report,
      f[["context"]],
      f[["manifest"]]
    )[["gate_passed"]])
  }
  report <- f[["report"]]
  report[["results"]][[7L]][["suite_result"]] <- "WARNING"
  testthat::expect_false(openid_check_report(
    report,
    f[["context"]],
    f[["manifest"]]
  )[["gate_passed"]])
})

testthat::test_that("OAuth-only request and token-response checks inspect actual log fields", {
  f <- fapi_full_fixture(profile = "fapi-oauth-dpop")
  expected <- f[["manifest"]][["profiles"]][["fapi-oauth-dpop"]][["modules"]]
  for (i in c(1L, 3L, 10L)) {
    row <- f[["report"]][["results"]][[i]]
    data <- fapi_logs_fixture(
      row[["module"]],
      row[["suite_id"]],
      expected[[i]],
      oauth_only = TRUE
    )
    for (mutation in c(
      "openid_scope",
      "oidc_nonce",
      "id_token",
      "missing_response",
      "unexpected_dpop_nonce"
    )) {
      if (i == 3L && !mutation %in% c("openid_scope", "oidc_nonce")) {
        next
      }
      if (mutation == "unexpected_dpop_nonce" && i != 10L) {
        next
      }
      events <- data[["logs"]]
      if (mutation %in% c("openid_scope", "oidc_nonce")) {
        par_index <- which(vapply(
          events,
          function(event) {
            identical(event[["incoming_path"]], "/test/a/fapi/par")
          },
          logical(1)
        ))[[1L]]
        events[[par_index]][["incoming_body_form_params"]][[
          if (mutation == "openid_scope") "scope" else "nonce"
        ]] <- "openid"
      } else if (mutation %in% c("id_token", "missing_response")) {
        n <- which(vapply(
          events,
          function(event) {
            identical(event[["src"]], "CreateTokenEndpointResponse")
          },
          logical(1)
        ))
        if (mutation == "missing_response") {
          events <- events[-n]
        } else {
          events[[n]][["Created token endpoint response"]][[
            "id_token"
          ]] <- "DO_NOT_EXPORT_ID_TOKEN"
        }
      } else {
        n <- which(vapply(
          events,
          function(event) !is.null(event[["incoming_headers"]][["dpop"]]),
          logical(1)
        ))[[1L]]
        jwt <- openid_fapi_decode(events[[n]][["incoming_headers"]][["dpop"]])
        jwt[[2L]][["nonce"]] <- "DO_NOT_EXPORT_UNEXPECTED_NONCE"
        events[[n]][["incoming_headers"]][["dpop"]] <- data[["jwt"]](
          jwt[[1L]],
          jwt[[2L]]
        )
      }
      row[["fapi"]] <- openid_fapi_evidence(
        events,
        data[["module"]],
        data[["plan"]],
        expected[[i]]
      )
      testthat::expect_false(
        openid_fapi_matches(row, expected[[i]]),
        info = paste(i, mutation)
      )
    }
  }
})
