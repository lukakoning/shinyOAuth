fapi_full_fixture <- function(backend = "sync") {
  f <- evidence_fixture("fapi-dpop-full")
  expected <- f[["manifest"]][["profiles"]][["fapi-dpop-full"]][["modules"]]
  for (i in seq_along(expected)) {
    e <- expected[[i]]
    row <- f[["report"]][["results"]][[i]]
    app <- row[["app"]]
    if (identical(e[["action"]], "discovery")) {
      row[["action"]] <- "discovery"
      row[["no_callback"]] <- TRUE
      row[["callback_cleaned"]] <- NULL
      app[["ready"]] <- app[["discovery_issuer_exact"]] <- FALSE
      app[["error_code"]] <- "discovery_setup_error"
      app[["error_classes"]] <- list("shinyOAuth_config_error")
      app[["claims"]] <- list("iss")
      app[["reasons"]] <- list("discovery_issuer_mismatch")
      app[["operations"]][] <- 0L
    } else if (identical(e[["outcome"]], "callback_rejected")) {
      row[["callback_cleaned"]] <- FALSE
      row[["callback_http"]] <- list(
        status = 400L,
        state_present = e[["state_present"]],
        issuer_present = e[["issuer_present"]],
        no_store = TRUE,
        no_referrer = TRUE,
        plain_text = TRUE,
        credentials_absent = TRUE,
        body_matches = TRUE,
        browser_status_400 = TRUE,
        headers_verified = TRUE,
        no_callback_module = TRUE
      )
      app[["error_code"]] <- e[["error_code"]]
      app[["error_classes"]] <- list("shinyOAuth_state_error")
      app[["callback_rejections"]] <- list(e[["callback_label"]])
      app[["claims"]] <- app[["reasons"]] <- list()
      app[["operations"]][] <- 0L
    } else if (!is.null(e[["claims_any"]])) {
      app[["claims"]] <- e[["claims_any"]][1L]
    }
    if (identical(e[["outcome"]], "authenticated")) {
      app[["resource"]] <- list(
        done = TRUE,
        succeeded = TRUE,
        response_marker_valid = TRUE,
        pid = 100L,
        transport = "main_process",
        api = e[["resource_api"]],
        expiry_unknown = FALSE,
        connection_unusable = FALSE
      )
    }
    row[["app"]] <- app
    row[["initial"]] <- NULL
    logs <- fapi_logs_fixture(row[["module"]], row[["suite_id"]], e)
    row[["fapi"]] <- openid_fapi_evidence(
      logs[["logs"]],
      logs[["module"]],
      logs[["plan"]],
      e
    )
    f[["report"]][["results"]][[i]] <- row
  }
  evidence_with_transport(f, backend)
}

testthat::test_that("full FAPI OIDC selection requires every pinned module in both transports", {
  for (backend in c("sync", "mirai")) {
    f <- fapi_full_fixture(backend)
    check <- openid_check_report(f[["report"]], f[["context"]], f[["manifest"]])
    testthat::expect_true(check[["gate_passed"]])
    testthat::expect_true(check[["coverage_complete"]])
    testthat::expect_length(f[["report"]][["results"]], 23L)
    for (i in seq_len(23L)) {
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

testthat::test_that("pre-token suite results require stage-specific no-exchange evidence", {
  f <- fapi_full_fixture()
  expected <- f[["manifest"]][["profiles"]][["fapi-dpop-full"]][["modules"]]
  indices <- which(vapply(
    expected,
    function(e) {
      e[["outcome"]] %in% c("discovery_rejected", "callback_rejected")
    },
    logical(1)
  ))
  for (i in indices) {
    proof <- f[["report"]][["results"]][[i]][["fapi"]]
    for (name in names(proof)) {
      report <- f[["report"]]
      report[["results"]][[i]][["fapi"]][[name]] <- NULL
      testthat::expect_false(openid_check_report(
        report,
        f[["context"]],
        f[["manifest"]]
      )[["gate_passed"]])
    }
    for (name in c(
      "token_request_count",
      "userinfo_request_count",
      "resource_request_count"
    )) {
      report <- f[["report"]]
      report[["results"]][[i]][["fapi"]][[name]] <- 1L
      testthat::expect_false(openid_check_report(
        report,
        f[["context"]],
        f[["manifest"]]
      )[["gate_passed"]])
    }
    if (identical(expected[[i]][["outcome"]], "callback_rejected")) {
      for (name in names(f[["report"]][["results"]][[i]][["callback_http"]])) {
        report <- f[["report"]]
        report[["results"]][[i]][["callback_http"]][[name]] <- NULL
        testthat::expect_false(openid_check_report(
          report,
          f[["context"]],
          f[["manifest"]]
        )[["gate_passed"]])
      }
      report <- f[["report"]]
      report[["results"]][[i]][["app"]][["callback_rejections"]] <- list(
        "wrong"
      )
      testthat::expect_false(openid_check_report(
        report,
        f[["context"]],
        f[["manifest"]]
      )[["gate_passed"]])
    }
  }
})

testthat::test_that("discovery mutation evidence requires its exact upstream event", {
  f <- fapi_full_fixture()
  e <- f[["manifest"]][["profiles"]][["fapi-dpop-full"]][["modules"]][[2L]]
  row <- f[["report"]][["results"]][[2L]]
  logs <- fapi_logs_fixture(row[["module"]], row[["suite_id"]], e)
  source <- openid_fapi_pre_token_checks(TRUE)
  i <- which(vapply(
    logs[["logs"]],
    function(event) {
      identical(event[["src"]], source)
    },
    logical(1)
  ))
  testthat::expect_length(i, 1L)
  for (level in c("INFO", "SUCCESS", "FAILURE", "WARNING")) {
    events <- logs[["logs"]]
    events[[i]][["result"]] <- level
    row[["fapi"]] <- openid_fapi_evidence(
      events,
      logs[["module"]],
      logs[["plan"]],
      e
    )
    testthat::expect_false(openid_fapi_matches(row, e))
  }
  for (field in c("msg", "issuer", "src")) {
    events <- logs[["logs"]]
    events[[i]][[field]] <- "wrong"
    row[["fapi"]] <- openid_fapi_evidence(
      events,
      logs[["module"]],
      logs[["plan"]],
      e
    )
    testthat::expect_false(openid_fapi_matches(row, e))
  }
})

testthat::test_that("omitted expiry requires a usable connection with the fallback lifetime", {
  f <- fapi_full_fixture()
  i <- which(vapply(
    f[["report"]][["results"]],
    function(row) endsWith(row[["module"]], "without-expires_in"),
    logical(1)
  ))
  for (field in c("api", "expiry_unknown", "connection_unusable")) {
    report <- f[["report"]]
    report[["results"]][[i]][["app"]][["resource"]][[field]] <- NULL
    testthat::expect_false(openid_check_report(
      report,
      f[["context"]],
      f[["manifest"]]
    )[["gate_passed"]])
  }
})
