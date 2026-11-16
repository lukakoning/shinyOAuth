shared_evidence_fixture <- function() {
  manifest <- openid_profiles("../..")
  report <- list(
    schema_version = 3L,
    run_id = "run",
    attempt_id = "attempt",
    checkout_revision = "checkout",
    source_revision = manifest[["source_revision"]],
    package_version = "version",
    profile = "shared-pool",
    transport = "mirai",
    plan_ids = as.list(paste0("plan-", 1:4)),
    selections = list(),
    registrations_distinct = TRUE,
    issuers_distinct = TRUE,
    audit_files_unchanged = TRUE,
    driver_failure_control_passed = TRUE,
    cleanup_verified = TRUE
  )
  for (i in seq_along(openid_shared_profiles())) {
    f <- evidence_with_transport(
      auth_evidence_fixture(openid_shared_profiles()[[i]]),
      "mirai"
    )
    f[["report"]][["plan_id"]] <- report[["plan_ids"]][[i]]
    f[["report"]][["results"]] <- lapply(
      seq_along(f[["report"]][["results"]]),
      function(j) {
        row <- f[["report"]][["results"]][[j]]
        row[["plan_id"]] <- report[["plan_ids"]][[i]]
        row[["suite_id"]] <- paste0("instance-", i, "-", j)
        row[["client_auth"]][["suite_id"]] <- row[["suite_id"]]
        row[["app"]][["run_id"]] <- paste0(
          f[["context"]][["run_id"]],
          "-",
          row[["suite_id"]]
        )
        for (name in c("app_instance", "cache_instance")) {
          row[["initial"]][[name]] <- row[["app"]][[name]] <- paste0(
            name,
            "-",
            i,
            "-",
            j
          )
        }
        row
      }
    )
    report[["selections"]][[i]] <- f[["report"]]
  }
  # Use the existing realistic auth fixture's run and worker metadata.
  reference <- f[["context"]]
  for (name in c(
    "run_id",
    "attempt_id",
    "checkout_revision",
    "source_revision",
    "package_version",
    "public_probe_plan_id",
    "public_probe_suite_id"
  )) {
    report[[name]] <- reference[[name]]
  }
  rows <- lapply(openid_shared_sequence(), function(step) {
    report[["selections"]][[step[["selection"]]]][["results"]][[step[["case"]]]]
  })
  report[["execution_order"]] <- lapply(rows, function(row) row[["suite_id"]])
  probes <- rows[[1L]][["app"]][["transport"]][["probes"]]
  state <- lapply(probes, function(probe) {
    list(
      pid = probe[["pid"]],
      options_clean = TRUE,
      session_clean = TRUE,
      worker_context_clean = TRUE
    )
  })
  report[["initial_worker_state"]] <- state
  report[["worker_states"]] <- rep(
    list(list(before = state, after = state)),
    8L
  )
  list(report = report, context = report, manifest = manifest)
}

testthat::test_that("shared issuers remain stable within a plan and distinct across plans", {
  configs <- lapply(c("a", "b", "a", "b", "c", "d", "c", "d"), function(id) {
    list(issuer = paste0("https://issuer/", id))
  })
  testthat::expect_true(openid_shared_issuers_match(configs))
  testthat::expect_false(openid_shared_issuers_match(configs[-1L]))
  configs[[3L]][["issuer"]] <- "https://issuer/foreign"
  testthat::expect_false(openid_shared_issuers_match(configs))
  configs <- rep(configs[1L], 8L)
  testthat::expect_false(openid_shared_issuers_match(configs))
})

testthat::test_that("a shared pool requires alternating credential generations and real client proof", {
  f <- shared_evidence_fixture()
  testthat::expect_true(openid_check_shared_report(
    f[["report"]],
    f[["context"]],
    f[["manifest"]]
  )[["gate_passed"]])
  for (name in c(
    "run_id",
    "attempt_id",
    "checkout_revision",
    "source_revision",
    "package_version",
    "profile",
    "transport",
    "plan_ids",
    "execution_order",
    "initial_worker_state",
    "worker_states",
    "registrations_distinct",
    "issuers_distinct",
    "audit_files_unchanged",
    "driver_failure_control_passed",
    "cleanup_verified"
  )) {
    report <- f[["report"]]
    report[[name]] <- NULL
    testthat::expect_false(openid_check_shared_report(
      report,
      f[["context"]],
      f[["manifest"]]
    )[["gate_passed"]])
  }
  for (i in 1:4) {
    report <- f[["report"]]
    report[["selections"]][[i]][["results"]][[1L]][["client_auth"]][[
      "client_id_matches"
    ]] <- FALSE
    testthat::expect_false(openid_check_shared_report(
      report,
      f[["context"]],
      f[["manifest"]]
    )[["gate_passed"]])
  }
})

testthat::test_that("shared-pool proof rejects replacement workers and stale scope", {
  f <- shared_evidence_fixture()
  for (i in 1:8) {
    for (phase in c("before", "after")) {
      for (field in c(
        "pid",
        "options_clean",
        "session_clean",
        "worker_context_clean"
      )) {
        report <- f[["report"]]
        report[["worker_states"]][[i]][[phase]][[1L]][[field]] <- if (
          field == "pid"
        ) {
          99999L
        } else {
          FALSE
        }
        testthat::expect_false(openid_check_shared_report(
          report,
          f[["context"]],
          f[["manifest"]]
        )[["gate_passed"]])
      }
    }
  }
  report <- f[["report"]]
  report[["selections"]][[2L]][["results"]][[1L]][["app"]][["transport"]][[
    "app_pid"
  ]] <- 99999L
  testthat::expect_false(openid_check_shared_report(
    report,
    f[["context"]],
    f[["manifest"]]
  )[["gate_passed"]])
})

testthat::test_that("audit proof detects wrong per-case worker options without exporting them", {
  source("fixture-transport.R", local = TRUE)
  directory <- withr::local_tempdir()
  package <- normalizePath(
    getNamespaceInfo(asNamespace("testthat"), "path"),
    winslash = "/"
  )
  withr::local_envvar(CURL_CA_BUNDLE = "private-ca")
  withr::local_options(list(shinyOAuth.timeout = 23L))
  hook <- openid_fixture_hook(
    directory,
    "run",
    package,
    "private-ca",
    package_name = "testthat",
    expected_timeout = 17L
  )
  hook(list(type = "audit_token_exchange", client_secret = "DO_NOT_EXPORT"))
  record <- jsonlite::read_json(list.files(directory, full.names = TRUE)[[1L]])
  testthat::expect_false(record[["options_match"]])
  testthat::expect_false(grepl(
    "DO_NOT_EXPORT",
    jsonlite::toJSON(record, auto_unbox = TRUE),
    fixed = TRUE
  ))
  testthat::expect_false(openid_fixture_audit(
    directory,
    "run",
    as.character(utils::packageVersion("testthat")),
    list()
  )[["transport"]][["events_verified"]])
})
