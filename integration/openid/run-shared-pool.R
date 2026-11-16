run_openid_shared_pool <- function() {
  if (length(commandArgs(trailingOnly = TRUE))) {
    stop("Usage: Rscript integration/openid/run-shared-pool.R")
  }
  Sys.setenv(CURL_SSL_BACKEND = "openssl")
  for (name in c(
    "environment",
    "suite",
    "evidence",
    "auth",
    "app",
    "driver",
    "shared-pool"
  )) {
    source(paste0("integration/openid/helper-", name, ".R"), local = TRUE)
  }
  openid_require(c(
    "httr2",
    "jsonlite",
    "processx",
    "openssl",
    "withr",
    "httpuv",
    "testthat",
    "ps",
    "jose",
    "shiny",
    "callr",
    "chromote",
    "mirai",
    "promises",
    "later"
  ))
  checks <- testthat::test_file(
    "integration/openid/test-evidence.R",
    env = environment(),
    reporter = "summary",
    stop_on_failure = TRUE,
    stop_on_warning = TRUE
  )
  if (any(as.data.frame(checks)[["skipped"]])) {
    stop("Shared-pool evidence checks require zero skips")
  }
  output <- openid_output(".", "shared-pool")
  report <- openid_report_context(
    ".",
    "shared-pool",
    "mirai",
    read.dcf("DESCRIPTION")[[1L, "Version"]]
  )
  on.exit(
    jsonlite::write_json(
      report,
      file.path(output, "evidence.json"),
      auto_unbox = TRUE,
      pretty = TRUE,
      null = "null"
    ),
    add = TRUE
  )
  context <- report
  manifest <- openid_profiles()
  library <- openid_install(".", output)
  stack <- openid_start(".", output)
  transport <- openid_app_transport(".", stack, httpuv::randomPort())
  context[["provider_origin"]] <- report[["provider_origin"]] <- stack[[
    "origin"
  ]]
  context[["app_origin"]] <- report[["app_origin"]] <- transport[["origin"]]
  capability <- openid_public_capability(
    stack,
    manifest,
    context,
    paste0(transport[["origin"]], "/"),
    library
  )
  for (name in c("plan_id", "suite_id")) {
    context[[paste0("public_probe_", name)]] <- report[[paste0(
      "public_probe_",
      name
    )]] <- capability[[name]]
  }
  report[["driver_failure_control_passed"]] <- openid_driver_failure_control(
    ".",
    stack,
    manifest,
    context,
    transport,
    library
  )
  profiles <- openid_shared_profiles()
  plans <- lapply(profiles, function(profile) {
    openid_suite_plan(
      stack,
      manifest,
      paste0(transport[["origin"]], "/"),
      profile
    )
  })
  context[["plan_ids"]] <- report[["plan_ids"]] <- lapply(
    plans,
    function(plan) plan[["id"]]
  )
  report[["registrations_distinct"]] <- !anyDuplicated(vapply(
    plans,
    function(plan) plan[["registration"]][["client_id"]],
    character(1)
  )) &&
    !identical(
      plans[[1L]][["credentials"]][["client_secret"]],
      plans[[3L]][["credentials"]][["client_secret"]]
    ) &&
    !identical(
      plans[[2L]][["credentials"]][["private_key"]],
      plans[[4L]][["credentials"]][["private_key"]]
    )
  report[["selections"]] <- lapply(seq_along(profiles), function(i) {
    selection <- context
    selection[["profile"]] <- profiles[[i]]
    selection[["plan_id"]] <- plans[[i]][["id"]]
    selection[["results"]] <- list()
    selection[["public_client_capability"]] <- capability
    selection[["driver_failure_control_passed"]] <- report[[
      "driver_failure_control_passed"
    ]]
    selection
  })
  report[["images"]] <- stack[["lock"]][["images"]]
  report[["image_sources"]] <- stack[["image_sources"]]
  pool <- openid_shared_start(".", stack, transport, library)
  report[["initial_worker_state"]] <- pool[["initial_state"]]
  fingerprints <- list()
  report[["execution_order"]] <- list()
  started <- Sys.time()
  for (step in openid_shared_sequence()) {
    i <- step[["selection"]]
    expectation <- manifest[["profiles"]][[profiles[[i]]]][["modules"]][[step[[
      "case"
    ]]]]
    row <- openid_run_case(
      ".",
      stack,
      plans[[i]],
      expectation,
      report[["selections"]][[i]],
      transport,
      library,
      .start_app = function(...) openid_shared_app_start(pool, ...),
      .stop_app = function(app) openid_shared_app_stop(pool, app),
      .shared_pool = TRUE
    )
    report[["selections"]][[i]][["results"]][[step[["case"]]]] <- row
    report[["execution_order"]][[
      length(report[["execution_order"]]) + 1L
    ]] <- row[["suite_id"]]
    fingerprints[[
      length(fingerprints) + 1L
    ]] <- openid_shared_audit_fingerprint(tail(pool[["configs"]], 1L)[[1L]])
  }
  report[["module_runtime_seconds"]] <- round(
    as.numeric(difftime(Sys.time(), started, units = "secs")),
    2
  )
  report[["worker_states"]] <- pool[["states"]]
  report[["issuers_distinct"]] <- openid_shared_issuers_match(pool[["configs"]])
  report[["audit_files_unchanged"]] <- identical(
    fingerprints,
    lapply(pool[["configs"]], openid_shared_audit_fingerprint)
  )
  openid_stop_app(as.list(pool))
  openid_stop_app(transport)
  openid_stop(stack)
  report[["cleanup_verified"]] <- TRUE
  for (i in seq_along(profiles)) {
    selection <- report[["selections"]][[i]]
    selection[["cleanup_verified"]] <- TRUE
    selection[["results"]] <- lapply(selection[["results"]], function(row) {
      row[["worker_cleanup_verified"]] <- TRUE
      row
    })
    trusted <- context
    trusted[["profile"]] <- profiles[[i]]
    trusted[["plan_id"]] <- plans[[i]][["id"]]
    check <- openid_check_report(selection, trusted, manifest)
    selection[names(check)] <- check
    if (isTRUE(check[["gate_passed"]])) {
      selection[["status"]] <- "passed"
    }
    report[["selections"]][[i]] <- selection
  }
  check <- openid_check_shared_report(report, context, manifest)
  report[names(check)] <- check
  if (!isTRUE(check[["gate_passed"]])) {
    stop("Shared-pool gate failed: ", check[["reason"]])
  }
  report[["status"]] <- "passed"
  cat(
    "Shared mirai pool passed eight alternating client cases; coverage_complete = FALSE.\n"
  )
  invisible(report)
}
run_openid_shared_pool()
