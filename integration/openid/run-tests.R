run_openid_tests <- function(args = commandArgs(trailingOnly = TRUE)) {
  api_mode <- identical(args, "--check-api")
  if (!api_mode) {
    valid <- length(args) == 4L &&
      !anyDuplicated(args[c(1L, 3L)]) &&
      setequal(args[c(1L, 3L)], c("--profile", "--transport"))
    if (!valid) {
      stop(
        "Usage: Rscript integration/openid/run-tests.R --check-api | --profile smoke|basic|config|form-post|refresh --transport sync"
      )
    }
    options <- setNames(args[c(2L, 4L)], args[c(1L, 3L)])
    if (
      !options[["--profile"]] %in%
        c("smoke", "basic", "config", "form-post", "refresh") ||
        !identical(options[["--transport"]], "sync")
    ) {
      stop(
        "Only smoke, basic, config, form-post and refresh profiles with sync transport are implemented"
      )
    }
  }
  Sys.setenv(CURL_SSL_BACKEND = "openssl")
  source("integration/openid/helper-environment.R", local = TRUE)
  source("integration/openid/helper-suite.R", local = TRUE)
  source("integration/openid/helper-evidence.R", local = TRUE)
  source("integration/openid/helper-app.R", local = TRUE)
  source("integration/openid/helper-driver.R", local = TRUE)
  openid_require(c(
    "httr2",
    "jsonlite",
    "processx",
    "openssl",
    "withr",
    "httpuv",
    "testthat"
  ))
  profile <- if (api_mode) "api" else options[["--profile"]]
  output <- openid_output(".", profile)
  report <- list(
    schema_version = 2L,
    status = "failed",
    application_flow = "not_attempted",
    gate_passed = FALSE,
    coverage_complete = FALSE
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
  checks <- testthat::test_file(
    "integration/openid/test-evidence.R",
    env = environment(),
    reporter = "summary",
    stop_on_failure = TRUE,
    stop_on_warning = TRUE
  )
  if (any(as.data.frame(checks)[["skipped"]])) {
    stop("OpenID evidence checks require zero skips")
  }
  manifest <- openid_profiles()
  if (!api_mode) {
    openid_require(c("shiny", "callr", "chromote"))
    report <- openid_report_context(
      ".",
      profile,
      "sync",
      read.dcf("DESCRIPTION")[[1L, "Version"]]
    )
    context <- report
    library <- openid_install(".", output)
    stack <- openid_start(".", output)
    transport <- openid_app_transport(".", stack, httpuv::randomPort())
    context[["provider_origin"]] <- report[["provider_origin"]] <- stack[[
      "origin"
    ]]
    context[["app_origin"]] <- report[["app_origin"]] <- transport[["origin"]]
    report[["driver_failure_control_passed"]] <- openid_driver_failure_control(
      ".",
      stack,
      manifest,
      context,
      transport,
      library
    )
    if (identical(profile, "config")) {
      report[["jwks_cache_policy"]] <- openid_suite_cache_policy(
        stack,
        manifest,
        paste0(transport[["origin"]], "/")
      )
    }
    plan <- openid_suite_plan(
      stack,
      manifest,
      paste0(transport[["origin"]], "/"),
      profile
    )
    context[["plan_id"]] <- plan[["id"]]
    report[["plan_id"]] <- plan[["id"]]
    report[["images"]] <- stack[["lock"]][["images"]]
    started <- Sys.time()
    for (expectation in manifest[["profiles"]][[profile]][["modules"]]) {
      report[["results"]][[
        length(report[["results"]]) + 1L
      ]] <- openid_run_case(
        ".",
        stack,
        plan,
        expectation,
        context,
        transport,
        library
      )
    }
    report[["module_runtime_seconds"]] <- round(
      as.numeric(difftime(Sys.time(), started, units = "secs")),
      2
    )
    openid_stop_app(transport)
    openid_stop(stack)
    report[["cleanup_verified"]] <- TRUE
    check <- openid_check_report(report, context, manifest)
    report[names(check)] <- check
    if (!isTRUE(check[["gate_passed"]])) {
      stop("OpenID ", profile, " gate failed: ", check[["reason"]])
    }
    report[["status"]] <- "passed"
    cat(
      "OpenID ",
      profile,
      " selection passed; coverage_complete = ",
      check[["coverage_complete"]],
      ".\n",
      sep = ""
    )
    return(invisible(report))
  }
  stack <- openid_start(".", output)
  plan <- openid_suite_plan(stack, manifest, "https://localhost:58100/")
  module <- openid_suite_module(stack, plan, "oidcc-client-test")
  stopifnot(identical(openid_suite_info(stack, module)[["status"]], "WAITING"))
  unknown <- module
  unknown[["id"]] <- "UnknownOpenIDInstance"
  failure <- tryCatch(openid_suite_info(stack, unknown), error = identity)
  stopifnot(
    inherits(failure, "openid_http_error"),
    identical(failure[["status"]], 404L)
  )
  openid_suite_cancel(stack, module)
  stopifnot(identical(
    openid_suite_info(stack, module)[["status"]],
    "INTERRUPTED"
  ))
  openid_stop(stack)
  report[["source_revision"]] <- manifest[["source_revision"]]
  report[["api_checks"]] <- list(
    plan_created = TRUE,
    module_waiting = TRUE,
    exported_issuer_checked = TRUE,
    unknown_instance_rejected = TRUE,
    cancellation_verified = TRUE
  )
  report[["cleanup_verified"]] <- TRUE
  report[["status"]] <- "passed"
  cat(
    "OpenID API and evidence checks passed; client conformance not attempted.\n"
  )
}
run_openid_tests()
