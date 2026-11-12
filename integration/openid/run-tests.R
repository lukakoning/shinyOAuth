run_openid_tests <- function(args = commandArgs(trailingOnly = TRUE)) {
  if (!identical(args, "--check-api")) {
    stop(
      "Usage: Rscript integration/openid/run-tests.R --check-api (browser profiles are not implemented yet)"
    )
  }
  Sys.setenv(CURL_SSL_BACKEND = "openssl")
  source("integration/openid/helper-environment.R", local = TRUE)
  source("integration/openid/helper-suite.R", local = TRUE)
  source("integration/openid/helper-evidence.R", local = TRUE)
  openid_require(c(
    "httr2",
    "jsonlite",
    "processx",
    "openssl",
    "withr",
    "httpuv",
    "testthat"
  ))
  output <- openid_output(".", "api")
  report <- list(
    schema_version = 1L,
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
