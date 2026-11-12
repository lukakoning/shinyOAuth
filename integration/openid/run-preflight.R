run_openid_preflight <- function(args = commandArgs(trailingOnly = TRUE)) {
  if (length(args)) {
    stop("Usage: Rscript integration/openid/run-preflight.R")
  }
  Sys.setenv(CURL_SSL_BACKEND = "openssl")
  source("integration/openid/helper-environment.R", local = TRUE)
  openid_require(c(
    "httr2",
    "jsonlite",
    "processx",
    "openssl",
    "withr",
    "chromote",
    "httpuv",
    "testthat"
  ))
  output <- openid_output(".", "preflight")
  evidence <- list(
    schema_version = 1L,
    status = "failed",
    application_flow = "not_attempted"
  )
  # A pass is set only after the explicit cleanup has succeeded.
  on.exit(
    jsonlite::write_json(
      evidence,
      file.path(output, "evidence.json"),
      auto_unbox = TRUE,
      pretty = TRUE
    ),
    add = TRUE
  )
  checks <- testthat::test_file(
    "integration/openid/test-environment.R",
    env = environment(),
    reporter = "summary",
    stop_on_failure = TRUE,
    stop_on_warning = TRUE
  )
  if (any(as.data.frame(checks)[["skipped"]])) {
    stop("OpenID environment checks require zero skips")
  }
  evidence[["environment_checks"]] <- "passed"
  stack <- openid_start(".", output)
  evidence[["source_revision"]] <- stack[["provenance"]][["revision"]]
  evidence[["image_provenance"]] <- stack[["provenance"]]
  evidence[["images"]] <- stack[["lock"]][["images"]]
  evidence[["server_info"]] <- stack[["server_info"]][c(
    "revision",
    "version",
    "tag"
  )]
  plans <- openid_api(stack, "/api/plan/available")
  openid_plan_ids(plans, stack[["lock"]][["required_plans"]])
  evidence[["required_plans_present"]] <- TRUE
  evidence[[
    "r_tls"
  ]] <- "certificate chain and hostname verified against temporary trust anchor"
  evidence[["browser_tls"]] <- openid_browser_tls(stack)
  evidence[["coverage_complete"]] <- FALSE
  # Cleanup is explicit on success; the deferred cleanup remains an idempotent fallback.
  openid_stop(stack)
  evidence[["cleanup_verified"]] <- TRUE
  evidence[["status"]] <- "passed"
  cat("OpenID preflight passed; no client conformance flow attempted.\n")
  invisible(evidence)
}
run_openid_preflight()
