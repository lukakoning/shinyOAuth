# Install this checkout first. No client authorization is performed by preflight.
run_inferno_preflight <- function() {
  for (package in c("shinyOAuth", "httr2", "openssl", "jsonlite", "processx", "withr", "httpuv")) {
    if (!requireNamespace(package, quietly = TRUE)) stop("Missing package: ", package)
  }
  root <- normalizePath(".", winslash = "/")
  output <- file.path(root, "integration/smart/.artifacts",
    paste0("inferno-preflight-", format(Sys.time(), "%Y%m%d-%H%M%S")))
  dir.create(output, recursive = TRUE)
  source("integration/smart/helper-inferno.R", local = TRUE)
  evidence <- list(status = "failed", application_flow = "not_attempted")
  on.exit(jsonlite::write_json(evidence, file.path(output, "evidence.json"),
    auto_unbox = TRUE, pretty = TRUE), add = TRUE)
  evidence$provenance <- inferno_build(root, output)
  evidence$simulator_regressions <- inferno_test_simulator(root, output)
  stack <- inferno_start(root, output)
  withr::local_envvar(CURL_CA_BUNDLE = stack$ca)
  discovery <- shinyOAuth::smart_discover(stack$fhir_base)
  stopifnot("sso-openid-connect" %in% discovery$metadata$capabilities)
  evidence$discovery_accepted <- TRUE
  evidence$transport <- "loopback HTTPS; R verifies the repository test CA"
  evidence$status <- "passed"
  cat("Inferno preflight passed; simulator modified; no app flow attempted.\n")
}
run_inferno_preflight()
