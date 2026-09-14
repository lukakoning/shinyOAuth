# Run from the repository root with the current package installed.
run_smart_ehr_browser_tests <- function() {
  packages <- c("shinyOAuth", "shiny", "webfakes", "httpuv", "chromote", "callr",
    "testthat", "httr2", "jsonlite", "curl", "withr", "mirai", "promises")
  for (package in packages) {
    if (!requireNamespace(package, quietly = TRUE)) stop("Missing package: ", package)
  }
  retention_root <- normalizePath(".", winslash = "/")
  quick <- "--sync-query" %in% commandArgs(trailingOnly = TRUE)
  async_modes <- if (quick) FALSE else c(FALSE, TRUE)
  response_modes <- if (quick) "query" else c("query", "form_post")
  retention_evidence_env <- new.env(parent = emptyenv())
  source("integration/connections/helper-browser.R", local = TRUE)
  source("integration/smart/fixture-ehr-provider.R", local = TRUE)
  output <- file.path("integration/smart/.artifacts", paste0("ehr-", format(Sys.time(), "%Y%m%d-%H%M%S")))
  dir.create(output, recursive = TRUE)
  evidence <- list(gate = if (quick) "P5a sync/query diagnostic" else "P5a",
    status = "failed", external_conformance = FALSE,
    server = "strict synthetic SMART fixture", transport = "HTTP loopback development exception",
    registration = "public", response_modes = response_modes,
    engines = if (quick) "sync" else c("sync", "mirai"),
    versions = setNames(lapply(packages, function(p) as.character(utils::packageVersion(p))), packages))
  on.exit({
    evidence$chrome <- retention_evidence_env$chrome
    jsonlite::write_json(evidence, file.path(output, "evidence.json"), auto_unbox = TRUE, pretty = TRUE)
  }, add = TRUE)
  results <- testthat::test_file("integration/smart/test-browser-ehr-launch.R",
    env = environment(), reporter = "summary", stop_on_failure = FALSE)
  counts <- as.data.frame(results)
  evidence$passed <- sum(counts$passed)
  evidence$failures <- sum(counts$failed)
  evidence$errors <- sum(counts$error)
  evidence$skipped <- sum(counts$skipped)
  if (evidence$failures || evidence$errors || evidence$skipped) stop("Incomplete EHR browser gate")
  evidence$status <- "passed"
  cat("EHR browser assertions:", evidence$passed, "; sanitized evidence:", output, "\n")
}
run_smart_ehr_browser_tests()
