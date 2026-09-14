# Supplemental synthetic SMART lifecycle gates; each scenario uses a real browser.
run_smart_lifecycle <- function(args = commandArgs(trailingOnly = TRUE)) {
  if (length(args) != 1L || !args %in% c("expiry", "context", "interrupted", "consent"))
    stop("Usage: Rscript integration/smart/run-lifecycle.R expiry|context|interrupted|consent")
  scenario <- args[[1L]]
  for (package in c("shinyOAuth", "testthat", "chromote", "webfakes", "callr", "processx", "mirai"))
    if (!requireNamespace(package, quietly = TRUE)) stop("Missing package: ", package)
  retention_root <- normalizePath(".", winslash = "/")
  retention_evidence_env <- new.env(parent = emptyenv())
  for (path in c("integration/connections/helper-browser.R", "integration/smart/fixture-profile-provider.R",
    "integration/smart/helper-lifecycle.R")) source(path, local = TRUE)
  output <- file.path(retention_root, "integration/smart/.artifacts",
    paste0("lifecycle-", scenario, "-", format(Sys.time(), "%Y%m%d-%H%M%S")))
  dir.create(output, recursive = TRUE)
  evidence <- list(status = "failed", scenario = scenario, server = "synthetic SMART fixture",
    external_interoperability = "not_established", token_transport = c("sync", "mirai"))
  on.exit(jsonlite::write_json(evidence, file.path(output, "evidence.json"),
    auto_unbox = TRUE, pretty = TRUE), add = TRUE)
  results <- testthat::test_file(paste0("integration/smart/test-browser-", scenario, ".R"),
    env = environment(), reporter = "summary", stop_on_failure = FALSE)
  counts <- as.data.frame(results)
  evidence$tests <- as.list(colSums(counts[c("passed", "failed", "error", "skipped")]))
  evidence$scenarios <- nrow(counts)
  expected_scenarios <- switch(scenario, interrupted = 5L, consent = 8L, 4L)
  if (nrow(counts) != expected_scenarios || evidence$tests$passed == 0L ||
    any(unlist(evidence$tests[c("failed", "error", "skipped")]) != 0)) stop("SMART lifecycle gate failed")
  evidence$status <- "passed"
  cat("SMART", scenario, "scenarios:", nrow(counts), "; assertions:", evidence$tests$passed, "\n")
}
run_smart_lifecycle()
