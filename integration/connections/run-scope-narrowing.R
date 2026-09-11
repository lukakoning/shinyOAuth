# Install the current checkout first; run from the repository root.
run_scope_narrowing_browser_tests <- function() {
  required <- c("shinyOAuth", "shiny", "httpuv", "webfakes", "chromote", "testthat",
    "callr", "withr", "curl", "jsonlite", "promises", "future", "mirai")
  missing <- Filter(function(package) !requireNamespace(package, quietly = TRUE), required)
  if (length(missing)) stop("Missing browser-test packages: ", paste(missing, collapse = ", "))
  retention_root <- normalizePath(".", winslash = "/")
  retention_evidence_env <- new.env(parent = emptyenv())
  for (file in c("fixture-provider.R", "helper-browser.R")) {
    source(file.path("integration/connections", file), local = TRUE)
  }
  artifacts <- file.path("integration/connections/.artifacts", paste0("scopes-", format(Sys.time(), "%Y%m%d-%H%M%S")))
  dir.create(artifacts, recursive = TRUE)
  evidence <- list(gate = "P7a", status = "failed", external_conformance = FALSE,
    transport = "HTTP loopback development exception",
    provider = "synthetic PKCE and rotating-refresh server retaining the original refresh-token grant",
    modes = c("sync", "async"), responses = c("query", "form_post"),
    versions = stats::setNames(lapply(required, function(package) as.character(utils::packageVersion(package))), required))
  on.exit({
    evidence$chrome <- retention_evidence_env$chrome
    jsonlite::write_json(evidence, file.path(artifacts, "evidence.json"), auto_unbox = TRUE, pretty = TRUE)
  }, add = TRUE)
  results <- testthat::test_file("integration/connections/test-browser-scope-narrowing.R",
    env = environment(), reporter = "summary", stop_on_failure = FALSE)
  counts <- as.data.frame(results)
  evidence$passed <- sum(counts$passed)
  evidence$skipped <- sum(counts$skipped)
  evidence$failures <- sum(counts$failed)
  evidence$errors <- sum(counts$error)
  if (evidence$failures || evidence$errors || evidence$skipped) stop("Refresh scope browser gate did not fully pass")
  evidence$status <- "passed"
  cat("Refresh scope browser gate:", evidence$passed, "assertions passed; no skips.\n")
}
run_scope_narrowing_browser_tests()
