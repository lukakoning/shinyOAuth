# Run from the repository root after installing the current package checkout.
run_retention_browser_tests <- function(args = commandArgs(trailingOnly = TRUE)) {
  if (!all(args %in% "--post")) stop("Usage: Rscript integration/connections/run-tests.R [--post]")
  authorization_method <- if ("--post" %in% args) "POST" else "GET"
  required <- c(
    "shinyOAuth",
    "shiny",
    "httpuv",
    "webfakes",
    "chromote",
    "testthat",
    "callr",
    "withr",
    "curl",
    "jsonlite",
    "promises",
    "future",
    "mirai"
  )
  missing <- Filter(
    function(package) !requireNamespace(package, quietly = TRUE),
    required
  )
  if (length(missing)) {
    stop("Missing browser-test packages: ", paste(missing, collapse = ", "))
  }
  retention_root <- normalizePath(".", winslash = "/")
  retention_evidence_env <- new.env(parent = emptyenv())
  for (file in c("fixture-provider.R", "helper-browser.R")) {
    source(file.path("integration/connections", file), local = TRUE)
  }
  artifacts <- file.path(
    "integration/connections/.artifacts",
    format(Sys.time(), "%Y%m%d-%H%M%S")
  )
  dir.create(artifacts, recursive = TRUE)
  evidence <- list(
    gate = "P3d",
    authorization_method = authorization_method,
    status = "failed",
    transport = "HTTP loopback development exception",
    provider = "synthetic PKCE and rotating-refresh fixture; not independent conformance",
    modes = c("sync", "async"),
    responses = c("query", "form_post"),
    versions = lapply(required, function(package) {
      as.character(utils::packageVersion(package))
    })
  )
  names(evidence$versions) <- required
  on.exit(
    {
      evidence$chrome <- retention_evidence_env$chrome
      jsonlite::write_json(
        evidence,
        file.path(artifacts, "evidence.json"),
        auto_unbox = TRUE,
        pretty = TRUE
      )
    },
    add = TRUE
  )
  results <- testthat::test_file(
    "integration/connections/test-browser-retention.R",
    env = environment(),
    reporter = "summary",
    stop_on_failure = TRUE
  )
  counts <- as.data.frame(results)
  evidence$passed <- sum(counts$passed)
  evidence$skipped <- sum(counts$skipped)
  if (sum(counts$failed) || sum(counts$error) || evidence$skipped) {
    stop("Retention browser gate did not fully pass")
  }
  evidence$status <- "passed"
  cat(
    "Retention browser gate:",
    evidence$passed,
    "assertions passed; no skips.\n"
  )
}
run_retention_browser_tests()
