# Install the current checkout first; run from the repository root.
run_target_browser_tests <- function() {
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
  for (file in c("fixture-target-provider.R", "helper-browser.R")) {
    source(file.path("integration/connections", file), local = TRUE)
  }
  artifacts <- file.path(
    "integration/connections/.artifacts",
    paste0("targets-", format(Sys.time(), "%Y%m%d-%H%M%S"))
  )
  dir.create(artifacts, recursive = TRUE)
  evidence <- list(
    status = "failed",
    external_conformance = FALSE,
    transport = "HTTP loopback development exception",
    scenarios = c(
      "target acquisition",
      "narrowed replacement",
      "pending acquisition replacement",
      "cancellation",
      "post-logout login"
    ),
    versions = stats::setNames(
      lapply(required, function(package) {
        as.character(utils::packageVersion(package))
      }),
      required
    )
  )
  on.exit(
    {
      evidence[["chrome"]] <- retention_evidence_env[["chrome"]]
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
    "integration/connections/test-browser-targets.R",
    env = environment(),
    reporter = "summary",
    stop_on_failure = FALSE
  )
  counts <- as.data.frame(results)
  for (field in c("passed", "failed", "error", "skipped", "warning")) {
    evidence[[field]] <- sum(counts[[field]])
  }
  if (
    evidence[["failed"]] ||
      evidence[["error"]] ||
      evidence[["skipped"]] ||
      evidence[["warning"]]
  ) {
    stop("Target browser gate did not fully pass")
  }
  evidence[["status"]] <- "passed"
  cat(
    "Target browser gate:",
    evidence[["passed"]],
    "assertions passed; no skips.\n"
  )
}
run_target_browser_tests()
