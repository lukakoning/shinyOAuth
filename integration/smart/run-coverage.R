# One entry point for implemented roadmap coverage. Each suite runs in a fresh
# R process; browser suites run sequentially and use their own cleanup/evidence.
run_smart_coverage <- function(args = commandArgs(trailingOnly = TRUE)) {
  if (!all(args %in% c("--integration-only", "--require-external"))) {
    stop("Usage: Rscript integration/smart/run-coverage.R [--integration-only] [--require-external]")
  }
  for (package in c("processx", "jsonlite", "shinyOAuth")) {
    if (!requireNamespace(package, quietly = TRUE)) stop("Missing package: ", package)
  }
  Sys.setenv(R_LIBS = paste(.libPaths(), collapse = .Platform$path.sep), NOT_CRAN = "true")
  root <- normalizePath(".", winslash = "/")
  output <- file.path(root, "integration/smart/.artifacts", paste0("coverage-", format(Sys.time(), "%Y%m%d-%H%M%S")))
  dir.create(output, recursive = TRUE)
  evidence <- list(status = "started", external_interoperability = "not_established",
    package_version = as.character(utils::packageVersion("shinyOAuth")),
    unit_suite_requested = !"--integration-only" %in% args, suites = list())
  on.exit(jsonlite::write_json(evidence, file.path(output, "evidence.json"),
    auto_unbox = TRUE, pretty = TRUE, null = "null"), add = TRUE)
  suites <- list(
    conformance = c("integration/conformance/run-tests.R"),
    retention = c("integration/connections/run-tests.R"),
    oauth_authorization_post = c("integration/connections/run-tests.R", "--post"),
    shared_callbacks = c("integration/connections/run-shared-router.R"),
    refresh_scopes = c("integration/connections/run-scope-narrowing.R"),
    smart_profiles = c("integration/smart/run-profiles.R"),
    smart_authorization_post = c("integration/smart/run-profiles.R", "--post"),
    ehr_concurrency = c("integration/smart/run-ehr-browser.R"),
    sandbox = c("integration/smart/run-tests.R", if ("--require-external" %in% args) "--require-compatible-discovery")
  )
  if (!"--integration-only" %in% args) {
    suites <- c(list(unit_and_browser = c("integration/smart/run-package-tests.R")), suites)
  }
  rscript <- file.path(R.home("bin"), "Rscript")
  for (name in names(suites)) {
    message("Running roadmap coverage: ", name)
    start <- Sys.time()
    result <- tryCatch(processx::run(rscript, suites[[name]], wd = root,
      error_on_status = FALSE, echo = TRUE, timeout = 1800000),
      error = function(...) list(status = 124L))
    evidence$suites[[name]] <- list(status = if (result$status == 0L) "passed" else "failed",
      exit_status = result$status, elapsed_seconds = round(as.numeric(difftime(Sys.time(), start, units = "secs")), 1))
  }
  if ("--require-external" %in% args) {
    evidence$suites$external_app_interoperability <- list(status = "not_implemented", exit_status = 1L)
  }
  failed <- names(Filter(function(row) row$exit_status != 0L, evidence$suites))
  evidence$status <- if (length(failed)) "failed" else "implemented_suites_passed"
  message("Coverage evidence: ", file.path(output, "evidence.json"))
  if (length(failed)) stop("Incomplete roadmap coverage: ", paste(failed, collapse = ", "))
  # A diagnostic sandbox pass cannot establish application interoperability.
  message("Implemented suites passed. External SMART app conformance remains unestablished; see coverage.md.")
}
run_smart_coverage()
