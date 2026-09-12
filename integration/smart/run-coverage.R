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
  source("integration/smart/helper-inferno-evidence.R", local = TRUE)
  output <- file.path(root, "integration/smart/.artifacts", paste0("coverage-", format(Sys.time(), "%Y%m%d-%H%M%S")))
  dir.create(output, recursive = TRUE)
  evidence <- list(status = "started", external_interoperability = "not_established",
    independent_client_verification = "not_run",
    package_version = as.character(utils::packageVersion("shinyOAuth")),
    unit_suite_requested = !"--integration-only" %in% args, suites = list())
  on.exit(jsonlite::write_json(evidence, file.path(output, "evidence.json"),
    auto_unbox = TRUE, pretty = TRUE, null = "null"), add = TRUE)
  suites <- list(
    conformance = c("integration/conformance/run-tests.R"),
    retention = c("integration/connections/run-tests.R"),
    account_retention = c("integration/connections/run-account.R"),
    oauth_authorization_post = c("integration/connections/run-tests.R", "--post"),
    shared_callbacks = c("integration/connections/run-shared-router.R"),
    refresh_scopes = c("integration/connections/run-scope-narrowing.R"),
    smart_profiles = c("integration/smart/run-profiles.R"),
    smart_authorization_post = c("integration/smart/run-profiles.R", "--post"),
    ehr_concurrency = c("integration/smart/run-ehr-browser.R"),
    sandbox = c("integration/smart/run-tests.R"),
    inferno_client = c("integration/smart/run-inferno.R")
  )
  if (!"--integration-only" %in% args) {
    suites <- c(list(unit_and_browser = c("integration/smart/run-package-tests.R")), suites)
  }
  rscript <- file.path(R.home("bin"), "Rscript")
  for (name in names(suites)) {
    message("Running roadmap coverage: ", name)
    start <- Sys.time()
    report <- file.path(output, "inferno-evidence.json")
    result <- tryCatch(processx::run(rscript, suites[[name]], wd = root,
      env = c("current", SHINYOAUTH_INFERNO_REPORT = report),
      error_on_status = FALSE, echo = TRUE, timeout = 1800000),
      error = function(...) list(status = 124L))
    evidence$suites[[name]] <- list(status = if (result$status == 0L) "passed" else "failed",
      exit_status = result$status, elapsed_seconds = round(as.numeric(difftime(Sys.time(), start, units = "secs")), 1))
    if (name == "inferno_client") {
      proof <- tryCatch(jsonlite::read_json(report, simplifyVector = FALSE), error = function(...) NULL)
      if (result$status == 0L && inferno_report_passed(proof)) {
        evidence$independent_client_verification <- "passed_modified_inferno_simulator"
        evidence$suites[[name]]$scenarios <- length(proof$scenarios)
        evidence$suites[[name]]$upstream_tests_passed <- 10L * length(proof$scenarios)
        evidence$suites[[name]]$evidence_file <- "inferno-evidence.json"
      } else {
        evidence$independent_client_verification <- "failed"
        evidence$suites[[name]]$status <- "failed"
        evidence$suites[[name]]$exit_status <- 1L
      }
    }
  }
  if ("--require-external" %in% args) {
    evidence$suites$unmodified_external_app_interoperability <- list(status = "unverified", exit_status = 1L,
      reason = "The executed independent verifier uses documented simulator corrections; no unmodified external app run is recorded.")
  }
  failed <- names(Filter(function(row) row$exit_status != 0L, evidence$suites))
  evidence$status <- if (length(failed)) "failed" else "implemented_suites_passed"
  message("Coverage evidence: ", file.path(output, "evidence.json"))
  if (length(failed)) stop("Incomplete roadmap coverage: ", paste(failed, collapse = ", "))
  # A diagnostic sandbox pass cannot establish application interoperability.
  message("Implemented suites passed, including independent Inferno client verification with recorded simulator corrections.")
  message("Unmodified external SMART interoperability remains unestablished; see coverage.md.")
}
run_smart_coverage()
