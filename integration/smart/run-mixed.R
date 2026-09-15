run_smart_mixed <- function() {
  packages <- c(
    "shinyOAuth",
    "shiny",
    "webfakes",
    "httpuv",
    "chromote",
    "callr",
    "testthat",
    "httr2",
    "jsonlite",
    "curl",
    "withr",
    "mirai",
    "promises",
    "jose",
    "openssl",
    "processx"
  )
  for (package in packages) {
    if (!requireNamespace(package, quietly = TRUE)) {
      stop("Missing package: ", package)
    }
  }
  retention_root <- normalizePath(".", winslash = "/")
  retention_evidence_env <- new.env(parent = emptyenv())
  source("integration/connections/helper-browser.R", local = TRUE)
  source("integration/smart/fixture-profile-provider.R", local = TRUE)
  cases <- expand.grid(
    managed_oidc = c(FALSE, TRUE),
    response_mode = c("query", "form_post"),
    async = c(FALSE, TRUE),
    stringsAsFactors = FALSE
  )
  output <- file.path(
    "integration/smart/.artifacts",
    paste0("mixed-", format(Sys.time(), "%Y%m%d-%H%M%S"))
  )
  dir.create(output, recursive = TRUE)
  evidence <- list(
    gate = "ordinary OIDC and SMART browser composition",
    status = "failed",
    external_conformance = FALSE,
    scenarios = cases,
    transport = "HTTPS cross-site",
    versions = setNames(
      lapply(packages, function(p) as.character(utils::packageVersion(p))),
      packages
    )
  )
  on.exit(
    {
      evidence[["chrome"]] <- retention_evidence_env[["chrome"]]
      jsonlite::write_json(
        evidence,
        file.path(output, "evidence.json"),
        auto_unbox = TRUE,
        pretty = TRUE
      )
    },
    add = TRUE
  )
  results <- testthat::test_file(
    "integration/smart/test-browser-mixed.R",
    env = environment(),
    reporter = "summary",
    stop_on_failure = FALSE
  )
  counts <- as.data.frame(results)
  evidence[["tests"]] <- as.list(colSums(counts[c(
    "passed",
    "failed",
    "error",
    "skipped"
  )]))
  if (
    nrow(counts) != nrow(cases) ||
      evidence[["tests"]][["passed"]] == 0 ||
      any(unlist(evidence[["tests"]][c("failed", "error", "skipped")]) != 0)
  ) {
    stop("Incomplete mixed browser matrix")
  }
  evidence[["status"]] <- "passed"
  message(
    "Mixed OIDC/SMART browser assertions: ",
    evidence[["tests"]][["passed"]],
    "; scenarios: ",
    nrow(cases)
  )
}
run_smart_mixed()
