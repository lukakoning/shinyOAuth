# Run from the repository root after installing this checkout.
run_smart_profiles <- function(args = commandArgs(trailingOnly = TRUE)) {
  if (!all(args %in% c("--quick", "--post", "--es384"))) stop("Usage: Rscript integration/smart/run-profiles.R [--quick] [--post] [--es384]")
  authorization_method <- if ("--post" %in% args) "POST" else "GET"
  extra_scopes <- if (authorization_method == "POST") paste0(
    "patient/Observation.rs?code=https://example.test/synthetic-codes|observation-", seq_len(32)) else character()
  packages <- c("shinyOAuth", "shiny", "webfakes", "httpuv", "chromote", "callr",
    "testthat", "httr2", "jsonlite", "curl", "withr", "mirai", "promises", "jose", "openssl")
  for (package in packages) if (!requireNamespace(package, quietly = TRUE)) stop("Missing package: ", package)
  retention_root <- normalizePath(".", winslash = "/")
  retention_evidence_env <- new.env(parent = emptyenv())
  source("integration/connections/helper-browser.R", local = TRUE)
  source("integration/smart/fixture-profile-provider.R", local = TRUE)
  cases <- expand.grid(registration = c("public", "header", "private_key_jwt"),
    launch = c("standalone", "ehr"), response_mode = c("query", "form_post"),
    async = c(FALSE, TRUE), stringsAsFactors = FALSE)
  cases$assertion_alg <- ifelse(cases$registration == "private_key_jwt", "RS384", NA_character_)
  elliptic <- cases[cases$registration == "private_key_jwt", ]
  elliptic$assertion_alg <- "ES384"
  cases <- rbind(cases, elliptic)
  if ("--es384" %in% args) cases <- cases[cases$assertion_alg %in% "ES384", ]
  if ("--quick" %in% args) cases <- cases[cases$launch == "standalone" & cases$response_mode == "query" & !cases$async, ]
  output <- file.path("integration/smart/.artifacts", paste0("profiles-", format(Sys.time(), "%Y%m%d-%H%M%S")))
  dir.create(output, recursive = TRUE)
  evidence <- list(gate = "SMART profile browser matrix", status = "failed", external_conformance = FALSE,
    complete_matrix = !any(c("--quick", "--es384") %in% args), scenarios = cases, server = "strict synthetic SMART fixture",
    authorization_method = authorization_method, extra_scope_count = length(extra_scopes),
    transport = "HTTP loopback development exception", identity = "validated fhirUser distinct from Patient",
    versions = setNames(lapply(packages, function(p) as.character(utils::packageVersion(p))), packages))
  on.exit({
    evidence$chrome <- retention_evidence_env$chrome
    jsonlite::write_json(evidence, file.path(output, "evidence.json"), auto_unbox = TRUE, pretty = TRUE)
  }, add = TRUE)
  results <- testthat::test_file("integration/smart/test-browser-profiles.R",
    env = environment(), reporter = "summary", stop_on_failure = FALSE)
  counts <- as.data.frame(results)
  evidence$tests <- as.list(colSums(counts[c("passed", "failed", "error", "skipped")]))
  if (nrow(counts) != nrow(cases) || evidence$tests$passed == 0 ||
      any(unlist(evidence$tests[c("failed", "error", "skipped")]) != 0)) stop("Incomplete SMART profile matrix")
  evidence$status <- "passed"
  cat("SMART profile browser assertions:", evidence$tests$passed, "; scenarios:", nrow(cases), "\n")
}
run_smart_profiles()
