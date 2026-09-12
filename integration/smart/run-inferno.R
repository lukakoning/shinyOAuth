# Real Shiny browser flows followed by the upstream Inferno client verifier.
run_inferno <- function(args = commandArgs(trailingOnly = TRUE)) {
  if (!all(args %in% "--quick")) stop("Usage: Rscript integration/smart/run-inferno.R [--quick]")
  packages <- c("shinyOAuth", "shiny", "httr2", "openssl", "jose", "jsonlite", "processx", "withr",
    "httpuv", "callr", "chromote", "testthat", "promises", "mirai")
  for (package in packages) if (!requireNamespace(package, quietly = TRUE)) stop("Missing package: ", package)
  root <- normalizePath(".", winslash = "/")
  output <- file.path(root, "integration/smart/.artifacts", paste0("inferno-", format(Sys.time(), "%Y%m%d-%H%M%S")))
  dir.create(output, recursive = TRUE)
  for (file in c("integration/smart/helper-inferno.R", "integration/smart/helper-inferno-browser.R",
    "integration/connections/helper-browser.R")) source(file, local = TRUE)
  testthat::test_file(file.path(root, "integration/smart/test-inferno-evidence.R"),
    env = environment(), reporter = "summary", stop_on_failure = TRUE, stop_on_warning = TRUE)
  evidence <- list(status = "failed", suite_id = inferno_suite, complete_matrix = !"--quick" %in% args,
    simulator_modified = TRUE, unmodified_external_interoperability = "not_established",
    max_id_token_lifetime_seconds = 366 * 86400,
    checkout_revision = trimws(processx::run("git", c("rev-parse", "HEAD"))$stdout),
    checkout_dirty = nzchar(trimws(processx::run("git", c("status", "--porcelain"))$stdout)),
    package_version = as.character(utils::packageVersion("shinyOAuth")),
    r_version = as.character(getRversion()), response_mode = "query", scenarios = list())
  on.exit(jsonlite::write_json(evidence, file.path(output, "evidence.json"),
    auto_unbox = TRUE, pretty = TRUE, null = "null"), add = TRUE)
  evidence$provenance <- inferno_build(root, output)
  evidence$simulator_regressions <- inferno_test_simulator(root, output)
  stack <- inferno_start(root, output)
  withr::local_envvar(CURL_CA_BUNDLE = stack$ca)
  shinyOAuth::smart_discover(stack$fhir_base)
  cases <- expand.grid(profile = c("public", "basic", "rs384", "es384"),
    launch = c("standalone", "ehr"), stringsAsFactors = FALSE)
  if ("--quick" %in% args) cases <- cases[1L, , drop = FALSE]
  run_case <- function(row, index) {
    case_dir <- file.path(output, paste0("case-", index))
    dir.create(case_dir)
    style <- switch(row$profile, public = "public", basic = "header", "private_key_jwt")
    algorithm <- if (row$profile == "es384") "ES384" else "RS384"
    registrations <- list(a = inferno_registration(stack, style, algorithm, "a"))
    app <- inferno_start_app(root, case_dir, registrations, row$launch)
    session <- inferno_begin_session(stack, registrations$a, app$origin, "a", row$launch)
    chrome <- inferno_open_browser(app)
    browser <- chrome$browser
    if (row$launch == "ehr") {
      stopifnot(is.character(session$launch_url), startsWith(session$launch_url, paste0(app$origin, "/launch?")))
      browser$Page$navigate(session$launch_url)
    } else retention_browser_click(browser, "connect_a")
    authorized <- retention_browser_wait(browser, function() {
      value <- retention_browser_snapshot(browser)
      if (!is.null(value) && length(value$connections) == 1L) value else NULL
    }, "Inferno SMART callback")
    stopifnot(length(authorized$errors) == 0L)
    for (action in c("read_a", "user_a", "refresh_a", "read_a", "user_a")) {
      retention_browser_action(browser, action, paste0(action, ":ok"))
    }
    verification <- inferno_finish_session(stack, session)
    list(profile = row$profile, launch = row$launch, browser = chrome$version,
      authorization_method = "GET", async = FALSE, response_mode = "query",
      app_flow = "passed", patient_read = TRUE, validated_fhir_user = TRUE, refresh_and_read = TRUE,
      inferno = verification, status = if (verification$passed) "passed" else "failed")
  }
  for (index in seq_len(nrow(cases))) {
    row <- cases[index, ]
    message("Inferno app flow: ", row$profile, " / ", row$launch)
    evidence$scenarios[[index]] <- tryCatch(run_case(row, index), error = function(e) {
      # Browser/HTTP errors are intentionally coarse; raw exchange details remain
      # in the owned Inferno database, which is removed on exit.
      message("Scenario failed: ", conditionMessage(e))
      list(profile = row$profile, launch = row$launch, status = "failed")
    })
  }
  if (length(evidence$scenarios) != nrow(cases) || !all(vapply(evidence$scenarios,
    function(row) identical(row$status, "passed"), logical(1)))) stop("Inferno application matrix did not pass")
  evidence$status <- "passed"
  cat("Inferno application scenarios passed:", nrow(cases), "; simulator modifications recorded.\n")
}
run_inferno()
