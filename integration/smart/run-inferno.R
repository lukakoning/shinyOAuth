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
    "integration/smart/helper-inferno-exchanges.R",
    "integration/connections/helper-browser.R")) source(file, local = TRUE)
  testthat::test_file(file.path(root, "integration/smart/test-inferno-evidence.R"),
    env = environment(), reporter = "summary", stop_on_failure = TRUE, stop_on_warning = TRUE)
  evidence <- list(status = "failed", suite_id = inferno_suite, complete_matrix = !"--quick" %in% args,
    simulator_modified = TRUE, unmodified_external_interoperability = "not_established",
    max_id_token_lifetime_seconds = 366 * 86400,
    checkout_revision = trimws(processx::run("git", c("rev-parse", "HEAD"))$stdout),
    checkout_dirty = nzchar(trimws(processx::run("git", c("status", "--porcelain"))$stdout)),
    package_version = as.character(utils::packageVersion("shinyOAuth")),
    r_version = as.character(getRversion()), response_mode = "query",
    limitations = list(form_post_callback = "not_verified_by_inferno",
      server_permission_enforcement = "not_verified", refresh_token_rotation = "not_verified_by_inferno",
      cross_vendor_portability = "not_established"), scenarios = list())
  on.exit(jsonlite::write_json(evidence, file.path(output, "evidence.json"),
    auto_unbox = TRUE, pretty = TRUE, null = "null"), add = TRUE)
  evidence$provenance <- inferno_build(root, output)
  evidence$simulator_regressions <- inferno_test_simulator(root, output)
  run_env <- environment()
  stacks <- lapply(c("a", "b"), function(site) inferno_start(root, output, site, .env = run_env))
  names(stacks) <- c("a", "b")
  # Keep both owned deployments alive until this runner returns.
  # The explicit environment avoids attaching cleanup to lapply's short frame.
  withr::local_envvar(CURL_CA_BUNDLE = stacks$a$ca)
  for (stack in stacks) shinyOAuth::smart_discover(stack$fhir_base)
  cases <- expand.grid(profile = c("public", "basic", "rs384", "es384"),
    launch = c("standalone", "ehr"), async = c(FALSE, TRUE),
    authorization_method = c("GET", "POST"), stringsAsFactors = FALSE)
  if ("--quick" %in% args) cases <- cases[cases$profile == "public" & cases$launch == "standalone", , drop = FALSE]
  run_case <- function(row, index) {
    case_dir <- file.path(output, paste0("case-", index))
    dir.create(case_dir)
    style <- switch(row$profile, public = "public", basic = "header", "private_key_jwt")
    algorithm <- if (row$profile == "es384") "ES384" else "RS384"
    registrations <- lapply(names(stacks), function(site) inferno_registration(stacks[[site]], style, algorithm, site))
    names(registrations) <- names(stacks)
    app <- inferno_start_app(root, case_dir, registrations, row$launch,
      async = row$async, authorization_method = row$authorization_method)
    sessions <- lapply(names(stacks), function(site)
      inferno_begin_session(stacks[[site]], registrations[[site]], app$origin, site, row$launch))
    names(sessions) <- names(stacks)
    chrome <- inferno_open_browser(app)
    browser <- chrome$browser
    authorize <- function(site, count) {
      session <- sessions[[site]]
      if (row$launch == "ehr") {
        stopifnot(is.character(session$launch_url), startsWith(session$launch_url, paste0(app$origin, "/launch?")))
        browser$Page$navigate(session$launch_url)
      } else retention_browser_click(browser, paste0("connect_", site))
      value <- retention_browser_wait(browser, function() {
        value <- retention_browser_snapshot(browser)
        if (!is.null(value) && length(value$connections) == count) value else NULL
      }, "Inferno SMART callback")
      stopifnot(length(value$errors) == 0L)
      value
    }
    action <- function(id, ok = TRUE, target = browser)
      retention_browser_action(target, id, paste0(id, if (ok) ":ok" else ":unavailable"))
    connection <- function(snapshot, site) {
      rows <- Filter(function(value) identical(value$client_label, paste("Site", site)), snapshot$connections)
      stopifnot(length(rows) == 1L)
      rows[[1L]]
    }
    first <- authorize("a", 1L)
    for (id in c("read_a", "user_a", "search_a", "narrow_a")) action(id)
    action("search_a", FALSE)
    for (id in c("read_a", "user_a")) action(id)
    both <- authorize("b", 2L)
    stopifnot(both$session > first$session,
      identical(connection(first, "a")$connection_id, connection(both, "a")$connection_id),
      identical(connection(both, "a")$status, "limited"))
    for (id in c("read_b", "user_b", "search_b")) action(id)
    browser$Page$navigate(paste0(app$origin, "/retained"))
    retained <- retention_browser_wait(browser, function() {
      value <- retention_browser_snapshot(browser)
      if (!is.null(value) && value$session > both$session && length(value$connections) == 2L) value else NULL
    }, "retained Inferno connections in a new Shiny session")
    for (site in names(stacks)) stopifnot(identical(connection(both, site)$connection_id,
      connection(retained, site)$connection_id))
    stopifnot(identical(connection(retained, "a")$status, "limited"),
      identical(connection(retained, "b")$status, "active"))
    for (id in c("read_a", "user_a")) action(id)
    for (id in c("search_a", "widen_a")) action(id, FALSE)
    for (id in c("refresh_a", "read_a", "user_a", "refresh_b", "read_b", "user_b", "search_b")) action(id)
    foreign <- inferno_open_browser(app)$browser
    stopifnot(length(retention_browser_snapshot(foreign)$connections) == 0L)
    action("read_a", FALSE, foreign)
    action("read_b", FALSE, foreign)
    retention_browser_click(browser, "disconnect_b")
    retention_browser_wait(browser, function()
      identical(connection(retention_browser_snapshot(browser), "b")$status, "disconnected"), "disconnect site B")
    for (id in c("read_b", "user_b", "refresh_b")) action(id, FALSE)
    for (id in c("read_a", "user_a")) action(id)
    retention_browser_click(browser, "logout")
    retention_browser_wait(browser, function() {
      value <- retention_browser_snapshot(browser)
      !is.null(value) && length(value$connections) == 0L
    }, "browser logout")
    action("read_a", FALSE)
    verification <- lapply(names(stacks), function(site) {
      verified <- inferno_finish_session(stacks[[site]], sessions[[site]])
      verified$driver_exchange_checks <- inferno_exchange_summary(stacks[[site]], sessions[[site]],
        registrations[[site]], row$launch, row$authorization_method)
      verified
    })
    names(verification) <- names(stacks)
    list(profile = row$profile, launch = row$launch, browser = chrome$version,
      authorization_method = row$authorization_method, async = row$async, response_mode = "query",
      app_flow = "passed", patient_read = TRUE, validated_fhir_user = TRUE, refresh_and_read = TRUE,
      two_sites_retained = TRUE, browser_owner_isolation = TRUE, narrowing_retained = TRUE,
      independent_refresh_and_disconnect = TRUE, logout = TRUE,
      inferno = verification, status = if (all(vapply(verification, function(site) site$passed, logical(1))))
        "passed" else "failed")
  }
  for (index in seq_len(nrow(cases))) {
    row <- cases[index, ]
    message("Inferno app flow: ", row$profile, " / ", row$launch, " / ",
      row$authorization_method, " / ", if (row$async) "mirai" else "sync")
    evidence$scenarios[[index]] <- tryCatch(run_case(row, index), error = function(e) {
      # Browser/HTTP errors are intentionally coarse; raw exchange details remain
      # in the owned Inferno database, which is removed on exit.
      message("Scenario failed: ", conditionMessage(e))
      writeLines(paste(deparse(conditionCall(e)), collapse = "\n"),
        file.path(output, paste0("case-", index), "error-call.txt"))
      list(profile = row$profile, launch = row$launch, authorization_method = row$authorization_method,
        async = row$async, status = "failed")
    })
  }
  if (length(evidence$scenarios) != nrow(cases) || !all(vapply(evidence$scenarios,
    function(row) identical(row$status, "passed"), logical(1)))) stop("Inferno application matrix did not pass")
  evidence$status <- "passed"
  cat("Inferno application scenarios passed:", nrow(cases), "; simulator modifications recorded.\n")
}
run_inferno()
