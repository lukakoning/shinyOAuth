run_oidc_provider_tests <- function(args = commandArgs(TRUE)) {
  if (
    length(args) != 2L ||
      !identical(args[[1L]], "--transport") ||
      !args[[2L]] %in% c("sync", "mirai")
  ) {
    stop(
      "Usage: Rscript integration/oidc-provider/run-tests.R --transport sync|mirai"
    )
  }
  Sys.setenv(CURL_SSL_BACKEND = "openssl", NOT_CRAN = "true")
  withr::local_options(warn = 2)
  for (name in c(
    "environment",
    "suite",
    "source",
    "evidence",
    "app",
    "driver"
  )) {
    source(paste0("integration/openid/helper-", name, ".R"), local = TRUE)
  }
  for (name in c("environment", "driver", "evidence")) {
    source(
      paste0("integration/oidc-provider/helper-", name, ".R"),
      local = TRUE
    )
  }
  openid_require(c(
    "testthat",
    "processx",
    "jsonlite",
    "httr2",
    "openssl",
    "jose",
    "callr",
    "shiny",
    "chromote",
    "ps",
    "httpuv",
    "withr"
  ))
  if (args[[2L]] == "mirai") {
    openid_require(c("mirai", "promises", "later"))
  }
  output <- interop_output()
  checkout <- openid_source_identity(".")
  report <- list(
    schema_version = 2L,
    status = "failed",
    scope = "oidc_provider_interoperability",
    coverage_complete = FALSE,
    run_id = paste(format(openssl::rand_bytes(16)), collapse = ""),
    transport = args[[2L]],
    checkout_revision = checkout[["revision"]],
    checkout_dirty = checkout[["dirty"]],
    checkout_source = checkout,
    source_verified = FALSE,
    package_version = read.dcf("DESCRIPTION")[[1L, "Version"]],
    r_version = as.character(getRversion()),
    results = list(),
    gate_passed = FALSE,
    cleanup_verified = FALSE,
    driver_failure_control_passed = FALSE
  )
  on.exit(
    jsonlite::write_json(
      report,
      file.path(output, "evidence.json"),
      auto_unbox = TRUE,
      pretty = TRUE,
      null = "null"
    ),
    add = TRUE
  )
  cases <- jsonlite::read_json("integration/oidc-provider/profiles.json")[[
    "cases"
  ]]
  environment <- interop_prepare(".", output)
  report[["provider_lock"]] <- environment[["lock"]]
  report[["image_id"]] <- environment[["image"]]
  report[["source_hashes"]] <- environment[["source_hashes"]]
  report[["dependency_versions"]] <- as.list(vapply(
    c("openssl", "httr2", "chromote", "mirai"),
    function(name) as.character(utils::packageVersion(name)),
    character(1)
  ))
  library <- openid_install(".", output, checkout)
  report[["installation"]] <- openid_use_installation(library, checkout)
  context <- report
  transport <- openid_app_transport(".", environment, httpuv::randomPort())
  failure <- tryCatch(
    interop_run_case(
      ".",
      environment,
      transport,
      library,
      context,
      cases[[1L]],
      .stop_before_login = TRUE
    ),
    error = identity
  )
  if (
    !inherits(failure, "error") ||
      !identical(
        conditionMessage(failure),
        "OpenID fixture app stopped before an outcome"
      )
  ) {
    stop("Provider app-stop failure control failed")
  }
  report[["driver_failure_control_passed"]] <- TRUE
  started <- Sys.time()
  for (selection in cases) {
    row <- interop_run_case(
      ".",
      environment,
      transport,
      library,
      context,
      selection
    )
    report[["results"]][[length(report[["results"]]) + 1L]] <- row
  }
  report[["case_runtime_seconds"]] <- round(
    as.numeric(difftime(Sys.time(), started, units = "secs")),
    2
  )
  openid_stop_app(transport)
  report[["cleanup_verified"]] <- TRUE
  report[["checkout_source_after"]] <- openid_assert_source(".", checkout)
  report[["installation_after"]] <- openid_use_installation(
    library,
    checkout,
    context[["installation"]]
  )
  report[["source_verified"]] <- TRUE
  report[["rejection_controls"]] <- interop_rejection_controls(
    report,
    context,
    environment[["lock"]],
    cases
  )
  if (!interop_check_report(report, context, environment[["lock"]], cases)) {
    stop("Provider report failed validation")
  }
  serialized <- jsonlite::fromJSON(
    as.character(jsonlite::toJSON(report, auto_unbox = TRUE, null = "null")),
    simplifyVector = FALSE
  )
  if (
    !interop_check_report(serialized, context, environment[["lock"]], cases)
  ) {
    stop("Serialized provider report failed validation")
  }
  report[["gate_passed"]] <- TRUE
  report[["status"]] <- "passed"
  cat(
    "oidc-provider baseline passed:",
    length(cases),
    "cases;",
    length(report[["rejection_controls"]]),
    "evidence rejection controls\n"
  )
  invisible(report)
}

run_oidc_provider_tests()
