run_advanced_provider_tests <- function(args = commandArgs(TRUE)) {
  if (
    length(args) != 2L ||
      !identical(args[[1L]], "--transport") ||
      !args[[2L]] %in% c("sync", "mirai")
  ) {
    stop(
      "Usage: Rscript integration/oidc-provider/run-advanced.R --transport sync|mirai"
    )
  }
  Sys.setenv(CURL_SSL_BACKEND = "openssl", NOT_CRAN = "true")
  withr::local_options(warn = 2)
  for (name in c(
    "environment",
    "suite",
    "evidence",
    "auth",
    "fapi",
    "signing",
    "mtls",
    "app",
    "driver"
  )) {
    source(paste0("integration/openid/helper-", name, ".R"), local = TRUE)
  }
  for (name in c(
    "environment",
    "driver",
    "evidence",
    "advanced",
    "advanced-evidence"
  )) {
    source(
      paste0("integration/oidc-provider/helper-", name, ".R"),
      local = TRUE
    )
  }
  output <- interop_output(profile = "advanced")
  report <- list(
    schema_version = 1L,
    scope = "oidc_provider_advanced_interoperability",
    status = "failed",
    gate_passed = FALSE,
    coverage_complete = FALSE,
    coverage_limitations = interop_advanced_limitations(),
    run_id = paste(format(openssl::rand_bytes(16)), collapse = ""),
    transport = args[[2L]],
    checkout_revision = trimws(processx::run("git", c("rev-parse", "HEAD"))[[
      "stdout"
    ]]),
    checkout_dirty = nzchar(trimws(processx::run(
      "git",
      c("status", "--porcelain")
    )[["stdout"]])),
    package_version = read.dcf("DESCRIPTION")[[1L, "Version"]],
    r_version = as.character(getRversion()),
    results = list(),
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
  cases <- jsonlite::read_json(
    "integration/oidc-provider/advanced-profiles.json"
  )[["cases"]]
  environment <- interop_prepare(".", output)
  environment[["client_certificates"]] <- interop_client_certificates(
    environment
  )
  report[["provider_lock"]] <- environment[["lock"]]
  report[["image_id"]] <- environment[["image"]]
  report[["source_hashes"]] <- environment[["source_hashes"]]
  report[["dependency_versions"]] <- as.list(vapply(
    c("openssl", "httr2", "chromote", "mirai"),
    function(name) as.character(utils::packageVersion(name)),
    character(1)
  ))
  context <- report
  library <- openid_install(".", output)
  transport <- openid_app_transport(".", environment, httpuv::randomPort())
  basic <- jsonlite::read_json("integration/oidc-provider/profiles.json")[[
    "cases"
  ]][[1L]]
  failure <- tryCatch(
    interop_run_case(
      ".",
      environment,
      transport,
      library,
      context,
      basic,
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
    stop("Advanced app-stop control failed")
  }
  report[["driver_failure_control_passed"]] <- TRUE
  started <- Sys.time()
  for (selection in cases) {
    row <- interop_run_advanced(
      ".",
      environment,
      transport,
      library,
      context,
      selection
    )
    report[["results"]][[length(report[["results"]]) + 1L]] <- row
    if (
      !interop_advanced_row_matches(
        row,
        context,
        selection,
        environment[["lock"]]
      )
    ) {
      stop("Advanced evidence did not match: ", row[["id"]])
    }
  }
  for (selection in Filter(function(value) isTRUE(value[["jarm"]]), cases)) {
    row <- interop_run_advanced(
      ".",
      environment,
      transport,
      library,
      context,
      selection,
      tamper = TRUE
    )
    report[["results"]][[length(report[["results"]]) + 1L]] <- row
    if (
      !interop_advanced_row_matches(
        row,
        context,
        selection,
        environment[["lock"]]
      )
    ) {
      stop("Advanced negative evidence did not match: ", row[["id"]])
    }
  }
  report[["case_runtime_seconds"]] <- round(
    as.numeric(difftime(Sys.time(), started, units = "secs")),
    2
  )
  openid_stop_app(transport)
  report[["cleanup_verified"]] <- TRUE
  report[["rejection_controls"]] <- interop_advanced_rejections(
    report,
    context,
    environment[["lock"]],
    cases
  )
  serialized <- jsonlite::fromJSON(
    as.character(jsonlite::toJSON(report, auto_unbox = TRUE, null = "null")),
    simplifyVector = FALSE
  )
  if (
    !interop_advanced_check_report(
      serialized,
      context,
      environment[["lock"]],
      cases
    )
  ) {
    stop("Serialized advanced report did not match")
  }
  report[["status"]] <- "passed"
  report[["gate_passed"]] <- TRUE
  cat(
    "Advanced provider gate passed:",
    length(report[["results"]]),
    "browser cases;",
    length(report[["rejection_controls"]]),
    "report rejection controls\n"
  )
}

run_advanced_provider_tests()
