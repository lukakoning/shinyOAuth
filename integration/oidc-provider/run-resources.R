run_resource_provider_tests <- function(args = commandArgs(TRUE)) {
  if (
    length(args) != 2L ||
      !identical(args[[1L]], "--transport") ||
      !args[[2L]] %in% c("sync", "mirai")
  ) {
    stop(
      "Usage: Rscript integration/oidc-provider/run-resources.R --transport sync|mirai"
    )
  }
  Sys.setenv(CURL_SSL_BACKEND = "openssl", NOT_CRAN = "true")
  withr::local_options(warn = 2)
  for (name in c("environment", "suite", "evidence", "app", "driver")) {
    source(paste0("integration/openid/helper-", name, ".R"), local = TRUE)
  }
  for (name in c(
    "environment",
    "driver",
    "evidence",
    "resources",
    "resource-evidence"
  )) {
    source(
      paste0("integration/oidc-provider/helper-", name, ".R"),
      local = TRUE
    )
  }
  openid_require(c(
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
  output <- interop_output(profile = "resources")
  report <- list(
    schema_version = 1L,
    scope = "oidc_provider_resource_indicators",
    status = "failed",
    gate_passed = FALSE,
    coverage_complete = FALSE,
    coverage_limitations = interop_resource_limits(),
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
    "integration/oidc-provider/resource-profiles.json"
  )[["cases"]]
  environment <- interop_prepare(".", output)
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
    stop("Resource app-stop control failed")
  }
  report[["driver_failure_control_passed"]] <- TRUE
  started <- Sys.time()
  for (selection in cases) {
    row <- interop_run_resources(
      ".",
      environment,
      transport,
      library,
      context,
      selection
    )
    report[["results"]][[length(report[["results"]]) + 1L]] <- row
    if (
      !interop_resource_row_matches(
        row,
        context,
        selection,
        environment[["lock"]]
      )
    ) {
      stop("Resource evidence did not match: ", row[["id"]])
    }
  }
  report[["case_runtime_seconds"]] <- round(
    as.numeric(difftime(Sys.time(), started, units = "secs")),
    2
  )
  openid_stop_app(transport)
  report[["cleanup_verified"]] <- TRUE
  report[["rejection_controls"]] <- interop_resource_rejections(
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
    !interop_resource_check_report(
      serialized,
      context,
      environment[["lock"]],
      cases
    )
  ) {
    stop("Serialized resource report did not match")
  }
  invalid <- serialized
  invalid[["rejection_controls"]] <- list()
  if (
    interop_resource_check_report(
      invalid,
      context,
      environment[["lock"]],
      cases
    )
  ) {
    stop("Missing resource rejection controls passed")
  }
  invalid <- serialized
  invalid[["rejection_controls"]][[1L]] <- FALSE
  if (
    interop_resource_check_report(
      invalid,
      context,
      environment[["lock"]],
      cases
    )
  ) {
    stop("False resource rejection control passed")
  }
  report[["status"]] <- "passed"
  report[["gate_passed"]] <- TRUE
  cat(
    "Resource provider gate passed:",
    length(cases),
    "browser cases;",
    length(report[["rejection_controls"]]),
    "report rejection controls\n"
  )
}

run_resource_provider_tests()
