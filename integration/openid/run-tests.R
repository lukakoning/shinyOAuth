run_openid_tests <- function(args = commandArgs(trailingOnly = TRUE)) {
  api_mode <- identical(args, "--check-api")
  if (!api_mode) {
    valid <- length(args) == 4L &&
      !anyDuplicated(args[c(1L, 3L)]) &&
      setequal(args[c(1L, 3L)], c("--profile", "--transport"))
    if (!valid) {
      stop(
        "Usage: Rscript integration/openid/run-tests.R --check-api | --profile smoke|basic|config|form-post|form-post-cross-site|refresh|auth-post|comprehensive-userinfo|auth-secret-jwt|auth-private-jwt|fapi-dpop|fapi-dpop-full|fapi-oauth-dpop|fapi-oauth-dpop-reference|fapi-oauth-mtls|fapi-oauth-mtls-auth|fapi-mtls|fapi-mtls-auth|fapi-message-signing --transport sync|mirai|future"
      )
    }
    options <- setNames(args[c(2L, 4L)], args[c(1L, 3L)])
    if (
      !options[["--profile"]] %in%
        c(
          "smoke",
          "basic",
          "config",
          "form-post",
          "form-post-cross-site",
          "refresh",
          "auth-post",
          "comprehensive-userinfo",
          "auth-secret-jwt",
          "auth-private-jwt",
          "fapi-dpop",
          "fapi-dpop-full",
          "fapi-oauth-dpop",
          "fapi-oauth-dpop-reference",
          "fapi-oauth-mtls",
          "fapi-oauth-mtls-auth",
          "fapi-mtls",
          "fapi-mtls-auth",
          "fapi-message-signing"
        ) ||
        !options[["--transport"]] %in% c("sync", "mirai", "future") ||
        (identical(options[["--transport"]], "future") &&
          !options[["--profile"]] %in% c("smoke", "refresh"))
    ) {
      stop(
        "Use sync/mirai for core profiles, or future for smoke/refresh parity selections"
      )
    }
  }
  Sys.setenv(CURL_SSL_BACKEND = "openssl")
  source("integration/openid/helper-environment.R", local = TRUE)
  source("integration/openid/helper-source.R", local = TRUE)
  source("integration/openid/helper-suite.R", local = TRUE)
  source("integration/openid/helper-evidence.R", local = TRUE)
  source("integration/openid/helper-configuration.R", local = TRUE)
  source("integration/openid/helper-auth.R", local = TRUE)
  source("integration/openid/helper-fapi.R", local = TRUE)
  source("integration/openid/helper-signing.R", local = TRUE)
  source("integration/openid/helper-mtls.R", local = TRUE)
  source("integration/openid/helper-app.R", local = TRUE)
  source("integration/openid/helper-driver.R", local = TRUE)
  openid_require(c(
    "httr2",
    "jsonlite",
    "processx",
    "openssl",
    "withr",
    "httpuv",
    "testthat",
    "ps",
    "jose",
    "callr"
  ))
  profile <- if (api_mode) "api" else options[["--profile"]]
  output <- openid_output(".", profile)
  report <- list(
    schema_version = 4L,
    status = "failed",
    application_flow = "not_attempted",
    gate_passed = FALSE,
    coverage_complete = FALSE,
    upstream_plan_complete = FALSE,
    assessment = openid_failed_assessment()[["assessment"]]
  )
  source <- openid_source_identity(".")
  report[["checkout_source"]] <- source
  report[["checkout_revision"]] <- source[["revision"]]
  report[["checkout_dirty"]] <- source[["dirty"]]
  report[["source_verified"]] <- FALSE
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
  library <- openid_install(".", output, source)
  installation <- report[["installation"]] <- openid_use_installation(
    library,
    source
  )
  checks <- testthat::test_file(
    "integration/openid/test-evidence.R",
    env = environment(),
    reporter = "summary",
    stop_on_failure = TRUE,
    stop_on_warning = TRUE
  )
  if (any(as.data.frame(checks)[["skipped"]])) {
    stop("OpenID evidence checks require zero skips")
  }
  openid_assert_source(".", source)
  regression_installation <- report[[
    "regression_installation_after"
  ]] <- openid_use_installation(library, source, installation)
  manifest <- openid_profiles()
  if (!api_mode) {
    openid_require(c("shiny", "chromote"))
    if (!identical(options[["--transport"]], "sync")) {
      openid_require(c(options[["--transport"]], "promises", "later"))
    }
    report <- openid_report_context(
      ".",
      profile,
      options[["--transport"]],
      read.dcf("DESCRIPTION")[[1L, "Version"]]
    )
    if (!identical(report[["checkout_source"]], source)) {
      stop("Checkout source changed during regression checks")
    }
    report[["installation"]] <- installation
    report[["regression_installation_after"]] <- regression_installation
    context <- report
    stack <- openid_start(".", output)
    transport <- openid_app_transport(
      ".",
      stack,
      httpuv::randomPort(),
      host = if (identical(profile, "form-post-cross-site")) {
        "127.0.0.1"
      } else {
        "localhost"
      }
    )
    context[["provider_origin"]] <- report[["provider_origin"]] <- stack[[
      "origin"
    ]]
    context[["app_origin"]] <- report[["app_origin"]] <- transport[["origin"]]
    if (startsWith(profile, "auth-")) {
      report[["public_client_capability"]] <- openid_public_capability(
        stack,
        manifest,
        context,
        paste0(transport[["origin"]], "/"),
        library
      )
      for (name in c("plan_id", "suite_id")) {
        context[[paste0("public_probe_", name)]] <- report[[paste0(
          "public_probe_",
          name
        )]] <- report[["public_client_capability"]][[name]]
      }
    }
    report[["driver_failure_control_passed"]] <- openid_driver_failure_control(
      ".",
      stack,
      manifest,
      context,
      transport,
      library
    )
    if (identical(profile, "config")) {
      report[["jwks_cache_policy"]] <- openid_suite_cache_policy(
        stack,
        manifest,
        paste0(transport[["origin"]], "/")
      )
    }
    plan <- openid_suite_plan(
      stack,
      manifest,
      paste0(transport[["origin"]], "/"),
      profile
    )
    context[["plan_id"]] <- plan[["id"]]
    report[["plan_id"]] <- plan[["id"]]
    context[["images"]] <- report[["images"]] <- stack[["lock"]][["images"]]
    context[["image_sources"]] <- report[["image_sources"]] <- stack[[
      "image_sources"
    ]]
    started <- Sys.time()
    for (expectation in manifest[["profiles"]][[profile]][["modules"]]) {
      row <- openid_run_case(
        ".",
        stack,
        plan,
        expectation,
        context,
        transport,
        library
      )
      report[["results"]][[length(report[["results"]]) + 1L]] <- row
      checks <- c(
        app = openid_case_app_matches(
          row,
          expectation,
          paste0(context[["run_id"]], "-", row[["suite_id"]]),
          context[["package_version"]]
        ),
        transport = openid_transport_matches(row, expectation, context)
      )
      if (openid_fapi_plan(plan[["spec"]][["plan"]])) {
        checks[["fapi"]] <- openid_fapi_matches(row, expectation)
      }
      if (!all(checks)) {
        stop(
          "Invalid ",
          paste(names(checks)[!checks], collapse = "/"),
          " evidence for ",
          expectation[["module"]]
        )
      }
    }
    report[["module_runtime_seconds"]] <- round(
      as.numeric(difftime(Sys.time(), started, units = "secs")),
      2
    )
    if (
      identical(plan[["spec"]][["plan_variant"]][["sender_constrain"]], "mtls")
    ) {
      report[["mtls_controls"]] <- openid_mtls_controls(
        ".",
        stack,
        plan,
        manifest[["profiles"]][[profile]][["modules"]][[1L]],
        context,
        transport,
        library
      )
    }
    openid_stop_app(transport)
    openid_stop(stack)
    report[["cleanup_verified"]] <- TRUE
    report[["checkout_source_after"]] <- openid_assert_source(
      ".",
      context[["checkout_source"]]
    )
    report[["source_verified"]] <- TRUE
    report[["installation_after"]] <- openid_use_installation(
      library,
      context[["checkout_source"]],
      installation
    )
    check <- openid_check_report(report, context, manifest)
    report[names(check)] <- check
    if (!isTRUE(check[["gate_passed"]])) {
      stop("OpenID ", profile, " gate failed: ", check[["reason"]])
    }
    report[["status"]] <- "passed"
    cat(
      "OpenID ",
      profile,
      " selection passed; upstream_plan_complete = ",
      check[["upstream_plan_complete"]],
      "; coverage_complete = ",
      check[["coverage_complete"]],
      ".\n",
      sep = ""
    )
    return(invisible(report))
  }
  stack <- openid_start(".", output)
  report[["plan_inventory"]] <- openid_suite_inventory(
    stack,
    manifest,
    "https://localhost:58100/"
  )
  report[["images"]] <- stack[["lock"]][["images"]]
  report[["image_sources"]] <- stack[["image_sources"]]
  plan <- openid_suite_plan(stack, manifest, "https://localhost:58100/")
  module <- openid_suite_module(stack, plan, "oidcc-client-test")
  stopifnot(identical(openid_suite_info(stack, module)[["status"]], "WAITING"))
  unknown <- module
  unknown[["id"]] <- "UnknownOpenIDInstance"
  failure <- tryCatch(openid_suite_info(stack, unknown), error = identity)
  stopifnot(
    inherits(failure, "openid_http_error"),
    identical(failure[["status"]], 404L)
  )
  openid_suite_cancel(stack, module)
  stopifnot(identical(
    openid_suite_info(stack, module)[["status"]],
    "INTERRUPTED"
  ))
  openid_stop(stack)
  report[["checkout_source_after"]] <- openid_assert_source(".", source)
  report[["installation_after"]] <- openid_use_installation(
    library,
    source,
    installation
  )
  report[["source_verified"]] <- TRUE
  report[["source_revision"]] <- manifest[["source_revision"]]
  report[["api_checks"]] <- list(
    plan_created = TRUE,
    module_waiting = TRUE,
    exported_issuer_checked = TRUE,
    unknown_instance_rejected = TRUE,
    cancellation_verified = TRUE
  )
  report[["cleanup_verified"]] <- TRUE
  report[["status"]] <- "passed"
  cat(
    "OpenID API and evidence checks passed; client conformance not attempted.\n"
  )
}
run_openid_tests()
