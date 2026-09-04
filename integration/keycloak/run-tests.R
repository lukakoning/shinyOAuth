local({
  repository <- normalizePath(".", winslash = "/", mustWork = TRUE)
  dependency_libraries <- .libPaths()
  integration_library <- tempfile("shinyOAuth-integration-library-")
  dir.create(integration_library, recursive = TRUE)
  on.exit(
    unlink(integration_library, recursive = TRUE, force = TRUE),
    add = TRUE
  )

  r_binary <- file.path(
    R.home("bin"),
    if (.Platform$OS.type == "windows") "R.exe" else "R"
  )
  install_result <- processx::run(
    r_binary,
    c(
      "CMD",
      "INSTALL",
      paste0("--library=", integration_library),
      repository
    ),
    echo = TRUE,
    error_on_status = FALSE
  )
  if (!identical(install_result$status, 0L)) {
    stop(
      "R CMD INSTALL failed; integration tests were not started",
      call. = FALSE
    )
  }

  .libPaths(c(integration_library, dependency_libraries))
  expected_package_path <- normalizePath(
    file.path(integration_library, "shinyOAuth"),
    winslash = "/",
    mustWork = TRUE
  )
  loaded_package_path <- normalizePath(
    find.package("shinyOAuth"),
    winslash = "/",
    mustWork = TRUE
  )
  if (!identical(loaded_package_path, expected_package_path)) {
    stop(
      "Integration tests did not resolve shinyOAuth from the fresh library",
      call. = FALSE
    )
  }

  integration_library_path <- paste(.libPaths(), collapse = .Platform$path.sep)
  Sys.setenv(
    R_LIBS = integration_library_path,
    R_LIBS_USER = integration_library_path
  )

  options(shinyOAuth.allow_insecure_oidc_loopback = TRUE)

  results <- testthat::test_dir(
    "integration/keycloak",
    stop_on_failure = TRUE
  )

  skip_budget_text <- Sys.getenv("SHINYOAUTH_INT_MAX_SKIPS", unset = "0")
  skip_budget <- suppressWarnings(as.integer(skip_budget_text))
  if (
    is.na(skip_budget) ||
      skip_budget < 0L ||
      !identical(as.character(skip_budget), skip_budget_text)
  ) {
    stop(
      "SHINYOAUTH_INT_MAX_SKIPS must be a non-negative integer",
      call. = FALSE
    )
  }

  summary <- as.data.frame(results)
  skip_count <- sum(summary$skipped)
  message(
    "[run-integration] Skip budget: ",
    skip_count,
    "/",
    skip_budget
  )
  if (skip_count > skip_budget) {
    skipped_tests <- summary$test[summary$skipped]
    stop(
      paste0(
        "Integration skip budget exceeded (",
        skip_count,
        "/",
        skip_budget,
        "): ",
        paste(skipped_tests, collapse = "; ")
      ),
      call. = FALSE
    )
  }
})
