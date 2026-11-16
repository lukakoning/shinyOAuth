run_conformance_tests <- function() {
  Sys.setenv(CURL_SSL_BACKEND = "openssl", NOT_CRAN = "true")
  root <- normalizePath(".", winslash = "/")
  artifacts <- Sys.getenv(
    "SHINYOAUTH_CONFORMANCE_ARTIFACTS",
    unset = file.path(root, "integration/conformance/.artifacts")
  )
  dir.create(artifacts, recursive = TRUE, showWarnings = FALSE)
  output <- tempfile(
    paste0("tests-", format(Sys.time(), "%Y%m%d-%H%M%S", tz = "UTC"), "-"),
    tmpdir = artifacts
  )
  dir.create(output)
  report <- list(
    schema_version = 1L,
    status = "failed",
    scope = "independent_python_fixture",
    coverage_complete = FALSE
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
  report[["checkout_revision"]] <- trimws(processx::run(
    "git",
    c("rev-parse", "HEAD")
  )[["stdout"]])
  report[["checkout_dirty"]] <- nzchar(trimws(processx::run(
    "git",
    c("status", "--porcelain")
  )[["stdout"]]))
  report[["r_version"]] <- as.character(getRversion())
  library_path <- file.path(output, "library")
  dir.create(library_path)
  executable <- file.path(
    R.home("bin"),
    if (.Platform[["OS.type"]] == "windows") "R.exe" else "R"
  )
  installed <- processx::run(
    executable,
    c("CMD", "INSTALL", paste0("--library=", library_path), root),
    stdout = file.path(output, "install.log"),
    stderr = file.path(output, "install.stderr"),
    error_on_status = FALSE,
    timeout = 180000
  )
  if (installed[["status"]] != 0L) {
    stop("Checkout installation failed; inspect the private install log")
  }
  withr::local_libpaths(c(library_path, .libPaths()))
  withr::local_envvar(
    R_LIBS = paste(.libPaths(), collapse = .Platform[["path.sep"]])
  )
  library("shinyOAuth", lib.loc = library_path)
  report[["dependency_versions"]] <- as.list(vapply(
    c("openssl", "httr2", "mirai", "testthat", "S7"),
    function(package) as.character(utils::packageVersion(package)),
    character(1)
  ))
  python <- Sys.getenv("SHINYOAUTH_TEST_PYTHON", unset = Sys.which("python"))
  report[["python_cryptography_version"]] <- trimws(processx::run(
    python,
    c("-c", "import cryptography; print(cryptography.__version__)")
  )[["stdout"]])
  report[["package_version"]] <- as.character(utils::packageVersion(
    "shinyOAuth"
  ))
  report[["package_matches"]] <- identical(
    normalizePath(
      getNamespaceInfo(asNamespace("shinyOAuth"), "path"),
      winslash = "/"
    ),
    normalizePath(file.path(library_path, "shinyOAuth"), winslash = "/")
  )
  if (!isTRUE(report[["package_matches"]])) {
    stop("Tests must load this checkout's private installation")
  }
  results <- testthat::test_dir(
    "integration/conformance",
    reporter = "summary",
    stop_on_failure = FALSE,
    stop_on_warning = FALSE
  )
  summary <- as.data.frame(results)
  report[["tests"]] <- lapply(seq_len(nrow(summary)), function(i) {
    list(
      file = basename(summary[["file"]][[i]]),
      assertions = summary[["nb"]][[i]],
      failed = summary[["failed"]][[i]],
      error = summary[["error"]][[i]],
      warnings = summary[["warning"]][[i]],
      skipped = summary[["skipped"]][[i]]
    )
  })
  if (
    !nrow(summary) ||
      !sum(summary[["nb"]]) ||
      any(
        summary[["failed"]] > 0L |
          summary[["error"]] |
          summary[["warning"]] > 0L |
          summary[["skipped"]]
      )
  ) {
    stop(
      "Independent fixture requires passing assertions with zero errors, warnings or skips"
    )
  }
  report[["status"]] <- "passed"
  cat("Independent fixture passed:", sum(summary[["nb"]]), "assertions.\n")
  invisible(results)
}

run_conformance_tests()
