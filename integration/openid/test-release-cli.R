release_cli_test_fixture <- function(root, evidence_root) {
  source_test_repo(root)
  original_revision <- openid_source_identity(root)[["revision"]]
  directory <- file.path(root, "integration/openid")
  dir.create(directory, recursive = TRUE)
  helpers <- c(
    "environment",
    "source",
    "suite",
    "evidence",
    "auth",
    "shared-pool",
    "fapi",
    "signing",
    "mtls",
    "release"
  )
  files <- c(
    paste0("helper-", helpers, ".R"),
    "run-release-check.R",
    "profiles.json",
    "suite-lock.json"
  )
  stopifnot(all(file.copy(files, directory)))
  matrix <- release_matrix_test_matrix(list(c("smoke", "sync")))
  jsonlite::write_json(
    matrix,
    file.path(directory, "release-matrix.json"),
    auto_unbox = TRUE
  )
  processx::run("git", c("add", "."), wd = root)
  processx::run(
    "git",
    c(
      "-c",
      "user.name=Release Test",
      "-c",
      "user.email=test@example.com",
      "commit",
      "--quiet",
      "-m",
      "declare fixture policy"
    ),
    wd = root
  )
  source <- openid_source_identity(root)
  archive <- tempfile("openid-release-cli-fixture-", fileext = ".tar")
  on.exit(unlink(archive), add = TRUE)
  openid_git_archive(root, archive, source[["revision"]])
  version <- read.dcf(file.path(root, "DESCRIPTION"))[[1L, "Version"]]
  rebind <- function(value) {
    if (!is.list(value)) {
      return(value)
    }
    value <- lapply(value, rebind)
    if ("checkout_revision" %in% names(value)) {
      value[["checkout_revision"]] <- source[["revision"]]
    }
    if ("package_version" %in% names(value)) {
      value[["package_version"]] <- version
    }
    value
  }
  report <- rebind(release_matrix_test_report())
  report[["checkout_source"]] <- report[["checkout_source_after"]] <- source
  installation <- report[["installation"]]
  installation[["revision"]] <- source[["revision"]]
  installation[["tree"]] <- source[["tree"]]
  installation[["source_fingerprint"]] <- source[["fingerprint"]]
  installation[["archive_sha256"]] <- openid_file_hash(archive)
  for (name in c(
    "installation",
    "regression_installation_after",
    "installation_after"
  )) {
    report[[name]] <- installation
  }
  check <- openid_check_report(report, report, openid_profiles(root))
  stopifnot(isTRUE(check[["gate_passed"]]))
  report <- release_matrix_test_store_check(report, check)
  evidence <- file.path(evidence_root, "evidence.json")
  jsonlite::write_json(
    report,
    evidence,
    auto_unbox = TRUE,
    pretty = TRUE,
    null = "null"
  )
  matrix_blob <- tempfile("openid-release-cli-matrix-", fileext = ".json")
  on.exit(unlink(matrix_blob), add = TRUE)
  processx::run(
    "git",
    c(
      "show",
      paste0(source[["revision"]], ":integration/openid/release-matrix.json")
    ),
    wd = root,
    stdout = matrix_blob
  )
  list(
    root = root,
    evidence_root = evidence_root,
    revision = source[["revision"]],
    original_revision = original_revision,
    evidence = evidence,
    report = report,
    matrix_sha256 = openid_file_hash(matrix_blob)
  )
}

release_cli_test_run <- function(f, output, revision = f[["revision"]]) {
  executable <- file.path(
    R.home("bin"),
    if (.Platform$OS.type == "windows") "Rscript.exe" else "Rscript"
  )
  processx::run(
    executable,
    c(
      "integration/openid/run-release-check.R",
      "--revision",
      revision,
      "--output",
      output,
      f[["evidence"]]
    ),
    wd = f[["root"]],
    error_on_status = FALSE
  )
}

testthat::test_that("release CLI reads committed policy and hashes original JSON bytes", {
  root <- withr::local_tempdir("openid-release-cli-")
  evidence_root <- withr::local_tempdir("openid-release-cli-input-")
  f <- release_cli_test_fixture(root, evidence_root)
  for (path in c("release-matrix.json", "profiles.json", "suite-lock.json")) {
    writeLines(
      "invalid later working-copy policy",
      file.path(root, "integration/openid", path)
    )
  }
  writeLines(
    c("Package: shinyOAuth", "Version: 99.0.0"),
    file.path(root, "DESCRIPTION")
  )
  output <- file.path(evidence_root, "summary.json")
  result <- release_cli_test_run(f, output)
  testthat::expect_identical(result[["status"]], 0L, info = result[["stderr"]])
  summary <- jsonlite::read_json(output)
  testthat::expect_true(summary[["matrix_complete"]])
  testthat::expect_equal(summary[["selection_count"]], 1L)
  testthat::expect_identical(summary[["package_version"]], "0.0.0.9000")
  testthat::expect_identical(summary[["matrix_sha256"]], f[["matrix_sha256"]])
  testthat::expect_identical(
    summary[["input_sha256"]],
    list(openid_file_hash(f[["evidence"]]))
  )
  testthat::expect_identical(
    summary[["requested_source"]][["revision"]],
    f[["revision"]]
  )
  testthat::expect_identical(
    summary[["entries"]][[1L]][["report_sha256"]],
    openid_file_hash(f[["evidence"]])
  )
  testthat::expect_identical(summary[["platform_coverage"]], "not_assessed")
  testthat::expect_identical(
    summary[["artifact_authentication"]],
    "not_assessed"
  )
  testthat::expect_identical(summary[["durable_retention"]], "not_assessed")
  testthat::expect_identical(summary[["certification_status"]], "not_assessed")
  text <- paste(readLines(output, warn = FALSE), collapse = "\n")
  testthat::expect_false(grepl(root, text, fixed = TRUE))
  testthat::expect_false(grepl(evidence_root, text, fixed = TRUE))
  testthat::expect_false(grepl("report_index", text, fixed = TRUE))
  # This is a synthetic one-cell Git fixture, not execution of the shipped matrix.
})

testthat::test_that("release CLI cannot retrofit policy or overwrite an existing input", {
  root <- withr::local_tempdir("openid-release-cli-fail-")
  evidence_root <- withr::local_tempdir("openid-release-cli-fail-input-")
  f <- release_cli_test_fixture(root, evidence_root)
  output <- file.path(evidence_root, "missing-policy-summary.json")
  result <- release_cli_test_run(f, output, f[["original_revision"]])
  testthat::expect_true(result[["status"]] != 0L)
  testthat::expect_false(file.exists(output))
  original <- openid_file_hash(f[["evidence"]])
  result <- release_cli_test_run(f, f[["evidence"]])
  testthat::expect_true(result[["status"]] != 0L)
  testthat::expect_match(result[["stderr"]], "already exists", fixed = TRUE)
  testthat::expect_identical(openid_file_hash(f[["evidence"]]), original)
})

testthat::test_that("release CLI binds package version to the selected commit", {
  root <- withr::local_tempdir("openid-release-cli-version-")
  evidence_root <- withr::local_tempdir("openid-release-cli-version-input-")
  f <- release_cli_test_fixture(root, evidence_root)
  rebind <- function(value) {
    if (!is.list(value)) {
      return(value)
    }
    value <- lapply(value, rebind)
    if ("package_version" %in% names(value)) {
      value[["package_version"]] <- "99.0.0"
    }
    value
  }
  jsonlite::write_json(
    rebind(f[["report"]]),
    f[["evidence"]],
    auto_unbox = TRUE,
    pretty = TRUE,
    null = "null"
  )
  output <- file.path(evidence_root, "version-summary.json")
  result <- release_cli_test_run(f, output)
  testthat::expect_true(result[["status"]] != 0L)
  summary <- jsonlite::read_json(output)
  testthat::expect_false(summary[["gate_passed"]])
  testthat::expect_false(summary[["matrix_complete"]])
  testthat::expect_match(summary[["reason"]], "package version", fixed = TRUE)
  testthat::expect_identical(
    summary[["input_sha256"]],
    list(openid_file_hash(f[["evidence"]]))
  )
  testthat::expect_identical(
    summary[["requested_source"]][["revision"]],
    f[["revision"]]
  )
  text <- paste(readLines(output, warn = FALSE), collapse = "\n")
  testthat::expect_false(grepl(root, text, fixed = TRUE))
  testthat::expect_false(grepl(evidence_root, text, fixed = TRUE))
})
