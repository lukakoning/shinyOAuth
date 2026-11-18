source_test_repo <- function(root) {
  dir.create(file.path(root, "R"))
  writeLines(
    c(
      "Package: shinyOAuth",
      "Version: 0.0.0.9000",
      "Title: Source Identity Fixture",
      "Description: Minimal package for testing installation source identity.",
      "Authors@R: person('Test', 'Author', email = 'test@example.com', role = c('aut', 'cre'))",
      "License: MIT + file LICENSE",
      "Encoding: UTF-8"
    ),
    file.path(root, "DESCRIPTION")
  )
  writeLines(
    c("YEAR: 2026", "COPYRIGHT HOLDER: Test Author"),
    file.path(root, "LICENSE")
  )
  writeLines("export(source_value)", file.path(root, "NAMESPACE"))
  writeLines(
    'source_value <- function() "committed"',
    file.path(root, "R/value.R")
  )
  writeLines("R/zz-ignored.R", file.path(root, ".gitignore"))
  git <- function(args) processx::run("git", args, wd = root)
  git(c("init", "--quiet"))
  git(c("add", "."))
  git(c(
    "-c",
    "user.name=Source Test",
    "-c",
    "user.email=test@example.com",
    "commit",
    "--quiet",
    "-m",
    "fixture"
  ))
  invisible(root)
}

source_evidence_fixture <- function(f = evidence_fixture(), dirty = FALSE) {
  hashes <- list(
    "R/client.R" = strrep("c", 64),
    "integration/openid/fixture-app.R" = strrep("d", 64)
  )
  source <- list(
    kind = if (dirty) "dirty_development" else "clean_checkout",
    revision = f[["context"]][["checkout_revision"]],
    tree = strrep("b", 40),
    dirty = dirty,
    index_masked = FALSE,
    files = hashes,
    fingerprint = openid_hash_manifest(hashes)
  )
  files <- list(
    "DESCRIPTION" = strrep("a", 64),
    "R/shinyOAuth.rdb" = strrep("f", 64)
  )
  installation <- list(
    revision = source[["revision"]],
    tree = source[["tree"]],
    source_fingerprint = source[["fingerprint"]],
    method = if (dirty) "working_tree_build" else "git_archive",
    archive_sha256 = strrep("e", 64),
    package_version = f[["context"]][["package_version"]],
    files = files,
    fingerprint = openid_hash_manifest(files)
  )
  for (name in c("report", "context")) {
    f[[name]][["schema_version"]] <- 4L
    f[[name]][["checkout_dirty"]] <- dirty
    f[[name]][["checkout_source"]] <- source
    f[[name]][["installation"]] <- installation
  }
  f[["report"]][["checkout_source_after"]] <- source
  f[["report"]][["source_verified"]] <- TRUE
  f[["report"]][["installation_after"]] <- installation
  f[["report"]][["status"]] <- "passed"
  f[["report"]][["gate_passed"]] <- TRUE
  for (i in seq_along(f[["report"]][["selections"]])) {
    child <- f[["report"]][["selections"]][[i]]
    f[["report"]][["selections"]][[i]] <- source_evidence_fixture(
      list(report = child, context = child, manifest = f[["manifest"]]),
      dirty
    )[["report"]]
  }
  f
}

testthat::test_that("source fingerprints catch modified, missing and newly added inputs", {
  root <- withr::local_tempdir("openid-source-")
  source_test_repo(root)
  original <- openid_source_identity(root)
  testthat::expect_false(original[["dirty"]])
  testthat::expect_true(openid_source_record_valid(original))
  testthat::expect_identical(openid_assert_source(root, original), original)
  writeLines("changed", file.path(root, "R/value.R"))
  testthat::expect_error(openid_assert_source(root, original), "source changed")
  dirty <- openid_source_identity(root)
  testthat::expect_true(dirty[["dirty"]])
  testthat::expect_true(openid_source_record_valid(dirty))
  writeLines("changed again", file.path(root, "R/value.R"))
  testthat::expect_error(openid_assert_source(root, dirty), "source changed")
  unlink(file.path(root, "R/value.R"))
  testthat::expect_identical(
    openid_source_identity(root)[["files"]][["R/value.R"]],
    "missing"
  )
  writeLines("new input", file.path(root, "R/new file.R"))
  testthat::expect_error(openid_assert_source(root, dirty), "source changed")
  testthat::expect_true(
    "R/new file.R" %in% names(openid_source_identity(root)[["files"]])
  )
})

testthat::test_that("index flags cannot conceal development source from release policy", {
  root <- withr::local_tempdir("openid-source-masked-")
  source_test_repo(root)
  processx::run(
    "git",
    c("update-index", "--assume-unchanged", "R/value.R"),
    wd = root
  )
  writeLines(
    'source_value <- function() "hidden change"',
    file.path(root, "R/value.R")
  )
  testthat::expect_true(openid_source_identity(root)[["index_masked"]])
  testthat::expect_true(openid_source_identity(root)[["dirty"]])
  processx::run(
    "git",
    c("update-index", "--no-assume-unchanged", "R/value.R"),
    wd = root
  )
  writeLines(
    'source_value <- function() "committed"',
    file.path(root, "R/value.R")
  )
  processx::run(
    "git",
    c("update-index", "--skip-worktree", "R/value.R"),
    wd = root
  )
  testthat::expect_true(openid_source_identity(root)[["index_masked"]])
  testthat::expect_identical(
    openid_source_identity(root)[["kind"]],
    "dirty_development"
  )
})

testthat::test_that("clean installation uses committed input and detects later package changes", {
  root <- withr::local_tempdir("openid-source-install-")
  output <- withr::local_tempdir("openid-source-output-")
  source_test_repo(root)
  writeLines(
    'source_value <- function() "ignored"',
    file.path(root, "R/zz-ignored.R")
  )
  source <- openid_source_identity(root)
  testthat::expect_false(source[["dirty"]])
  library <- openid_install(root, output, source)
  record <- openid_installation(library, source)
  testthat::expect_identical(record[["method"]], "git_archive")
  testthat::expect_false(any(grepl(
    "zz-ignored",
    utils::untar(file.path(output, "checkout-source.tar"), list = TRUE)
  )))
  value <- callr::r(
    function() getExportedValue("shinyOAuth", "source_value")(),
    libpath = c(library, .libPaths())
  )
  testthat::expect_identical(value, "committed")
  testthat::expect_identical(
    record[["archive_sha256"]],
    openid_file_hash(file.path(output, "checkout-source.tar"))
  )
  reproduced <- file.path(output, "reproduced.tar")
  withr::with_envvar(
    c(
      GIT_CONFIG_COUNT = "1",
      GIT_CONFIG_KEY_0 = "tar.umask",
      GIT_CONFIG_VALUE_0 = "0077"
    ),
    openid_git_archive(root, reproduced, source[["revision"]])
  )
  testthat::expect_identical(
    openid_file_hash(reproduced),
    record[["archive_sha256"]]
  )
  cat(
    "changed archive",
    file = file.path(output, "checkout-source.tar"),
    append = TRUE
  )
  testthat::expect_error(
    openid_installation(library, source),
    "no longer matches"
  )
  file.copy(
    reproduced,
    file.path(output, "checkout-source.tar"),
    overwrite = TRUE
  )
  testthat::expect_identical(openid_installation(library, source), record)
  cat(
    "\nchanged installation\n",
    file = file.path(library, "shinyOAuth/NAMESPACE"),
    append = TRUE
  )
  testthat::expect_error(
    openid_installation(library, source),
    "no longer matches"
  )
})

testthat::test_that("development installation records the actual built archive", {
  root <- withr::local_tempdir("openid-source-development-")
  output <- withr::local_tempdir("openid-source-output-")
  source_test_repo(root)
  writeLines(
    'source_value <- function() "development"',
    file.path(root, "R/value.R")
  )
  source <- openid_source_identity(root)
  testthat::expect_true(source[["dirty"]])
  library <- openid_install(root, output, source)
  record <- openid_installation(library, source)
  testthat::expect_identical(record[["method"]], "working_tree_build")
  value <- callr::r(
    function() getExportedValue("shinyOAuth", "source_value")(),
    libpath = c(library, .libPaths())
  )
  testthat::expect_identical(value, "development")
  testthat::expect_identical(
    record[["archive_sha256"]],
    openid_file_hash(file.path(output, "checkout-source.tar.gz"))
  )
})

testthat::test_that("schema 4 binds serialized source and installation evidence to the run", {
  f <- source_evidence_fixture()
  check <- function(report) {
    openid_check_report(report, f[["context"]], f[["manifest"]])[[
      "gate_passed"
    ]]
  }
  report <- jsonlite::fromJSON(
    jsonlite::toJSON(f[["report"]], auto_unbox = TRUE, null = "null"),
    simplifyVector = FALSE
  )
  testthat::expect_true(check(report))
  for (name in c(
    "checkout_source",
    "checkout_source_after",
    "source_verified",
    "installation",
    "installation_after"
  )) {
    changed <- report
    changed[[name]] <- NULL
    testthat::expect_false(check(changed))
  }
  for (field in c("checkout_source", "checkout_source_after")) {
    for (name in names(report[[field]])) {
      changed <- report
      changed[[field]][[name]] <- NULL
      testthat::expect_false(check(changed))
    }
  }
  for (field in c("installation", "installation_after")) {
    for (name in names(report[[field]])) {
      changed <- report
      changed[[field]][[name]] <- NULL
      testthat::expect_false(check(changed))
    }
  }
  changed <- report
  changed[["source_verified"]] <- FALSE
  testthat::expect_false(check(changed))
  changed <- report
  changed[["schema_version"]] <- 3L
  testthat::expect_false(check(changed))
  development <- source_evidence_fixture(dirty = TRUE)
  testthat::expect_true(openid_check_report(
    development[["report"]],
    development[["context"]],
    development[["manifest"]]
  )[["gate_passed"]])
})

testthat::test_that("release source policy rejects dirty, mixed, old and unidentified evidence", {
  f <- source_evidence_fixture()
  report <- f[["report"]]
  revision <- report[["checkout_revision"]]
  tree <- report[["checkout_source"]][["tree"]]
  check <- function(reports) {
    openid_release_source_matches(
      reports,
      revision,
      tree,
      report[["installation"]][["archive_sha256"]]
    )
  }
  testthat::expect_true(check(list(report)))
  testthat::expect_true(check(list(report, report)))
  testthat::expect_false(check(list()))
  testthat::expect_false(check(list(evidence_fixture()[["report"]])))
  testthat::expect_false(check(list(source_evidence_fixture(dirty = TRUE)[[
    "report"
  ]])))
  for (field in c(
    "checkout_source",
    "checkout_source_after",
    "source_verified",
    "installation",
    "installation_after",
    "results"
  )) {
    changed <- report
    changed[[field]] <- NULL
    testthat::expect_false(check(list(changed)))
  }
  changed <- report
  changed[["checkout_revision"]] <- strrep("f", 40)
  testthat::expect_false(check(list(report, changed)))
  changed <- report
  changed[["checkout_source"]][["tree"]] <- strrep("f", 40)
  testthat::expect_false(check(list(changed)))
  changed <- report
  changed[["checkout_source_after"]][["files"]][[1L]] <- strrep("a", 64)
  testthat::expect_false(check(list(changed)))
  changed <- report
  changed[["installation_after"]][["files"]][[1L]] <- strrep("c", 64)
  testthat::expect_false(check(list(changed)))
  changed <- report
  changed[["installation"]][["archive_sha256"]] <- strrep("a", 64)
  changed[["installation_after"]] <- changed[["installation"]]
  testthat::expect_false(check(list(changed)))
})

testthat::test_that("shared-pool source evidence binds every selection and its installation", {
  f <- source_evidence_fixture(shared_evidence_fixture())
  check <- function(report) {
    openid_check_shared_report(report, f[["context"]], f[["manifest"]])[[
      "gate_passed"
    ]]
  }
  testthat::expect_true(check(f[["report"]]))
  testthat::expect_true(openid_release_source_matches(
    list(f[["report"]]),
    f[["report"]][["checkout_revision"]],
    f[["report"]][["checkout_source"]][["tree"]],
    f[["report"]][["installation"]][["archive_sha256"]]
  ))
  for (i in seq_along(f[["report"]][["selections"]])) {
    for (name in c(
      "checkout_source",
      "checkout_source_after",
      "installation",
      "installation_after",
      "source_verified"
    )) {
      changed <- f[["report"]]
      changed[["selections"]][[i]][[name]] <- NULL
      testthat::expect_false(check(changed))
      testthat::expect_false(openid_release_source_matches(
        list(changed),
        f[["report"]][["checkout_revision"]],
        f[["report"]][["checkout_source"]][["tree"]],
        f[["report"]][["installation"]][["archive_sha256"]]
      ))
    }
  }
})
