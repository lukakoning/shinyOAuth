run_interop_release_check <- function(args = commandArgs(TRUE)) {
  manifests <- c(
    basic = "profiles.json",
    advanced = "advanced-profiles.json",
    resources = "resource-profiles.json",
    retention = "retention-profiles.json"
  )
  if (
    length(args) != 7L ||
      !identical(
        args[c(1L, 3L, 5L)],
        c("--revision", "--profile", "--transport")
      ) ||
      !grepl("^[a-f0-9]{40}$", args[[2L]]) ||
      !args[[4L]] %in% names(manifests) ||
      !args[[6L]] %in% c("sync", "mirai")
  ) {
    stop(
      paste(
        "Usage: Rscript integration/oidc-provider/run-release-check.R",
        "--revision COMMIT --profile basic|advanced|resources|retention",
        "--transport sync|mirai evidence.json"
      )
    )
  }
  for (name in c("environment", "suite", "source", "evidence", "fapi")) {
    source(paste0("integration/openid/helper-", name, ".R"), local = TRUE)
  }
  for (name in c(
    "environment",
    "evidence",
    "advanced-evidence",
    "resource-evidence",
    "retention-evidence"
  )) {
    source(
      paste0("integration/oidc-provider/helper-", name, ".R"),
      local = TRUE
    )
  }
  openid_require(c("jsonlite", "openssl", "processx"))

  revision <- args[[2L]]
  profile <- args[[4L]]
  transport <- args[[6L]]
  report <- jsonlite::read_json(args[[7L]])
  unique_keys <- function(value) {
    !is.list(value) ||
      (!anyDuplicated(names(value)) &&
        all(vapply(value, unique_keys, logical(1))))
  }
  if (!unique_keys(report)) {
    stop("Provider report contains duplicate JSON object keys")
  }
  if (
    !is.list(report) ||
      !identical(report[["schema_version"]], 2L) ||
      !identical(report[["status"]], "passed") ||
      !isTRUE(report[["gate_passed"]]) ||
      !identical(report[["checkout_revision"]], revision) ||
      !identical(report[["checkout_dirty"]], FALSE) ||
      !identical(report[["transport"]], transport)
  ) {
    stop(
      "Expected a passing schema-2 provider report from the selected clean revision and transport"
    )
  }
  openid_check_source(report, report)
  tree <- trimws(processx::run(
    "git",
    c("rev-parse", paste0(revision, "^{tree}"))
  )[["stdout"]])
  temporary <- tempfile("oidc-provider-release-")
  dir.create(temporary)
  on.exit(unlink(temporary, recursive = TRUE), add = TRUE)
  checkout_files <- report[["checkout_source"]][["files"]]
  inventory <- file.path(temporary, "tree-paths")
  processx::run(
    "git",
    c("ls-tree", "-r", "--name-only", "-z", revision),
    stdout = inventory
  )
  committed_files <- readBin(
    inventory,
    "character",
    n = length(checkout_files) + 1L
  )
  if (!setequal(committed_files, names(checkout_files))) {
    stop("Provider checkout inventory differs from the selected commit")
  }
  archive <- file.path(temporary, "source.tar")
  openid_git_archive(".", archive, revision)
  if (
    !identical(report[["checkout_source"]][["tree"]], tree) ||
      !identical(
        report[["installation"]][["archive_sha256"]],
        openid_file_hash(archive)
      )
  ) {
    stop(
      "Provider source tree or installation archive differs from the selected commit"
    )
  }

  provider <- "integration/oidc-provider"
  fixtures <- interop_fixture_files()
  paths <- file.path(provider, fixtures)
  manifest <- file.path(provider, manifests[[profile]])
  dir.create(file.path(temporary, provider), recursive = TRUE)
  for (name in c("DESCRIPTION", paths, manifest)) {
    processx::run(
      "git",
      c("show", paste0(revision, ":", name)),
      stdout = file.path(temporary, name)
    )
  }
  description <- read.dcf(file.path(temporary, "DESCRIPTION"))
  if (!identical(report[["package_version"]], description[[1L, "Version"]])) {
    stop("Provider report package version differs from the selected commit")
  }
  hashes <- setNames(unname(checkout_files[paths]), fixtures)
  if (
    !is.list(report[["source_hashes"]]) ||
      length(report[["source_hashes"]]) != length(fixtures) ||
      !identical(report[["source_hashes"]][fixtures], hashes)
  ) {
    stop("Provider fixture hashes differ from the recorded checkout")
  }
  for (i in seq_along(paths)) {
    path <- file.path(temporary, paths[[i]])
    hash <- hashes[[i]]
    if (!identical(hash, openid_file_hash(path))) {
      # Git can materialize the fixture text with CRLF on Windows.
      blob <- rawToChar(readBin(path, "raw", n = file.info(path)[["size"]]))
      crlf <- gsub("(?<!\\r)\\n", "\r\n", blob, perl = TRUE, useBytes = TRUE)
      if (
        !identical(hash, paste(openssl::sha256(charToRaw(crlf)), collapse = ""))
      ) {
        stop("Provider fixture differs from the selected commit: ", paths[[i]])
      }
    }
  }

  lock <- interop_lock(temporary)
  cases <- jsonlite::read_json(file.path(temporary, manifest))[["cases"]]
  validators <- switch(
    profile,
    basic = list(
      check = interop_check_report,
      replay = interop_rejection_controls
    ),
    advanced = list(
      check = interop_advanced_check_report,
      replay = interop_advanced_rejections
    ),
    resources = list(
      check = interop_resource_check_report,
      replay = interop_resource_rejections
    ),
    retention = list(
      check = interop_retention_check_report,
      replay = interop_retention_rejections
    )
  )
  if (!validators[["check"]](report, report, lock, cases)) {
    stop(
      "Provider report does not match the selected profile and committed policy"
    )
  }
  controls <- validators[["replay"]](report, report, lock, cases)
  if (!identical(report[["rejection_controls"]][names(controls)], controls)) {
    stop("Provider report rejection controls differ from the replay")
  }
  cat(
    "Verified oidc-provider ",
    profile,
    "/",
    transport,
    " at ",
    revision,
    " (",
    length(report[["results"]]),
    " cases and ",
    length(controls),
    " rejection controls).\n",
    sep = ""
  )
}
run_interop_release_check()
