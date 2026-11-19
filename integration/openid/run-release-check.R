run_openid_release_check <- function(args = commandArgs(TRUE)) {
  if (
    length(args) < 5L ||
      !identical(args[[1L]], "--revision") ||
      !grepl("^[a-f0-9]{40}$", args[[2L]]) ||
      !identical(args[[3L]], "--output") ||
      !nzchar(args[[4L]])
  ) {
    stop(
      "Usage: Rscript integration/openid/run-release-check.R --revision COMMIT --output summary.json evidence.json [evidence.json ...]"
    )
  }
  for (name in c(
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
  )) {
    source(paste0("integration/openid/helper-", name, ".R"), local = TRUE)
  }
  openid_require(c("jsonlite", "openssl", "processx"))
  output <- args[[4L]]
  if (file.exists(output) || dir.exists(output)) {
    stop("Release summary output already exists; choose a new path")
  }
  parent <- dirname(output)
  if (!dir.exists(parent) && !dir.create(parent, recursive = TRUE)) {
    stop("Cannot create release summary directory")
  }
  read_input <- function(path) {
    size <- file.info(path)[["size"]]
    if (is.na(size) || dir.exists(path) || size <= 0 || size > 64 * 1024^2) {
      stop("Release evidence must be a nonempty JSON file of at most 64 MiB")
    }
    bytes <- readBin(path, "raw", n = size)
    list(
      value = jsonlite::fromJSON(rawToChar(bytes), simplifyVector = FALSE),
      sha256 = paste(openssl::sha256(bytes), collapse = "")
    )
  }
  revision <- args[[2L]]
  policy_root <- tempfile("openid-release-policy-")
  if (
    !dir.create(file.path(policy_root, "integration/openid"), recursive = TRUE)
  ) {
    stop("Cannot create the private release policy directory")
  }
  on.exit(
    {
      resolved <- normalizePath(policy_root, winslash = "/", mustWork = TRUE)
      temporary <- normalizePath(tempdir(), winslash = "/", mustWork = TRUE)
      if (!startsWith(resolved, paste0(temporary, "/"))) {
        stop(
          "Refusing to remove a release policy directory outside this R temporary directory"
        )
      }
      unlink(resolved, recursive = TRUE)
    },
    add = TRUE
  )
  policy_paths <- c(
    "integration/openid/release-matrix.json",
    "integration/openid/profiles.json",
    "integration/openid/suite-lock.json",
    "DESCRIPTION"
  )
  for (path in policy_paths) {
    processx::run(
      "git",
      c("show", paste0(revision, ":", path)),
      stdout = file.path(policy_root, path)
    )
  }
  matrix_input <- read_input(file.path(policy_root, policy_paths[[1L]]))
  profiles_input <- read_input(file.path(policy_root, policy_paths[[2L]]))
  lock_input <- read_input(file.path(policy_root, policy_paths[[3L]]))
  manifest <- openid_profiles(policy_root)
  package_version <- read.dcf(file.path(policy_root, "DESCRIPTION"))[[
    1L,
    "Version"
  ]]
  inputs <- lapply(args[-seq_len(4L)], read_input)
  tree <- trimws(processx::run(
    "git",
    c("rev-parse", paste0(revision, "^{tree}"))
  )[["stdout"]])
  archive <- tempfile("openid-release-", fileext = ".tar")
  on.exit(unlink(archive), add = TRUE)
  openid_git_archive(".", archive, revision)
  check <- openid_check_release(
    lapply(inputs, function(input) input[["value"]]),
    matrix_input[["value"]],
    manifest,
    revision,
    tree,
    openid_file_hash(archive),
    package_version
  )
  check[["matrix_sha256"]] <- matrix_input[["sha256"]]
  check[["profiles_sha256"]] <- profiles_input[["sha256"]]
  check[["suite_lock_sha256"]] <- lock_input[["sha256"]]
  check[["input_sha256"]] <- as.list(vapply(
    inputs,
    function(input) input[["sha256"]],
    character(1)
  ))
  check[["requested_source"]] <- list(
    revision = revision,
    tree = tree,
    archive_sha256 = openid_file_hash(archive),
    package_version = package_version
  )
  for (i in seq_along(check[["entries"]])) {
    index <- check[["entries"]][[i]][["report_index"]]
    check[["entries"]][[i]][["report_sha256"]] <- inputs[[index]][["sha256"]]
    check[["entries"]][[i]][["report_index"]] <- NULL
  }
  jsonlite::write_json(
    check,
    output,
    auto_unbox = TRUE,
    pretty = TRUE,
    null = "null"
  )
  if (!isTRUE(check[["gate_passed"]])) {
    stop("Declared OpenID release matrix failed: ", check[["reason"]])
  }
  cat(
    "Declared OpenID client matrix passed for ",
    check[["selection_count"]],
    " selections at ",
    revision,
    ". Platform coverage, artifact authentication, durable retention and certification are not assessed.\n",
    sep = ""
  )
  invisible(check)
}

run_openid_release_check()
