openid_file_hash <- function(path) {
  connection <- file(path, "rb")
  on.exit(close(connection))
  paste(openssl::sha256(connection), collapse = "")
}

openid_hash_manifest <- function(files) {
  paths <- sort(names(files), method = "radix")
  text <- paste0(
    nchar(enc2utf8(paths), type = "bytes"),
    ":",
    enc2utf8(paths),
    ":",
    unlist(files[paths], use.names = FALSE),
    collapse = "\n"
  )
  paste(openssl::sha256(charToRaw(text)), collapse = "")
}

openid_source_identity <- function(root = ".") {
  git <- function(args, ...) processx::run("git", args, wd = root, ...)
  revision <- trimws(git(c("rev-parse", "HEAD"))[["stdout"]])
  tree <- trimws(git(c("rev-parse", "HEAD^{tree}"))[["stdout"]])
  dirty <- nzchar(trimws(git(c(
    "status",
    "--porcelain",
    "--untracked-files=all"
  ))[["stdout"]]))
  flags <- strsplit(git(c("ls-files", "-v"))[["stdout"]], "\n", fixed = TRUE)[[
    1L
  ]]
  index_masked <- any(grepl("^[a-zS] ", flags))
  dirty <- dirty || index_masked
  path <- tempfile("openid-source-files-")
  on.exit(unlink(path), add = TRUE)
  git(
    c("ls-files", "--cached", "--others", "--exclude-standard", "-z"),
    stdout = path
  )
  connection <- file(path, "rb")
  paths <- tryCatch(
    readBin(connection, "character", n = 100000L),
    finally = close(connection)
  )
  paths <- sort(unique(paths), method = "radix")
  if (
    !length(paths) ||
      length(paths) >= 100000L ||
      any(grepl("(^/|^[A-Za-z]:|(^|/)\\.\\.(/|$))", paths))
  ) {
    stop("Invalid source file inventory")
  }
  files <- setNames(
    lapply(paths, function(name) {
      file <- file.path(root, name)
      link <- Sys.readlink(file)
      if (!is.na(link) && nzchar(link)) {
        stop("Source inventory requires regular files")
      }
      if (!file.exists(file)) {
        return("missing")
      }
      openid_file_hash(file)
    }),
    paths
  )
  list(
    kind = if (dirty) "dirty_development" else "clean_checkout",
    revision = revision,
    tree = tree,
    dirty = dirty,
    index_masked = index_masked,
    files = files,
    fingerprint = openid_hash_manifest(files)
  )
}

openid_assert_source <- function(root, expected) {
  actual <- openid_source_identity(root)
  if (!identical(actual, expected)) {
    stop("Checkout source changed during this run")
  }
  actual
}

openid_git_archive <- function(root, archive, revision) {
  processx::run(
    "git",
    c(
      "-c",
      "tar.umask=0002",
      "archive",
      "--format=tar",
      "--prefix=shinyOAuth/",
      paste0("--output=", archive),
      revision
    ),
    wd = root
  )
  invisible(archive)
}

openid_source_archive <- function(root, output, source) {
  openid_assert_source(root, source)
  output <- normalizePath(output, winslash = "/")
  archive <- file.path(
    output,
    if (source[["dirty"]]) "checkout-source.tar.gz" else "checkout-source.tar"
  )
  if (!isTRUE(source[["dirty"]])) {
    openid_git_archive(root, archive, source[["revision"]])
  } else {
    executable <- file.path(
      R.home("bin"),
      if (.Platform[["OS.type"]] == "windows") "R.exe" else "R"
    )
    processx::run(
      executable,
      c(
        "CMD",
        "build",
        "--no-build-vignettes",
        "--no-manual",
        "--no-resave-data",
        normalizePath(root, winslash = "/")
      ),
      wd = output,
      stdout = file.path(output, "build.log"),
      stderr = file.path(output, "build.stderr"),
      timeout = 180000
    )
    built <- list.files(output, "^shinyOAuth_.*[.]tar[.]gz$", full.names = TRUE)
    if (length(built) != 1L || !file.rename(built, archive)) {
      stop("Cannot identify the development source archive")
    }
  }
  openid_assert_source(root, source)
  normalizePath(archive, winslash = "/")
}

openid_installed_files <- function(package) {
  paths <- sort(
    list.files(package, recursive = TRUE, all.files = TRUE),
    method = "radix"
  )
  paths <- setdiff(paths, "Meta/openid-source.json")
  setNames(lapply(file.path(package, paths), openid_file_hash), paths)
}

openid_installation <- function(library, source) {
  package <- file.path(library, "shinyOAuth")
  record <- jsonlite::read_json(file.path(package, "Meta/openid-source.json"))
  files <- openid_installed_files(package)
  if (
    !identical(record[["source_fingerprint"]], source[["fingerprint"]]) ||
      !identical(record[["revision"]], source[["revision"]]) ||
      !identical(record[["tree"]], source[["tree"]]) ||
      !identical(
        record[["archive_sha256"]],
        openid_file_hash(file.path(
          dirname(library),
          if (source[["dirty"]]) {
            "checkout-source.tar.gz"
          } else {
            "checkout-source.tar"
          }
        ))
      ) ||
      !identical(record[["files"]], files) ||
      !identical(record[["fingerprint"]], openid_hash_manifest(files))
  ) {
    stop("Installed package no longer matches its recorded source")
  }
  record
}

openid_source_record_valid <- function(source) {
  if (!is.list(source)) {
    return(FALSE)
  }
  if (
    !is.logical(source[["dirty"]]) ||
      length(source[["dirty"]]) != 1L ||
      is.na(source[["dirty"]]) ||
      !is.logical(source[["index_masked"]]) ||
      length(source[["index_masked"]]) != 1L ||
      is.na(source[["index_masked"]]) ||
      (isTRUE(source[["index_masked"]]) && !isTRUE(source[["dirty"]])) ||
      !identical(
        source[["kind"]],
        if (source[["dirty"]]) "dirty_development" else "clean_checkout"
      ) ||
      !openid_string(source[["revision"]]) ||
      !grepl("^[a-f0-9]{40}$", source[["revision"]]) ||
      !openid_string(source[["tree"]]) ||
      !grepl("^[a-f0-9]{40}$", source[["tree"]])
  ) {
    return(FALSE)
  }
  files <- source[["files"]]
  is.list(files) &&
    length(files) > 0L &&
    !is.null(names(files)) &&
    !anyDuplicated(names(files)) &&
    !anyNA(names(files)) &&
    all(nzchar(names(files))) &&
    all(vapply(
      files,
      function(value) {
        openid_string(value) &&
          (grepl("^[a-f0-9]{64}$", value) ||
            (isTRUE(source[["dirty"]]) && identical(value, "missing")))
      },
      logical(1)
    )) &&
    identical(source[["fingerprint"]], openid_hash_manifest(files))
}

openid_check_source <- function(report, context, installed = TRUE) {
  source <- context[["checkout_source"]]
  if (
    !openid_source_record_valid(source) ||
      !identical(source[["revision"]], context[["checkout_revision"]]) ||
      !identical(source[["dirty"]], context[["checkout_dirty"]]) ||
      !identical(report[["checkout_source"]], source) ||
      !identical(report[["checkout_source_after"]], source) ||
      !isTRUE(report[["source_verified"]])
  ) {
    stop("Missing, changed or unrelated checkout source evidence")
  }
  if (!installed) {
    return(invisible(TRUE))
  }
  installation <- context[["installation"]]
  if (
    !identical(report[["installation"]], installation) ||
      !identical(report[["installation_after"]], installation) ||
      !identical(installation[["revision"]], source[["revision"]]) ||
      !identical(installation[["tree"]], source[["tree"]]) ||
      !identical(
        installation[["source_fingerprint"]],
        source[["fingerprint"]]
      ) ||
      !identical(
        installation[["package_version"]],
        context[["package_version"]]
      ) ||
      !identical(
        installation[["method"]],
        if (source[["dirty"]]) "working_tree_build" else "git_archive"
      ) ||
      !openid_string(installation[["archive_sha256"]]) ||
      !grepl("^[a-f0-9]{64}$", installation[["archive_sha256"]]) ||
      !is.list(installation[["files"]]) ||
      !length(installation[["files"]]) ||
      is.null(names(installation[["files"]])) ||
      anyDuplicated(names(installation[["files"]])) ||
      !all(vapply(
        installation[["files"]],
        function(value) {
          openid_string(value) && grepl("^[a-f0-9]{64}$", value)
        },
        logical(1)
      )) ||
      !identical(
        installation[["fingerprint"]],
        openid_hash_manifest(installation[["files"]])
      )
  ) {
    stop("Missing, changed or unrelated installed-package evidence")
  }
  invisible(TRUE)
}

openid_release_source_matches <- function(
  reports,
  revision,
  tree,
  archive_sha256
) {
  tryCatch(
    {
      stopifnot(
        length(reports) > 0L,
        grepl("^[a-f0-9]{40}$", revision),
        grepl("^[a-f0-9]{40}$", tree),
        grepl("^[a-f0-9]{64}$", archive_sha256)
      )
      for (report in reports) {
        stopifnot(
          identical(report[["schema_version"]], 4L),
          identical(report[["status"]], "passed"),
          isTRUE(report[["gate_passed"]]),
          identical(report[["checkout_revision"]], revision),
          identical(report[["checkout_dirty"]], FALSE),
          identical(
            report[["installation"]][["archive_sha256"]],
            archive_sha256
          ),
          identical(report[["checkout_source"]][["tree"]], tree)
        )
        openid_check_source(report, report)
        if (identical(report[["profile"]], "shared-pool")) {
          stopifnot(
            length(report[["selections"]]) == 4L,
            openid_release_source_matches(
              report[["selections"]],
              revision,
              tree,
              archive_sha256
            )
          )
        } else {
          stopifnot(length(report[["results"]]) > 0L)
        }
      }
      TRUE
    },
    error = function(e) FALSE
  )
}
