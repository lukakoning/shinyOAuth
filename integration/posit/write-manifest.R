script_arg <- grep("^--file=", commandArgs(FALSE), value = TRUE)

if (length(script_arg) != 1) {
  stop("This script must be run with Rscript.", call. = FALSE)
}

script_path <- normalizePath(sub("^--file=", "", script_arg))
app_dir <- dirname(script_path)

primary_doc <- Sys.getenv("SHINYOAUTH_POSIT_PRIMARY_DOC", "app.R")

if (!file.exists(file.path(app_dir, primary_doc))) {
  stop(
    sprintf("Primary app file does not exist: %s", primary_doc),
    call. = FALSE
  )
}

required_packages <- c("remotes", "rsconnect")
missing_packages <- required_packages[
  !vapply(required_packages, requireNamespace, logical(1), quietly = TRUE)
]

if (length(missing_packages) > 0) {
  stop(
    paste(
      "Install required packages first:",
      paste(missing_packages, collapse = ", ")
    ),
    call. = FALSE
  )
}

temp_lib <- tempfile("rsconnect-lib-")
dir.create(temp_lib)

old_lib_paths <- .libPaths()
on.exit(.libPaths(old_lib_paths), add = TRUE)
on.exit(unlink(temp_lib, recursive = TRUE, force = TRUE), add = TRUE)

.libPaths(c(temp_lib, old_lib_paths))

github_repo <- Sys.getenv("SHINYOAUTH_GITHUB_REPO", "lukakoning/shinyOAuth")
github_ref <- Sys.getenv("SHINYOAUTH_GITHUB_REF", "master")

remotes::install_github(
  repo = github_repo,
  ref = github_ref,
  lib = temp_lib,
  upgrade = "never",
  dependencies = FALSE,
  quiet = TRUE
)

rsconnect::writeManifest(
  appDir = app_dir,
  appPrimaryDoc = primary_doc,
  appMode = "shiny",
  quiet = TRUE
)

cat(
  sprintf(
    "Wrote manifest.json in %s for %s using %s@%s\n",
    app_dir,
    primary_doc,
    github_repo,
    github_ref
  )
)
