run_openid_release_source_check <- function(args = commandArgs(TRUE)) {
  if (
    length(args) < 3L ||
      !identical(args[[1L]], "--revision") ||
      !grepl("^[a-f0-9]{40}$", args[[2L]])
  ) {
    stop(
      "Usage: Rscript integration/openid/run-release-source-check.R --revision COMMIT evidence.json [evidence.json ...]"
    )
  }
  source("integration/openid/helper-environment.R", local = TRUE)
  source("integration/openid/helper-suite.R", local = TRUE)
  source("integration/openid/helper-source.R", local = TRUE)
  openid_require(c("jsonlite", "openssl", "processx"))
  revision <- args[[2L]]
  tree <- trimws(processx::run(
    "git",
    c("rev-parse", paste0(revision, "^{tree}"))
  )[["stdout"]])
  reports <- lapply(args[-c(1L, 2L)], jsonlite::read_json)
  archive <- tempfile("openid-release-source-", fileext = ".tar")
  on.exit(unlink(archive), add = TRUE)
  openid_git_archive(".", archive, revision)
  if (
    !openid_release_source_matches(
      reports,
      revision,
      tree,
      openid_file_hash(archive)
    )
  ) {
    stop(
      "Release source check failed: require passing schema-4 client evidence from one clean identified source and installation"
    )
  }
  cat(
    "Release source policy passed for ",
    length(reports),
    " client report(s) at ",
    revision,
    ". Matrix completeness is not assessed.\n",
    sep = ""
  )
}
run_openid_release_source_check()
