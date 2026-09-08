# Run from the repository root: Rscript --vanilla tests/run-local.R [filter]
# Select the TLS backend before pkgload/devtools can load curl. Setting this
# inside testthat.R is too late for test_local()/devtools::test().
if (.Platform$OS.type == "windows") {
  Sys.setenv(CURL_SSL_BACKEND = "openssl")
}
args <- commandArgs(trailingOnly = TRUE)
# Worker processes load an installed namespace, whereas test_local() loads the
# checkout in the parent. Always give both processes this checkout's build.
test_library <- tempfile("shinyOAuth-local-library-")
dir.create(test_library)
.libPaths(c(test_library, .libPaths()))
invisible(processx::run(
  file.path(R.home("bin"), if (.Platform$OS.type == "windows") "R.exe" else "R"),
  c("CMD", "INSTALL", paste0("--library=", test_library), "."),
  echo = FALSE
))
Sys.setenv(
  R_LIBS = paste(.libPaths(), collapse = .Platform[["path.sep"]]),
  R_LIBS_USER = paste(.libPaths(), collapse = .Platform[["path.sep"]]),
  SHINYOAUTH_TEST_LIBRARY = normalizePath(test_library, winslash = "/")
)
expected_package <- normalizePath(
  file.path(test_library, "shinyOAuth"), winslash = "/"
)
worker_package <- callr::r(function() {
  loadNamespace("shinyOAuth")
  normalizePath(find.package("shinyOAuth"), winslash = "/")
}, libpath = .libPaths())
stopifnot(identical(worker_package, expected_package))
message("Worker package: ", worker_package)
results <- testthat::test_local(
  filter = if (length(args)) args[[1]] else NULL,
  stop_on_failure = TRUE
)
skipped <- sum(as.data.frame(results)$skipped)
if (skipped > 0L) {
  message("Local suite skipped ", skipped, " test(s); inspect the skip reasons above.")
}
