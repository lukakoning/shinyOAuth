# Run from the repository root: Rscript --vanilla tests/run-local.R [filter]
# Select the TLS backend before pkgload/devtools can load curl. Setting this
# inside testthat.R is too late for test_local()/devtools::test().
if (.Platform$OS.type == "windows") {
  Sys.setenv(CURL_SSL_BACKEND = "openssl")
}
args <- commandArgs(trailingOnly = TRUE)
testthat::test_local(
  filter = if (length(args)) args[[1]] else NULL,
  stop_on_failure = TRUE
)
