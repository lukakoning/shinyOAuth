Sys.setenv(CURL_SSL_BACKEND = "openssl", NOT_CRAN = "true")
pkgload::load_all(".")
results <- testthat::test_dir("integration/conformance", stop_on_failure = TRUE)
if (any(as.data.frame(results)$skipped)) {
  stop("Conformance fixture requires zero skips")
}
