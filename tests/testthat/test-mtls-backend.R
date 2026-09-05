test_that("PEM mTLS rejects active Schannel but accepts inactive alternatives", {
  expect_error(shinyOAuth:::validate_mtls_tls_backend("(OpenSSL/3.5.0) Schannel"),
               "CURL_SSL_BACKEND=openssl", class = "shinyOAuth_config_error")
  expect_silent(shinyOAuth:::validate_mtls_tls_backend("OpenSSL/3.5.0 (Schannel)"))
  expect_silent(shinyOAuth:::validate_mtls_tls_backend("OpenSSL/3.5.0"))
})

test_that("Windows fresh-process default and OpenSSL override are detected", {
  skip_if(.Platform$OS.type != "windows")
  skip_if_not_installed("callr")
  read_backend <- function() curl::curl_version()$ssl_version
  default <- callr::r(read_backend, env = c(CURL_SSL_BACKEND = NA_character_))
  if (grepl("Schannel", gsub("\\([^)]*\\)", "", default))) {
    expect_error(shinyOAuth:::validate_mtls_tls_backend(default), "PEM mTLS")
  }
  openssl <- callr::r(read_backend, env = c(CURL_SSL_BACKEND = "openssl"))
  expect_match(openssl, "OpenSSL")
  expect_silent(shinyOAuth:::validate_mtls_tls_backend(openssl))
})
