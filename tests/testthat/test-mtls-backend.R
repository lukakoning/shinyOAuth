test_that("PEM mTLS rejects active Schannel but accepts inactive alternatives", {
  expect_error(
    shinyOAuth:::validate_mtls_tls_backend("(OpenSSL/3.5.0) Schannel"),
    "CURL_SSL_BACKEND=openssl",
    class = "shinyOAuth_config_error"
  )
  expect_silent(shinyOAuth:::validate_mtls_tls_backend(
    "OpenSSL/3.5.0 (Schannel)"
  ))
  expect_silent(shinyOAuth:::validate_mtls_tls_backend("OpenSSL/3.5.0"))
})
