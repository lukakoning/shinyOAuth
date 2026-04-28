write_fake_pem <- function(path, label) {
  writeLines(
    c(
      paste0("-----BEGIN ", label, "-----"),
      "test",
      paste0("-----END ", label, "-----")
    ),
    path
  )
}

make_mtls_test_files <- function() {
  cert_file <- tempfile(fileext = ".pem")
  key_file <- tempfile(fileext = ".pem")
  ca_file <- tempfile(fileext = ".pem")

  write_fake_pem(cert_file, "CERTIFICATE")
  write_fake_pem(key_file, "PRIVATE KEY")
  write_fake_pem(ca_file, "CERTIFICATE")

  list(cert_file = cert_file, key_file = key_file, ca_file = ca_file)
}

mtls_pem_fixture <- function(filename) {
  normalizePath(
    testthat::test_path("fixtures", "mtls", filename),
    winslash = "/",
    mustWork = TRUE
  )
}
