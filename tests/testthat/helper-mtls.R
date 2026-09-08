write_fake_pem <- function(path, label) {
  # Request/configuration tests need parseable, matching certificate material.
  fixture <- if (label == "PRIVATE KEY") "client-key.pem" else "client-cert.pem"
  file.copy(mtls_pem_fixture(fixture), path, overwrite = TRUE)
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
