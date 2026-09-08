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

req_perform_tls_fixture <- function(req, minimum) {
  tryCatch(
    req_perform_bounded(req),
    httr2_failure = function(err) {
      # Some system libcurl builds support TLS 1.2 but lack TLS 1.3. Only
      # that build-time limitation skips the separate TLS 1.3 exchange test;
      # certificate, handshake and connection failures must still surface.
      if (
        identical(minimum, "1.3") &&
          inherits(err$parent, "curl_error_not_built_in")
      ) {
        testthat::skip(paste0(
          "TLS 1.3 is not built into the linked libcurl (",
          curl::curl_version()$ssl_version,
          ")"
        ))
      }
      stop(err)
    }
  )
}

wait_for_mtls_server_port <- function(server, timeout = 30) {
  deadline <- unname(proc.time()["elapsed"]) + timeout
  diagnostics <- ""
  repeat {
    # poll_io() can wake for stderr or process exit before stdout is ready.
    server$poll_io(100)
    diagnostics <- paste0(diagnostics, server$read_error())
    line <- server$read_output_lines(n = 1L)
    if (length(line)) {
      port <- suppressWarnings(as.integer(line))
      if (
        !grepl("^[0-9]+$", line) || is.na(port) || port < 1L || port > 65535L
      ) {
        stop("TLS fixture published an invalid port: ", line, call. = FALSE)
      }
      return(port)
    }
    if (!server$is_alive()) {
      stop(
        "TLS fixture exited before publishing its port (status ",
        server$get_exit_status(),
        "): ",
        diagnostics,
        server$read_all_error(),
        call. = FALSE
      )
    }
    if (unname(proc.time()["elapsed"]) >= deadline) {
      stop(
        "Timed out waiting for the TLS fixture port: ",
        diagnostics,
        call. = FALSE
      )
    }
  }
}
