local_readiness_process <- function(code, .local_envir = parent.frame()) {
  script <- withr::local_tempfile(fileext = ".R", .local_envir = .local_envir)
  writeLines(code, script)
  server <- processx::process$new(
    file.path(
      R.home("bin"),
      if (.Platform$OS.type == "windows") "Rscript.exe" else "Rscript"
    ),
    c("--vanilla", script),
    stdout = "|",
    stderr = "|"
  )
  withr::defer(server$kill(), envir = .local_envir)
  server
}

test_that("TLS readiness waits through stderr and partial port output", {
  server <- local_readiness_process(c(
    "cat('starting fixture\n', file = stderr())",
    "Sys.sleep(0.5)",
    "cat('123'); flush.console()",
    "Sys.sleep(0.2)",
    "cat('45\n'); flush.console()",
    "Sys.sleep(10)"
  ))
  expect_identical(wait_for_mtls_server_port(server), 12345L)
})

test_that("TLS readiness reports startup errors before making a request", {
  server <- local_readiness_process(c(
    "cat('fixture startup failed\n', file = stderr())",
    "quit(status = 2)"
  ))
  expect_error(
    wait_for_mtls_server_port(server),
    "TLS fixture exited.*status 2.*fixture startup failed"
  )
})

test_that("TLS readiness has a bounded wait", {
  server <- local_readiness_process("Sys.sleep(10)")
  expect_error(
    wait_for_mtls_server_port(server, timeout = 0.1),
    "Timed out waiting for the TLS fixture port"
  )
})

test_that("TLS readiness rejects an invalid published port", {
  server <- local_readiness_process("cat('65536\n'); Sys.sleep(10)")
  expect_error(
    wait_for_mtls_server_port(server),
    "TLS fixture published an invalid port: 65536"
  )
})

test_that("the loopback TLS fixture starts without reverse hostname lookups", {
  python <- Sys.which("python3")
  if (!nzchar(python)) {
    python <- Sys.which("python")
  }
  skip_if(!nzchar(python), "Python is required for the loopback TLS fixture")
  # Make resolver dependencies fail immediately on every platform, including
  # runners where reverse lookups would otherwise hang during HTTPServer bind.
  code <- paste(
    "import runpy, socket, sys",
    "def reject_lookup(*args, **kwargs):",
    "    raise RuntimeError('TLS fixture must not resolve hostnames')",
    "socket.getfqdn = reject_lookup",
    "socket.gethostbyaddr = reject_lookup",
    "runpy.run_path(sys.argv[1], run_name='__main__')",
    sep = "\n"
  )
  server <- processx::process$new(
    python,
    c("-c", code, mtls_pem_fixture("roundtrip-server.py")),
    stdout = "|",
    stderr = "|"
  )
  withr::defer(server$kill())
  port <- wait_for_mtls_server_port(server)
  req <- httr2::request(paste0("https://127.0.0.1:", port, "/"))
  req <- httr2::req_options(
    req,
    sslcert = mtls_pem_fixture("client-cert.pem"),
    sslkey = mtls_pem_fixture("client-key.pem"),
    cainfo = mtls_pem_fixture("server-cert.pem")
  )
  expect_identical(
    httr2::resp_body_string(httr2::req_perform(req)),
    "client certificate accepted"
  )
})
