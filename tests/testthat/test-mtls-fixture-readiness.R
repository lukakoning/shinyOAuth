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
