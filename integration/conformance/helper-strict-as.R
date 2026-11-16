strict_as_fixture <- function(alg, .env = parent.frame()) {
  python <- Sys.getenv("SHINYOAUTH_TEST_PYTHON", unset = Sys.which("python"))
  testthat::expect_true(nzchar(python))
  root <- tempfile("strict-as-")
  dir.create(root)
  withr::defer(unlink(root, recursive = TRUE), envir = .env)
  signing_key <- openssl::rsa_keygen()
  writeLines(
    openssl::write_pem(as.list(signing_key)[["pubkey"]]),
    file.path(root, "registered.pem")
  )
  server <- processx::process[["new"]](
    python,
    c("strict_as.py", root, alg),
    stdout = "|",
    stderr = "|"
  )
  withr::defer(server[["kill"]](), envir = .env)
  deadline <- Sys.time() + 15
  ready <- character()
  while (!length(ready) && server[["is_alive"]]() && Sys.time() < deadline) {
    server[["poll_io"]](100)
    ready <- server[["read_output_lines"]]()
  }
  if (!length(ready) || !startsWith(ready[[1L]], "{")) {
    server[["wait"]](1000)
    stop(paste(c(ready, server[["read_all_error"]]()), collapse = "\n"))
  }
  withr::local_envvar(
    CURL_CA_BUNDLE = file.path(root, "ca.pem"),
    .local_envir = .env
  )
  withr::local_options(
    list(
      shinyOAuth.tls_min_version = "1.2",
      shinyOAuth.timeout = 5,
      shinyOAuth.skip_id_sig = FALSE,
      shinyOAuth.otel_tracing_enabled = FALSE,
      shinyOAuth.otel_logging_enabled = FALSE
    ),
    .local_envir = .env
  )
  list(
    root = root,
    issuer = jsonlite::fromJSON(ready[[1L]])[["issuer"]],
    signing_key = signing_key
  )
}
