test_that("accepted leaf-first certificate layouts complete an mTLS exchange", {
  python <- Sys.which("python3")
  if (!nzchar(python)) {
    python <- Sys.which("python")
  }
  skip_if(!nzchar(python), "Python is required for the loopback TLS fixture")
  server <- processx::process$new(
    python,
    mtls_pem_fixture("roundtrip-server.py"),
    stdout = "|",
    stderr = "|"
  )
  withr::defer(server$kill())
  port <- wait_for_mtls_server_port(server)
  cert <- mtls_pem_fixture("client-cert.pem")
  ca <- mtls_pem_fixture("ca-cert.pem")
  bundle <- withr::local_tempfile(fileext = ".pem")
  client <- make_test_client(use_nonce = FALSE)
  # Set the pair atomically through the public constructor.
  client <- oauth_client(
    provider = client@provider,
    client_id = "test",
    redirect_uri = "http://localhost:8100",
    mtls_client_cert_file = cert,
    mtls_client_key_file = mtls_pem_fixture("client-key.pem"),
    mtls_client_ca_file = mtls_pem_fixture("server-cert.pem")
  )
  writeLines(c(readLines(cert), readLines(ca)), bundle)
  for (layout in c(cert, bundle)) {
    client@mtls_client_cert_file <- layout
    req <- httr2::request(paste0("https://127.0.0.1:", port, "/"))
    req <- req_apply_mtls_client_certificate(req, client)
    expect_identical(
      httr2::resp_body_string(httr2::req_perform(req)),
      "client certificate accepted"
    )
  }
  writeLines(c(readLines(ca), readLines(cert)), bundle)
  expect_error(
    req_apply_mtls_client_certificate(req, client),
    "must put the client certificate.*first"
  )
  expect_error(
    oauth_client(
      provider = client@provider,
      client_id = "test",
      redirect_uri = "http://localhost:8100",
      mtls_client_cert_file = bundle,
      mtls_client_key_file = client@mtls_client_key_file
    ),
    "must put the client certificate.*first"
  )
})
