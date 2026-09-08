test_that("TLS defaults remain unchanged and explicit minima preserve stronger constraints", {
  req <- httr2::request("https://example.com")
  withr::local_options(list(shinyOAuth.tls_min_version = NULL))
  expect_null(add_req_defaults(req)$options$sslversion)
  withr::local_options(list(shinyOAuth.tls_min_version = "1.2"))
  expect_identical(add_req_defaults(req)$options$sslversion, 6L)
  stronger <- httr2::req_options(req, sslversion = 7L, cainfo = "custom-ca.pem")
  expect_identical(req_apply_tls_policy(stronger)$options$sslversion, 7L)
  expect_identical(
    req_apply_tls_policy(stronger)$options$cainfo,
    "custom-ca.pem"
  )
  maximum <- bitwShiftL(7L, 16L)
  capped <- httr2::req_options(req, sslversion = bitwOr(5L, maximum))
  expect_identical(
    req_apply_tls_policy(capped)$options$sslversion,
    bitwOr(6L, maximum)
  )
  expect_null(
    req_apply_tls_policy(httr2::request("http://localhost"))$options$sslversion
  )
  withr::local_options(list(shinyOAuth.tls_min_version = "1.3"))
  expect_identical(
    resource_req("token", "https://example.com")$options$sslversion,
    7L
  )
  expect_error(
    req_apply_tls_policy(httr2::req_options(
      req,
      sslversion = bitwOr(6L, bitwShiftL(6L, 16L))
    )),
    "maximum conflicts"
  )
})

test_that("explicit TLS minima reject disabled verification and invalid options", {
  req <- httr2::request("https://example.com")
  withr::local_options(list(shinyOAuth.tls_min_version = "1.2"))
  expect_error(
    req_apply_tls_policy(httr2::req_options(req, ssl_verifypeer = FALSE)),
    "verification"
  )
  expect_error(
    req_apply_tls_policy(httr2::req_options(req, ssl_verifyhost = 0L)),
    "verification"
  )
  expect_identical(
    req_apply_tls_policy(httr2::req_options(
      req,
      ssl_verifyhost = 2L
    ))$options$ssl_verifyhost,
    2L
  )
  for (value in list("1.0", 1.2, NA_character_, character(), c("1.2", "1.3"))) {
    withr::local_options(list(shinyOAuth.tls_min_version = value))
    expect_error(add_req_defaults(req), "tls_min_version")
  }
})

test_that("TLS policy is checked immediately before package-owned HTTP performance", {
  withr::local_options(list(shinyOAuth.tls_min_version = "1.3"))
  testthat::local_mocked_bindings(
    req_perform = function(req, ...) {
      expect_identical(req$options$sslversion, 7L)
      httr2::response(status = 200, body = raw())
    },
    .package = "httr2"
  )
  expect_s3_class(
    req_perform_bounded(httr2::request("https://example.com")),
    "httr2_response"
  )
})

test_that("TLS minimum is captured and absent settings clear stale worker policy", {
  withr::local_options(list(shinyOAuth.tls_min_version = "1.3"))
  captured <- capture_async_options()
  expect_identical(captured$shinyOAuth.tls_min_version, "1.3")
  withr::local_options(list(shinyOAuth.tls_min_version = "1.2"))
  with_async_options(captured, {
    expect_identical(configured_tls_minimum(), "1.3")
  })
  captured$shinyOAuth.tls_min_version <- NULL
  with_async_options(captured, {
    expect_null(configured_tls_minimum())
  })
  expect_identical(configured_tls_minimum(), "1.2")
})

test_that("TLS policy changes invalidate the pending transaction policy", {
  client <- make_test_client(use_nonce = FALSE)
  withr::local_options(list(shinyOAuth.tls_min_version = NULL))
  before <- state_client_policy_fingerprint(client)
  withr::local_options(list(shinyOAuth.tls_min_version = "1.2"))
  expect_false(identical(before, state_client_policy_fingerprint(client)))
})

test_that("explicit TLS minima interoperate with local mTLS and custom trust roots", {
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
  client <- oauth_client(
    provider = make_test_provider(use_nonce = FALSE),
    client_id = "tls",
    redirect_uri = "http://localhost:8100",
    mtls_client_cert_file = mtls_pem_fixture("client-cert.pem"),
    mtls_client_key_file = mtls_pem_fixture("client-key.pem"),
    mtls_client_ca_file = mtls_pem_fixture("server-cert.pem")
  )
  for (minimum in c("1.2", "1.3")) {
    withr::local_options(list(shinyOAuth.tls_min_version = minimum))
    req <- httr2::request(paste0("https://127.0.0.1:", port, "/"))
    req <- req_apply_mtls_client_certificate(req, client)
    expect_identical(
      httr2::resp_body_string(req_perform_bounded(req)),
      "client certificate accepted"
    )
  }
})
