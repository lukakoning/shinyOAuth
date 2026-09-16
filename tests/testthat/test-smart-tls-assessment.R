test_that("SMART TLS assessment agrees with effective request policy", {
  local_mocked_bindings(
    curl_version = function(...) {
      list(version = "8.14.1", ssl_version = "OpenSSL/3.5.0")
    },
    .package = "curl"
  )
  smart <- smart_client(
    smart_client_fixture(),
    "app",
    "https://app.example/callback",
    "user/Patient.r"
  )
  ordinary <- make_test_client()
  finding <- function(client) {
    checks <- check_oauth21(client)[["checks"]]
    checks[checks[["id"]] == "tls.minimum", , drop = FALSE]
  }
  req <- httr2::request("https://ehr.example/token")
  for (minimum in list(NULL, "1.2", "1.3")) {
    local_options(shinyOAuth.tls_min_version = minimum)
    expect_identical(
      add_req_defaults(req, client = smart)[["options"]][["sslversion"]],
      if (identical(minimum, "1.3")) 7L else 6L
    )
    expect_identical(finding(smart)[["status"]], "pass")
    expect_identical(
      finding(smart)[["evidence_source"]],
      "configuration_and_runtime"
    )
    expect_identical(getOption("shinyOAuth.tls_min_version"), minimum)
    expect_identical(
      finding(ordinary)[["status"]],
      if (is.null(minimum)) "unknown" else "pass"
    )
    expect_identical(
      finding(smart@provider)[["status"]],
      if (is.null(minimum)) "unknown" else "pass"
    )
  }
  local_options(shinyOAuth.tls_min_version = "1.1")
  expect_identical(finding(smart)[["status"]], "fail")
  expect_error(add_req_defaults(req, client = smart), "tls_min_version")
  local_options(shinyOAuth.tls_min_version = NULL)
  local_mocked_bindings(
    curl_version = function(...) {
      list(version = "8.9.0", ssl_version = "wolfSSL/5.7.2")
    },
    .package = "curl"
  )
  expect_identical(finding(smart)[["status"]], "fail")
  expect_error(add_req_defaults(req, client = smart), "wolfSSL")
})
