connection_test_token <- function(
  access = "synthetic-access",
  scopes = c("read", "write"),
  expires = as.numeric(Sys.time()) + 3600
) {
  OAuthToken(
    access_token = access,
    token_type = "Bearer",
    expires_at = expires,
    granted_scopes = scopes,
    granted_scopes_verified = TRUE,
    extra_fields = list(
      patient = "synthetic-patient",
      encounter = "synthetic-encounter"
    )
  )
}

connection_test_headers <- function(req) {
  httr2::req_dry_run(req, quiet = TRUE, redact_headers = FALSE)$headers
}

test_that("targets preserve client settings and bind configuration immutably", {
  client <- make_test_client(scopes = c("read", "write"))
  target <- oauth_target(
    client,
    c(api = "https://api.example/v1"),
    required_scopes = "read"
  )
  original <- target$fingerprint
  expect_identical(target$client@resource, character())
  expect_identical(target$client@scopes, client@scopes)
  client@client_id <- "different-registration"
  expect_identical(target$client@client_id, "abc")
  expect_identical(target$fingerprint, original)
  expect_error(
    target$resource_bases <- c(api = "https://other.example"),
    "read-only"
  )
  expect_error(
    target$initialize(
      client,
      c(api = "https://other.example"),
      character(),
      "other"
    ),
    "read-only"
  )
  expect_error(
    oauth_target(client, c(api = "https://api.example/v1"), "admin"),
    "Required scopes"
  )
  expect_false(identical(
    original,
    oauth_target(client, c(api = "https://api.example/v1"), "read")$fingerprint
  ))
  expect_false(grepl(
    "api.example|different-registration",
    paste(capture.output(print(target)), collapse = "")
  ))
})

test_that("each session connection uses its own current credentials and complete base", {
  local_mocked_bindings(
    req_with_retry = function(req, ...) req,
    .package = "shinyOAuth"
  )
  local_options(shinyOAuth.allow_redirect = TRUE)
  shiny::testServer(
    function(input, output, session) {
      client_a <- make_test_client(scopes = c("read", "write"))
      client_b <- client_a
      client_b@client_id <- "registration-b"
      target_a <- oauth_target(
        client_a,
        c(api = "https://api.example/site-a/v1"),
        "read"
      )
      target_b <- oauth_target(
        client_b,
        c(api = "https://api.example/site-b/v1"),
        "read"
      )
      source_a <- shiny::reactiveVal(connection_test_token("synthetic-a"))
      source_b <- shiny::reactiveVal(connection_test_token("synthetic-b"))
      a <- oauth_connection(target_a, shiny::reactive(source_a()))
      b <- oauth_connection(target_b, shiny::reactive(source_b()))
    },
    {
      expect_true(a$is_usable())
      expect_false(identical(a$id, b$id))
      req_a <- a$request("api", "records", query = list(page = 2))
      req_b <- b$request("api", "records")
      expect_match(
        req_a$url,
        "https://api.example/site-a/v1/records?page=2",
        fixed = TRUE
      )
      expect_identical(req_b$url, "https://api.example/site-b/v1/records")
      expect_identical(
        connection_test_headers(req_a)[["authorization"]],
        "Bearer synthetic-a"
      )
      expect_identical(
        connection_test_headers(req_b)[["authorization"]],
        "Bearer synthetic-b"
      )
      expect_false(req_a$options$followlocation)
      expect_error(a$request("api", req_b$url), "approved base|ambiguous")
      source_a(connection_test_token("synthetic-a-rotated"))
      expect_identical(
        connection_test_headers(a$request("api", "records"))[["authorization"]],
        "Bearer synthetic-a-rotated"
      )
      source_b(NULL)
      expect_false(b$is_usable())
      expect_identical(b$summary()$status, "disconnected")
      expect_error(b$request("api", "records"), "not usable")
      expect_true(a$is_usable())
      text <- paste(
        capture.output(str(a$summary())),
        capture.output(print(a)),
        collapse = "\n"
      )
      expect_false(grepl(
        "synthetic-|access_token|refresh_token|patient|encounter",
        text
      ))
    }
  )
})

test_that("references reject a foreign session and become unavailable when the owner closes", {
  owner <- shiny::MockShinySession$new()
  foreign <- shiny::MockShinySession$new()
  withr::defer(owner$close())
  withr::defer(foreign$close())
  target <- oauth_target(make_test_client(), c(api = "https://api.example/v1"))
  source <- shiny::reactive(connection_test_token())
  connection <- shiny::withReactiveDomain(
    owner,
    oauth_connection(target, source)
  )
  shiny::withReactiveDomain(
    foreign,
    shiny::isolate({
      expect_false(connection$is_usable())
      expect_error(connection$summary(), "unavailable")
      expect_error(connection$request("api", "records"), "unavailable")
      expect_error(
        oauth_connection(target, source, session = owner),
        "owning Shiny session"
      )
    })
  )
  owner$close()
  shiny::withReactiveDomain(
    owner,
    shiny::isolate({
      expect_false(connection$is_usable())
      expect_error(connection$request("api", "records"), "unavailable")
    })
  )
})

test_that("required and optional operations use current scope evidence and expiry", {
  calls <- 0L
  local_mocked_bindings(
    req_with_retry = function(req, ...) {
      calls <<- calls + 1L
      req
    },
    .package = "shinyOAuth"
  )
  shiny::testServer(
    function(input, output, session) {
      target <- oauth_target(
        make_test_client(scopes = c("read", "write")),
        c(api = "https://api.example/v1"),
        "read"
      )
      source <- shiny::reactiveVal(connection_test_token(scopes = "read"))
      connection <- oauth_connection(target, shiny::reactive(source()))
    },
    {
      expect_identical(connection$summary()$status, "limited")
      expect_true(connection$is_usable())
      connection$request("api", "records", required_scopes = "read")
      expect_error(
        connection$request("api", "records", required_scopes = "write"),
        "does not cover"
      )
      expect_error(
        connection$request("api", "records", required_scopes = "admin"),
        "target's requested"
      )
      for (expires in c(NA_real_, as.numeric(Sys.time()) - 1)) {
        source(connection_test_token(expires = expires))
        expect_false(connection$is_usable())
        expect_error(connection$request("api", "records"), "not usable")
      }
      source(connection_test_token(scopes = "write"))
      expect_identical(connection$summary()$status, "insufficient_scope")
      expect_false(connection$is_usable())
      expect_identical(calls, 1L)
    }
  )
})

test_that("connection requests preserve DPoP binding and redact transport failures", {
  client <- make_test_client(scopes = "read")
  client@dpop_private_key <- openssl::ec_keygen("P-256")
  target <- oauth_target(client, c(api = "https://api.example/v1"))
  token <- connection_test_token(scopes = "read")
  token@token_type <- "DPoP"
  record <- list(target = target, token = token)
  local_mocked_bindings(
    req_with_dpop_retry = function(req, ...) req,
    .package = "shinyOAuth"
  )
  req <- connection_record_request(
    record,
    "api",
    "records",
    NULL,
    "GET",
    "read"
  )
  expect_identical(
    connection_test_headers(req)[["authorization"]],
    "DPoP synthetic-access"
  )
  expect_true(nzchar(connection_test_headers(req)[["dpop"]]))
  expect_false(req$options$followlocation)
  local_mocked_bindings(
    perform_resource_req = function(...) {
      stop("synthetic-patient synthetic-access")
    },
    .package = "shinyOAuth"
  )
  error <- tryCatch(
    connection_record_request(record, "api", "records", NULL, "GET", "read"),
    error = identity
  )
  expect_s3_class(error, "shinyOAuth_http_error")
  expect_false(grepl(
    "synthetic-",
    paste(capture.output(str(error)), collapse = "\n")
  ))
})

test_that("connection requests retain the configured mTLS certificate and binding", {
  provider <- make_test_provider()
  provider@mtls_client_certificate_bound_access_tokens <- TRUE
  client <- oauth_client(
    provider,
    client_id = "synthetic-client",
    redirect_uri = "https://app.example/callback",
    scopes = "read",
    mtls_client_cert_file = mtls_pem_fixture("client-cert.pem"),
    mtls_client_key_file = mtls_pem_fixture("client-key.pem"),
    mtls_certificate_bound_access_tokens = TRUE,
    mtls_require_observed_cnf = FALSE
  )
  target <- oauth_target(client, c(api = "https://api.example/v1"))
  token <- connection_test_token(scopes = "read")
  local_mocked_bindings(
    req_with_retry = function(req, ...) req,
    .package = "shinyOAuth"
  )
  request <- connection_record_request(
    list(target = target, token = token),
    "api",
    "records",
    NULL,
    "GET",
    "read"
  )
  expect_identical(request$options$sslcert, client@mtls_client_cert_file)
  expect_identical(request$options$sslkey, client@mtls_client_key_file)
  token@cnf <- list(`x5t#S256` = "LmpH6Yik2-D3dSsZpdndcwKkN1PcMYHtR5S6wXbUvDQ")
  expect_error(
    connection_record_request(
      list(target = target, token = token),
      "api",
      "records",
      NULL,
      "GET",
      "read"
    ),
    class = "shinyOAuth_http_error"
  )
})

test_that("live connection requests send matching credentials and never follow redirects", {
  skip_if_not_installed("webfakes")
  app <- webfakes::new_app()
  app$locals$b_requests <- 0L
  app$get("/a/v1/records", function(req, res) {
    res$send(req$get_header("authorization"))
  })
  app$get("/a/v1/next", function(req, res) {
    res$set_status(302L)$set_header("Location", "/b/v1/records")$send("")
  })
  app$get("/b/v1/records", function(req, res) {
    app$locals$b_requests <- app$locals$b_requests + 1L
    res$send(req$get_header("authorization"))
  })
  app$get("/counts", function(req, res) {
    res$send(as.character(app$locals$b_requests))
  })
  process <- webfakes::local_app_process(app)
  target <- oauth_target(
    make_test_client(scopes = "read"),
    c(api = process$url("/a/v1"))
  )
  record <- list(
    target = target,
    token = connection_test_token(scopes = "read")
  )
  local_options(shinyOAuth.allow_redirect = TRUE)
  response <- connection_record_request(
    record,
    "api",
    "records",
    NULL,
    "GET",
    "read"
  )
  expect_identical(httr2::resp_body_string(response), "Bearer synthetic-access")
  redirect <- connection_record_request(
    record,
    "api",
    "next",
    NULL,
    "GET",
    "read"
  )
  expect_identical(httr2::resp_status(redirect), 302L)
  count <- httr2::req_perform(httr2::request(process$url("/counts")))
  expect_identical(httr2::resp_body_string(count), "0")
})
