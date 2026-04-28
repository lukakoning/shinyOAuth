write_fake_mtls_pem <- function(path, label) {
  writeLines(
    c(
      paste0("-----BEGIN ", label, "-----"),
      "test",
      paste0("-----END ", label, "-----")
    ),
    path
  )
}

build_mtls_access_jwt <- function(payload) {
  header <- shinyOAuth:::base64url_encode(
    charToRaw('{"alg":"none","typ":"JWT"}')
  )
  body <- shinyOAuth:::base64url_encode(charToRaw(jsonlite::toJSON(
    payload,
    auto_unbox = TRUE
  )))

  paste0(header, ".", body, ".")
}

make_mtls_test_files <- function() {
  cert_file <- tempfile(fileext = ".pem")
  key_file <- tempfile(fileext = ".pem")
  ca_file <- tempfile(fileext = ".pem")

  write_fake_mtls_pem(cert_file, "CERTIFICATE")
  write_fake_mtls_pem(key_file, "PRIVATE KEY")
  write_fake_mtls_pem(ca_file, "CERTIFICATE")

  list(cert_file = cert_file, key_file = key_file, ca_file = ca_file)
}

make_mtls_test_client <- function(
  provider,
  cert_file,
  key_file,
  ca_file,
  client_secret = "top-secret"
) {
  oauth_client(
    provider = provider,
    client_id = "abc",
    client_secret = client_secret,
    redirect_uri = "http://localhost:8100/callback",
    scopes = character(0),
    tls_client_cert_file = cert_file,
    tls_client_key_file = key_file,
    tls_client_key_password = "password",
    tls_client_ca_file = ca_file
  )
}

test_that("token exchange uses mTLS alias, client certificate options, and client_id body auth", {
  files <- make_mtls_test_files()
  on.exit(unlink(unlist(files), force = TRUE), add = TRUE)

  provider <- oauth_provider(
    name = "example",
    auth_url = "https://example.com/auth",
    token_url = "https://example.com/token",
    use_nonce = FALSE,
    use_pkce = TRUE,
    id_token_required = FALSE,
    id_token_validation = FALSE,
    token_auth_style = "tls_client_auth",
    mtls_endpoint_aliases = list(
      token_endpoint = "https://example.com/mtls/token"
    )
  )
  client <- make_mtls_test_client(
    provider,
    cert_file = files$cert_file,
    key_file = files$key_file,
    ca_file = files$ca_file
  )

  captured_req <- NULL
  captured_form <- NULL
  testthat::local_mocked_bindings(
    req_body_form = function(req, ...) {
      captured_form <<- list(...)
      req
    },
    .package = "httr2"
  )
  testthat::local_mocked_bindings(
    req_with_dpop_retry = function(req, ...) {
      captured_req <<- req
      httr2::response(
        url = req$url,
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw(
          '{"access_token":"at","expires_in":3600,"token_type":"Bearer","cnf":{"x5t#S256":"thumbprint"}}'
        )
      )
    },
    .package = "shinyOAuth"
  )

  token_set <- shinyOAuth:::swap_code_for_token_set(
    client,
    code = "code",
    code_verifier = "verifier"
  )

  expect_identical(captured_req$url, "https://example.com/mtls/token")
  expect_identical(captured_req$options$sslcert, files$cert_file)
  expect_identical(captured_req$options$sslkey, files$key_file)
  expect_identical(captured_req$options$keypasswd, "password")
  expect_identical(captured_req$options$cainfo, files$ca_file)
  expect_identical(captured_form$client_id, "abc")
  expect_false("client_secret" %in% names(captured_form))
  expect_identical(token_set$cnf$`x5t#S256`, "thumbprint")
})

test_that("refresh token uses mTLS alias and preserves confirmation claims", {
  files <- make_mtls_test_files()
  on.exit(unlink(unlist(files), force = TRUE), add = TRUE)

  provider <- oauth_provider(
    name = "example",
    auth_url = "https://example.com/auth",
    token_url = "https://example.com/token",
    use_nonce = FALSE,
    use_pkce = TRUE,
    id_token_required = FALSE,
    id_token_validation = FALSE,
    token_auth_style = "self_signed_tls_client_auth",
    mtls_endpoint_aliases = list(
      token_endpoint = "https://example.com/mtls/token"
    )
  )
  client <- make_mtls_test_client(
    provider,
    cert_file = files$cert_file,
    key_file = files$key_file,
    ca_file = files$ca_file
  )
  token <- OAuthToken(
    access_token = "old-at",
    refresh_token = "old-rt",
    expires_at = as.numeric(Sys.time()) + 60,
    userinfo = list()
  )

  captured_req <- NULL
  captured_form <- NULL
  testthat::local_mocked_bindings(
    req_body_form = function(req, ...) {
      captured_form <<- list(...)
      req
    },
    .package = "httr2"
  )
  testthat::local_mocked_bindings(
    req_with_dpop_retry = function(req, ...) {
      captured_req <<- req
      httr2::response(
        url = req$url,
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw(
          '{"access_token":"new-at","refresh_token":"new-rt","expires_in":3600,"token_type":"Bearer","cnf":{"x5t#S256":"thumbprint-2"}}'
        )
      )
    },
    .package = "shinyOAuth"
  )

  refreshed <- shinyOAuth::refresh_token(client, token)

  expect_identical(captured_req$url, "https://example.com/mtls/token")
  expect_identical(captured_req$options$sslcert, files$cert_file)
  expect_identical(captured_form$client_id, "abc")
  expect_false("client_secret" %in% names(captured_form))
  expect_identical(refreshed@access_token, "new-at")
  expect_identical(refreshed@refresh_token, "new-rt")
  expect_identical(refreshed@cnf$`x5t#S256`, "thumbprint-2")
})

test_that("refresh token derives confirmation claims from JWT access tokens", {
  files <- make_mtls_test_files()
  on.exit(unlink(unlist(files), force = TRUE), add = TRUE)

  provider <- oauth_provider(
    name = "example",
    auth_url = "https://example.com/auth",
    token_url = "https://example.com/token",
    use_nonce = FALSE,
    use_pkce = TRUE,
    id_token_required = FALSE,
    id_token_validation = FALSE,
    token_auth_style = "self_signed_tls_client_auth",
    mtls_endpoint_aliases = list(
      token_endpoint = "https://example.com/mtls/token"
    )
  )
  client <- make_mtls_test_client(
    provider,
    cert_file = files$cert_file,
    key_file = files$key_file,
    ca_file = files$ca_file
  )
  token <- OAuthToken(
    access_token = "old-at",
    refresh_token = "old-rt",
    expires_at = as.numeric(Sys.time()) + 60,
    userinfo = list()
  )
  jwt_access_token <- build_mtls_access_jwt(list(
    cnf = list(`x5t#S256` = "jwt-thumbprint")
  ))

  testthat::local_mocked_bindings(
    req_with_dpop_retry = function(req, ...) {
      httr2::response(
        url = req$url,
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw(jsonlite::toJSON(
          list(
            access_token = jwt_access_token,
            refresh_token = "new-rt",
            expires_in = 3600,
            token_type = "Bearer"
          ),
          auto_unbox = TRUE
        ))
      )
    },
    .package = "shinyOAuth"
  )

  refreshed <- shinyOAuth::refresh_token(client, token)

  expect_identical(refreshed@cnf$`x5t#S256`, "jwt-thumbprint")
})

test_that("userinfo uses mTLS alias and client certificate for certificate-bound tokens", {
  files <- make_mtls_test_files()
  on.exit(unlink(unlist(files), force = TRUE), add = TRUE)

  provider <- oauth_provider(
    name = "example",
    auth_url = "https://example.com/auth",
    token_url = "https://example.com/token",
    userinfo_url = "https://example.com/userinfo",
    use_nonce = FALSE,
    use_pkce = TRUE,
    id_token_required = FALSE,
    id_token_validation = FALSE,
    tls_client_certificate_bound_access_tokens = TRUE,
    mtls_endpoint_aliases = list(
      userinfo_endpoint = "https://example.com/mtls/userinfo"
    )
  )
  client <- make_mtls_test_client(
    provider,
    cert_file = files$cert_file,
    key_file = files$key_file,
    ca_file = files$ca_file
  )
  token <- OAuthToken(
    access_token = "at",
    token_type = "Bearer",
    userinfo = list(),
    cnf = list(`x5t#S256` = "thumbprint")
  )

  captured_req <- NULL
  testthat::local_mocked_bindings(
    tls_client_cert_thumbprint_s256 = function(cert_file) {
      expect_identical(cert_file, files$cert_file)
      "thumbprint"
    },
    req_with_retry = function(req, ...) {
      captured_req <<- req
      httr2::response(
        url = req$url,
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw('{"sub":"user-123"}')
      )
    },
    .package = "shinyOAuth"
  )

  userinfo <- shinyOAuth::get_userinfo(client, token)

  expect_identical(captured_req$url, "https://example.com/mtls/userinfo")
  expect_identical(captured_req$options$sslcert, files$cert_file)
  expect_identical(captured_req$options$sslkey, files$key_file)
  expect_identical(userinfo$sub, "user-123")
})

test_that("client_bearer_req rejects certificate-bound tokens when thumbprint mismatches", {
  files <- make_mtls_test_files()
  on.exit(unlink(unlist(files), force = TRUE), add = TRUE)

  provider <- oauth_provider(
    name = "example",
    auth_url = "https://example.com/auth",
    token_url = "https://example.com/token",
    use_nonce = FALSE,
    use_pkce = TRUE,
    id_token_required = FALSE,
    id_token_validation = FALSE,
    tls_client_certificate_bound_access_tokens = TRUE
  )
  client <- make_mtls_test_client(
    provider,
    cert_file = files$cert_file,
    key_file = files$key_file,
    ca_file = files$ca_file
  )
  token <- OAuthToken(
    access_token = "at",
    token_type = "Bearer",
    userinfo = list(),
    cnf = list(`x5t#S256` = "expected-thumbprint")
  )

  testthat::local_mocked_bindings(
    tls_client_cert_thumbprint_s256 = function(...) "different-thumbprint",
    .package = "shinyOAuth"
  )

  expect_error(
    shinyOAuth::client_bearer_req(
      token = token,
      url = "https://resource.example.com/api",
      oauth_client = client
    ),
    regexp = "does not match token cnf x5t#S256"
  )
})

test_that("client_bearer_req enforces certificate binding from JWT cnf", {
  files <- make_mtls_test_files()
  on.exit(unlink(unlist(files), force = TRUE), add = TRUE)

  provider <- oauth_provider(
    name = "example",
    auth_url = "https://example.com/auth",
    token_url = "https://example.com/token",
    use_nonce = FALSE,
    use_pkce = TRUE,
    id_token_required = FALSE,
    id_token_validation = FALSE,
    tls_client_certificate_bound_access_tokens = TRUE
  )
  client <- make_mtls_test_client(
    provider,
    cert_file = files$cert_file,
    key_file = files$key_file,
    ca_file = files$ca_file
  )
  token <- OAuthToken(
    access_token = build_mtls_access_jwt(list(
      cnf = list(`x5t#S256` = "expected-thumbprint")
    )),
    token_type = "Bearer",
    userinfo = list()
  )

  testthat::local_mocked_bindings(
    tls_client_cert_thumbprint_s256 = function(...) "different-thumbprint",
    .package = "shinyOAuth"
  )

  expect_error(
    shinyOAuth::client_bearer_req(
      token = token,
      url = "https://resource.example.com/api",
      oauth_client = client
    ),
    regexp = "does not match token cnf x5t#S256"
  )
})
