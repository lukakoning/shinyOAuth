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

make_mtls_test_client <- function(
  provider,
  cert_file,
  key_file,
  ca_file,
  client_secret = "top-secret",
  mtls_request_certificate_bound_access_tokens = FALSE
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
    tls_client_ca_file = ca_file,
    mtls_request_certificate_bound_access_tokens = mtls_request_certificate_bound_access_tokens
  )
}

test_that("token exchange uses mTLS alias, client certificate options, and client_id body auth", {
  files <- list(
    cert_file = mtls_pem_fixture("client-cert.pem"),
    key_file = mtls_pem_fixture("client-key.pem"),
    ca_file = mtls_pem_fixture("ca-cert.pem")
  )
  thumbprint <- shinyOAuth:::tls_client_cert_thumbprint_s256(files$cert_file)

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
          paste0(
            '{"access_token":"at","expires_in":3600,"token_type":"Bearer","cnf":{"x5t#S256":"',
            thumbprint,
            '"}}'
          )
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
  expect_identical(token_set$cnf$`x5t#S256`, thumbprint)
})

test_that("public clients keep the standard token endpoint by default", {
  files <- list(
    cert_file = mtls_pem_fixture("client-cert.pem"),
    key_file = mtls_pem_fixture("client-key.pem"),
    ca_file = mtls_pem_fixture("ca-cert.pem")
  )

  provider <- oauth_provider(
    name = "example",
    auth_url = "https://example.com/auth",
    token_url = "https://example.com/token",
    use_nonce = FALSE,
    use_pkce = TRUE,
    id_token_required = FALSE,
    id_token_validation = FALSE,
    token_auth_style = "body",
    tls_client_certificate_bound_access_tokens = TRUE,
    mtls_endpoint_aliases = list(
      token_endpoint = "https://example.com/mtls/token"
    )
  )
  client <- make_mtls_test_client(
    provider,
    cert_file = files$cert_file,
    key_file = files$key_file,
    ca_file = files$ca_file,
    client_secret = ""
  )

  captured_req <- NULL
  testthat::local_mocked_bindings(
    req_with_dpop_retry = function(req, ...) {
      captured_req <<- req
      httr2::response(
        url = req$url,
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw(
          '{"access_token":"at","expires_in":3600,"token_type":"Bearer"}'
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

  expect_identical(captured_req$url, "https://example.com/token")
  expect_null(token_set$cnf)
})

test_that("public clients use mTLS token aliases when they explicitly request certificate-bound tokens", {
  files <- list(
    cert_file = mtls_pem_fixture("client-cert.pem"),
    key_file = mtls_pem_fixture("client-key.pem"),
    ca_file = mtls_pem_fixture("ca-cert.pem")
  )
  thumbprint <- shinyOAuth:::tls_client_cert_thumbprint_s256(files$cert_file)

  provider <- oauth_provider(
    name = "example",
    auth_url = "https://example.com/auth",
    token_url = "https://example.com/token",
    use_nonce = FALSE,
    use_pkce = TRUE,
    id_token_required = FALSE,
    id_token_validation = FALSE,
    token_auth_style = "body",
    tls_client_certificate_bound_access_tokens = TRUE,
    mtls_endpoint_aliases = list(
      token_endpoint = "https://example.com/mtls/token"
    )
  )
  client <- make_mtls_test_client(
    provider,
    cert_file = files$cert_file,
    key_file = files$key_file,
    ca_file = files$ca_file,
    client_secret = "",
    mtls_request_certificate_bound_access_tokens = TRUE
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
          paste0(
            '{"access_token":"at","expires_in":3600,"token_type":"Bearer","cnf":{"x5t#S256":"',
            thumbprint,
            '"}}'
          )
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
  expect_identical(captured_form$client_id, "abc")
  expect_false("client_secret" %in% names(captured_form))
  expect_identical(token_set$access_token, "at")
  expect_identical(token_set$cnf$`x5t#S256`, thumbprint)
})

test_that("public clients reject missing cnf when they explicitly request certificate-bound tokens", {
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
    token_auth_style = "body",
    tls_client_certificate_bound_access_tokens = TRUE,
    mtls_endpoint_aliases = list(
      token_endpoint = "https://example.com/mtls/token"
    )
  )
  client <- make_mtls_test_client(
    provider,
    cert_file = files$cert_file,
    key_file = files$key_file,
    ca_file = files$ca_file,
    client_secret = "",
    mtls_request_certificate_bound_access_tokens = TRUE
  )

  testthat::local_mocked_bindings(
    req_with_dpop_retry = function(req, ...) {
      httr2::response(
        url = req$url,
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw(
          '{"access_token":"at","expires_in":3600,"token_type":"Bearer"}'
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

  expect_error(
    shinyOAuth:::verify_token_set(
      client,
      token_set = token_set,
      nonce = NULL,
      is_refresh = FALSE,
      requested_scopes = character(0),
      prior_granted_scopes = character(0)
    ),
    class = "shinyOAuth_token_error",
    regexp = "required cnf x5t#S256 thumbprint"
  )
})

test_that("requested certificate-bound login can backfill cnf from introspection before userinfo", {
  files <- list(
    cert_file = mtls_pem_fixture("client-cert.pem"),
    key_file = mtls_pem_fixture("client-key.pem"),
    ca_file = mtls_pem_fixture("ca-cert.pem")
  )

  thumbprint <- shinyOAuth:::tls_client_cert_thumbprint_s256(files$cert_file)
  provider <- oauth_provider(
    name = "example",
    auth_url = "https://example.com/auth",
    token_url = "https://example.com/token",
    userinfo_url = "https://example.com/userinfo",
    introspection_url = "https://example.com/introspect",
    use_nonce = FALSE,
    use_pkce = TRUE,
    id_token_required = FALSE,
    id_token_validation = FALSE,
    token_auth_style = "body",
    tls_client_certificate_bound_access_tokens = TRUE,
    mtls_endpoint_aliases = list(
      userinfo_endpoint = "https://example.com/mtls/userinfo",
      introspection_endpoint = "https://example.com/mtls/introspect"
    )
  )
  client <- make_mtls_test_client(
    provider,
    cert_file = files$cert_file,
    key_file = files$key_file,
    ca_file = files$ca_file,
    client_secret = "",
    mtls_request_certificate_bound_access_tokens = TRUE
  )
  client@introspect <- TRUE

  browser_token <- valid_browser_token()
  auth_url <- shinyOAuth:::prepare_call(client, browser_token = browser_token)
  payload <- parse_query_param(auth_url, "state")
  captured_userinfo_req <- NULL

  testthat::with_mocked_bindings(
    swap_code_for_token_set = function(client, code, code_verifier) {
      list(
        access_token = "opaque-access-token",
        expires_in = 3600,
        token_type = "Bearer"
      )
    },
    req_with_retry = function(req, ...) {
      req_url <- as.character(req$url)
      if (identical(req_url, "https://example.com/mtls/introspect")) {
        return(httr2::response(
          url = req$url,
          status = 200,
          headers = list("content-type" = "application/json"),
          body = charToRaw(
            paste0(
              '{"active":true,"cnf":{"x5t#S256":"',
              thumbprint,
              '"}}'
            )
          )
        ))
      }

      captured_userinfo_req <<- req
      httr2::response(
        url = req$url,
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw('{"sub":"user-1"}')
      )
    },
    .package = "shinyOAuth",
    {
      token <- shinyOAuth:::handle_callback(
        client,
        code = "abc",
        payload = payload,
        browser_token = browser_token
      )

      testthat::expect_identical(token@cnf$`x5t#S256`, thumbprint)
      testthat::expect_identical(token@userinfo$sub, "user-1")
      testthat::expect_identical(
        captured_userinfo_req$url,
        "https://example.com/mtls/userinfo"
      )
    }
  )
})

test_that("PAR uses mTLS alias when the client explicitly requests certificate-bound tokens", {
  files <- make_mtls_test_files()
  on.exit(unlink(unlist(files), force = TRUE), add = TRUE)

  provider <- oauth_provider(
    name = "example",
    auth_url = "https://example.com/auth",
    token_url = "https://example.com/token",
    par_url = "https://example.com/par",
    use_nonce = FALSE,
    use_pkce = TRUE,
    id_token_required = FALSE,
    id_token_validation = FALSE,
    token_auth_style = "body",
    tls_client_certificate_bound_access_tokens = TRUE,
    mtls_endpoint_aliases = list(
      par_endpoint = "https://example.com/mtls/par"
    )
  )
  client <- make_mtls_test_client(
    provider,
    cert_file = files$cert_file,
    key_file = files$key_file,
    ca_file = files$ca_file,
    client_secret = "",
    mtls_request_certificate_bound_access_tokens = TRUE
  )

  captured_req <- NULL
  testthat::local_mocked_bindings(
    req_with_retry = function(req, ...) {
      captured_req <<- req
      httr2::response(
        url = req$url,
        status = 201,
        headers = list("content-type" = "application/json"),
        body = charToRaw(
          '{"request_uri":"urn:ietf:params:oauth:request_uri:test","expires_in":90}'
        )
      )
    },
    .package = "shinyOAuth"
  )

  result <- shinyOAuth:::push_authorization_request(
    client,
    params = list(response_type = "code", client_id = client@client_id)
  )

  expect_identical(captured_req$url, "https://example.com/mtls/par")
  expect_identical(captured_req$options$sslcert, files$cert_file)
  expect_identical(captured_req$options$sslkey, files$key_file)
  expect_identical(result$request_uri, "urn:ietf:params:oauth:request_uri:test")
})

test_that("explicit certificate-bound requests honor the standard PAR alias name", {
  files <- make_mtls_test_files()
  on.exit(unlink(unlist(files), force = TRUE), add = TRUE)

  provider <- oauth_provider(
    name = "example",
    auth_url = "https://example.com/auth",
    token_url = "https://example.com/token",
    par_url = "https://example.com/par",
    use_nonce = FALSE,
    use_pkce = TRUE,
    id_token_required = FALSE,
    id_token_validation = FALSE,
    token_auth_style = "body",
    tls_client_certificate_bound_access_tokens = TRUE,
    mtls_endpoint_aliases = list(
      pushed_authorization_request_endpoint = "https://example.com/mtls/par"
    )
  )
  client <- make_mtls_test_client(
    provider,
    cert_file = files$cert_file,
    key_file = files$key_file,
    ca_file = files$ca_file,
    client_secret = "",
    mtls_request_certificate_bound_access_tokens = TRUE
  )

  captured_req <- NULL
  testthat::local_mocked_bindings(
    req_with_retry = function(req, ...) {
      captured_req <<- req
      httr2::response(
        url = req$url,
        status = 201,
        headers = list("content-type" = "application/json"),
        body = charToRaw(
          '{"request_uri":"urn:ietf:params:oauth:request_uri:test","expires_in":90}'
        )
      )
    },
    .package = "shinyOAuth"
  )

  result <- shinyOAuth:::push_authorization_request(
    client,
    params = list(response_type = "code", client_id = client@client_id)
  )

  expect_identical(captured_req$url, "https://example.com/mtls/par")
  expect_identical(captured_req$options$sslcert, files$cert_file)
  expect_identical(captured_req$options$sslkey, files$key_file)
  expect_identical(result$request_uri, "urn:ietf:params:oauth:request_uri:test")
})

test_that("refresh token uses mTLS alias and preserves confirmation claims", {
  files <- list(
    cert_file = mtls_pem_fixture("client-cert.pem"),
    key_file = mtls_pem_fixture("client-key.pem"),
    ca_file = mtls_pem_fixture("ca-cert.pem")
  )
  thumbprint <- shinyOAuth:::tls_client_cert_thumbprint_s256(files$cert_file)

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
          paste0(
            '{"access_token":"new-at","refresh_token":"new-rt","expires_in":3600,"token_type":"Bearer","cnf":{"x5t#S256":"',
            thumbprint,
            '"}}'
          )
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
  expect_identical(refreshed@cnf$`x5t#S256`, thumbprint)
})

test_that("refresh token derives confirmation claims from JWT access tokens", {
  files <- list(
    cert_file = mtls_pem_fixture("client-cert.pem"),
    key_file = mtls_pem_fixture("client-key.pem"),
    ca_file = mtls_pem_fixture("ca-cert.pem")
  )

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
  thumbprint <- shinyOAuth:::tls_client_cert_thumbprint_s256(files$cert_file)
  jwt_access_token <- build_mtls_access_jwt(list(
    cnf = list(`x5t#S256` = thumbprint)
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

  expect_identical(refreshed@cnf$`x5t#S256`, thumbprint)
})

test_that("refresh rejects mismatched certificate-bound token responses", {
  files <- list(
    cert_file = mtls_pem_fixture("client-cert.pem"),
    key_file = mtls_pem_fixture("client-key.pem"),
    ca_file = mtls_pem_fixture("ca-cert.pem")
  )

  provider <- oauth_provider(
    name = "example",
    auth_url = "https://example.com/auth",
    token_url = "https://example.com/token",
    use_nonce = FALSE,
    use_pkce = TRUE,
    id_token_required = FALSE,
    id_token_validation = FALSE,
    token_auth_style = "body",
    tls_client_certificate_bound_access_tokens = TRUE,
    mtls_endpoint_aliases = list(
      token_endpoint = "https://example.com/mtls/token"
    ),
    allowed_token_types = character(0)
  )
  client <- make_mtls_test_client(
    provider,
    cert_file = files$cert_file,
    key_file = files$key_file,
    ca_file = files$ca_file,
    client_secret = ""
  )
  token <- OAuthToken(
    access_token = "old-at",
    refresh_token = "old-rt",
    expires_at = as.numeric(Sys.time()) + 60,
    userinfo = list()
  )

  testthat::local_mocked_bindings(
    req_with_dpop_retry = function(req, ...) {
      httr2::response(
        url = req$url,
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw(
          '{"access_token":"new-at","refresh_token":"new-rt","expires_in":3600,"token_type":"Bearer","cnf":{"x5t#S256":"wrong-thumbprint"}}'
        )
      )
    },
    .package = "shinyOAuth"
  )

  expect_error(
    shinyOAuth::refresh_token(client, token),
    class = "shinyOAuth_token_error",
    regexp = "TLS certificate does not match token cnf x5t#S256 thumbprint"
  )
})

test_that("refresh uses the mTLS token alias when the client explicitly requests certificate-bound tokens", {
  files <- list(
    cert_file = mtls_pem_fixture("client-cert.pem"),
    key_file = mtls_pem_fixture("client-key.pem"),
    ca_file = mtls_pem_fixture("ca-cert.pem")
  )
  thumbprint <- shinyOAuth:::tls_client_cert_thumbprint_s256(files$cert_file)

  provider <- oauth_provider(
    name = "example",
    auth_url = "https://example.com/auth",
    token_url = "https://example.com/token",
    use_nonce = FALSE,
    use_pkce = TRUE,
    id_token_required = FALSE,
    id_token_validation = FALSE,
    token_auth_style = "body",
    tls_client_certificate_bound_access_tokens = TRUE,
    mtls_endpoint_aliases = list(
      token_endpoint = "https://example.com/mtls/token"
    )
  )
  client <- make_mtls_test_client(
    provider,
    cert_file = files$cert_file,
    key_file = files$key_file,
    ca_file = files$ca_file,
    client_secret = "",
    mtls_request_certificate_bound_access_tokens = TRUE
  )
  token <- OAuthToken(
    access_token = "old-at",
    refresh_token = "old-rt",
    expires_at = as.numeric(Sys.time()) + 60,
    userinfo = list()
  )

  captured_req <- NULL
  testthat::local_mocked_bindings(
    req_with_dpop_retry = function(req, ...) {
      captured_req <<- req
      httr2::response(
        url = req$url,
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw(
          paste0(
            '{"access_token":"new-at","refresh_token":"new-rt","expires_in":3600,"token_type":"Bearer","cnf":{"x5t#S256":"',
            thumbprint,
            '"}}'
          )
        )
      )
    },
    .package = "shinyOAuth"
  )

  refreshed <- shinyOAuth::refresh_token(client, token)

  expect_identical(captured_req$url, "https://example.com/mtls/token")
  expect_identical(captured_req$options$sslcert, files$cert_file)
  expect_identical(captured_req$options$sslkey, files$key_file)
  expect_identical(refreshed@access_token, "new-at")
  expect_identical(refreshed@cnf$`x5t#S256`, thumbprint)
})

test_that("requested certificate-bound refresh rejects token responses missing cnf", {
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
    token_auth_style = "body",
    tls_client_certificate_bound_access_tokens = TRUE,
    mtls_endpoint_aliases = list(
      token_endpoint = "https://example.com/mtls/token"
    )
  )
  client <- make_mtls_test_client(
    provider,
    cert_file = files$cert_file,
    key_file = files$key_file,
    ca_file = files$ca_file,
    client_secret = "",
    mtls_request_certificate_bound_access_tokens = TRUE
  )
  token <- OAuthToken(
    access_token = "old-at",
    refresh_token = "old-rt",
    expires_at = as.numeric(Sys.time()) + 60,
    userinfo = list()
  )

  testthat::local_mocked_bindings(
    req_with_dpop_retry = function(req, ...) {
      httr2::response(
        url = req$url,
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw(
          '{"access_token":"new-at","refresh_token":"new-rt","expires_in":3600,"token_type":"Bearer"}'
        )
      )
    },
    .package = "shinyOAuth"
  )

  expect_error(
    shinyOAuth::refresh_token(client, token),
    class = "shinyOAuth_token_error",
    regexp = "required cnf x5t#S256 thumbprint"
  )
})

test_that("requested certificate-bound refresh can backfill cnf from introspection", {
  files <- list(
    cert_file = mtls_pem_fixture("client-cert.pem"),
    key_file = mtls_pem_fixture("client-key.pem"),
    ca_file = mtls_pem_fixture("ca-cert.pem")
  )

  thumbprint <- shinyOAuth:::tls_client_cert_thumbprint_s256(files$cert_file)
  provider <- oauth_provider(
    name = "example",
    auth_url = "https://example.com/auth",
    token_url = "https://example.com/token",
    introspection_url = "https://example.com/introspect",
    use_nonce = FALSE,
    use_pkce = TRUE,
    id_token_required = FALSE,
    id_token_validation = FALSE,
    token_auth_style = "body",
    tls_client_certificate_bound_access_tokens = TRUE,
    mtls_endpoint_aliases = list(
      token_endpoint = "https://example.com/mtls/token",
      introspection_endpoint = "https://example.com/mtls/introspect"
    )
  )
  client <- make_mtls_test_client(
    provider,
    cert_file = files$cert_file,
    key_file = files$key_file,
    ca_file = files$ca_file,
    client_secret = "",
    mtls_request_certificate_bound_access_tokens = TRUE
  )
  token <- OAuthToken(
    access_token = "old-at",
    refresh_token = "old-rt",
    expires_at = as.numeric(Sys.time()) + 60,
    userinfo = list()
  )

  testthat::local_mocked_bindings(
    req_with_dpop_retry = function(req, ...) {
      httr2::response(
        url = req$url,
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw(
          '{"access_token":"new-at","refresh_token":"new-rt","expires_in":3600,"token_type":"Bearer"}'
        )
      )
    },
    req_with_retry = function(req, ...) {
      httr2::response(
        url = req$url,
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw(
          paste0(
            '{"active":true,"cnf":{"x5t#S256":"',
            thumbprint,
            '"}}'
          )
        )
      )
    },
    .package = "shinyOAuth"
  )

  refreshed <- shinyOAuth::refresh_token(client, token, introspect = TRUE)

  expect_identical(refreshed@access_token, "new-at")
  expect_identical(refreshed@refresh_token, "new-rt")
  expect_identical(refreshed@cnf$`x5t#S256`, thumbprint)
})

test_that("refresh uses token cnf to choose mTLS alias without provider metadata", {
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
    token_auth_style = "body",
    mtls_endpoint_aliases = list(
      token_endpoint = "https://example.com/mtls/token"
    )
  )
  client <- make_mtls_test_client(
    provider,
    cert_file = files$cert_file,
    key_file = files$key_file,
    ca_file = files$ca_file,
    client_secret = ""
  )
  token <- OAuthToken(
    access_token = "old-at",
    refresh_token = "old-rt",
    expires_at = as.numeric(Sys.time()) + 60,
    userinfo = list(),
    cnf = list(`x5t#S256` = "thumbprint")
  )

  captured_req <- NULL
  testthat::local_mocked_bindings(
    tls_client_cert_thumbprint_s256 = function(...) {
      stop("thumbprint check should not run for token endpoint calls")
    },
    req_with_dpop_retry = function(req, ...) {
      captured_req <<- req
      httr2::response(
        url = req$url,
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw(
          '{"access_token":"new-at","refresh_token":"new-rt","expires_in":3600,"token_type":"Bearer"}'
        )
      )
    },
    .package = "shinyOAuth"
  )

  refreshed <- shinyOAuth::refresh_token(client, token)

  expect_identical(captured_req$url, "https://example.com/mtls/token")
  expect_identical(captured_req$options$sslcert, files$cert_file)
  expect_identical(captured_req$options$sslkey, files$key_file)
  expect_identical(refreshed@access_token, "new-at")
})

test_that("revoke uses token cnf to choose mTLS alias without local thumbprint validation", {
  files <- make_mtls_test_files()
  on.exit(unlink(unlist(files), force = TRUE), add = TRUE)

  provider <- oauth_provider(
    name = "example",
    auth_url = "https://example.com/auth",
    token_url = "https://example.com/token",
    revocation_url = "https://example.com/revoke",
    use_nonce = FALSE,
    use_pkce = TRUE,
    id_token_required = FALSE,
    id_token_validation = FALSE,
    token_auth_style = "body",
    mtls_endpoint_aliases = list(
      revocation_endpoint = "https://example.com/mtls/revoke"
    )
  )
  client <- make_mtls_test_client(
    provider,
    cert_file = files$cert_file,
    key_file = files$key_file,
    ca_file = files$ca_file,
    client_secret = ""
  )
  token <- OAuthToken(
    access_token = "old-at",
    refresh_token = "old-rt",
    expires_at = as.numeric(Sys.time()) + 60,
    userinfo = list(),
    cnf = list(`x5t#S256` = "thumbprint")
  )

  captured_req <- NULL
  testthat::local_mocked_bindings(
    tls_client_cert_thumbprint_s256 = function(...) {
      stop("thumbprint check should not run for revocation")
    },
    req_with_dpop_retry = function(...) {
      stop("DPoP retry should not run for revocation")
    },
    req_with_retry = function(req, ...) {
      captured_req <<- req
      httr2::response(
        url = req$url,
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw("{}")
      )
    },
    .package = "shinyOAuth"
  )

  revoked <- shinyOAuth::revoke_token(
    client,
    token,
    which = "access",
    async = FALSE
  )

  expect_identical(captured_req$url, "https://example.com/mtls/revoke")
  expect_identical(captured_req$options$sslcert, files$cert_file)
  expect_identical(captured_req$options$sslkey, files$key_file)
  expect_true(isTRUE(revoked$revoked))
  expect_identical(revoked$status, "ok")
})

test_that("introspect uses token cnf to choose mTLS alias without local thumbprint validation", {
  files <- make_mtls_test_files()
  on.exit(unlink(unlist(files), force = TRUE), add = TRUE)

  provider <- oauth_provider(
    name = "example",
    auth_url = "https://example.com/auth",
    token_url = "https://example.com/token",
    introspection_url = "https://example.com/introspect",
    use_nonce = FALSE,
    use_pkce = TRUE,
    id_token_required = FALSE,
    id_token_validation = FALSE,
    token_auth_style = "body",
    mtls_endpoint_aliases = list(
      introspection_endpoint = "https://example.com/mtls/introspect"
    )
  )
  client <- make_mtls_test_client(
    provider,
    cert_file = files$cert_file,
    key_file = files$key_file,
    ca_file = files$ca_file,
    client_secret = ""
  )
  token <- OAuthToken(
    access_token = "old-at",
    refresh_token = "old-rt",
    expires_at = as.numeric(Sys.time()) + 60,
    userinfo = list(),
    cnf = list(`x5t#S256` = "thumbprint")
  )

  captured_req <- NULL
  testthat::local_mocked_bindings(
    tls_client_cert_thumbprint_s256 = function(...) {
      stop("thumbprint check should not run for introspection")
    },
    req_with_dpop_retry = function(...) {
      stop("DPoP retry should not run for introspection")
    },
    req_with_retry = function(req, ...) {
      captured_req <<- req
      httr2::response(
        url = req$url,
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw('{"active":true}')
      )
    },
    .package = "shinyOAuth"
  )

  inspected <- shinyOAuth::introspect_token(
    client,
    token,
    which = "access",
    async = FALSE
  )

  expect_identical(captured_req$url, "https://example.com/mtls/introspect")
  expect_identical(captured_req$options$sslcert, files$cert_file)
  expect_identical(captured_req$options$sslkey, files$key_file)
  expect_true(isTRUE(inspected$active))
  expect_identical(inspected$status, "ok")
})

test_that("client bearer requests still enforce certificate thumbprint binding", {
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
    token_auth_style = "body"
  )
  client <- make_mtls_test_client(
    provider,
    cert_file = files$cert_file,
    key_file = files$key_file,
    ca_file = files$ca_file,
    client_secret = ""
  )
  token <- OAuthToken(
    access_token = "at",
    token_type = "Bearer",
    userinfo = list(),
    cnf = list(`x5t#S256` = "old-thumbprint")
  )

  testthat::local_mocked_bindings(
    tls_client_cert_thumbprint_s256 = function(cert_file, ...) {
      expect_identical(cert_file, files$cert_file)
      "new-thumbprint"
    },
    .package = "shinyOAuth"
  )

  testthat::expect_error(
    shinyOAuth::client_bearer_req(
      token,
      url = "https://example.com/resource",
      oauth_client = client
    ),
    regexp = "token cnf x5t#S256 thumbprint",
    class = "shinyOAuth_input_error"
  )
})

test_that("client bearer requests honor cnf in raw JWT access tokens", {
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
    token_auth_style = "body"
  )
  client <- make_mtls_test_client(
    provider,
    cert_file = files$cert_file,
    key_file = files$key_file,
    ca_file = files$ca_file,
    client_secret = ""
  )
  raw_token <- build_mtls_access_jwt(list(
    cnf = list(`x5t#S256` = "thumbprint")
  ))

  testthat::local_mocked_bindings(
    tls_client_cert_thumbprint_s256 = function(cert_file, ...) {
      expect_identical(cert_file, files$cert_file)
      "thumbprint"
    },
    .package = "shinyOAuth"
  )

  req <- shinyOAuth::client_bearer_req(
    raw_token,
    url = "https://example.com/resource",
    oauth_client = client
  )

  dry <- httr2::req_dry_run(req, quiet = TRUE, redact_headers = FALSE)
  expect_identical(req$options$sslcert, files$cert_file)
  expect_identical(req$options$sslkey, files$key_file)
  expect_identical(dry$headers$authorization, paste("Bearer", raw_token))
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
    token_auth_style = "body",
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
    tls_client_cert_thumbprint_s256 = function(cert_file, ...) {
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

test_that("userinfo ignores mTLS alias when only provider metadata is present", {
  provider <- oauth_provider(
    name = "example",
    auth_url = "https://example.com/auth",
    token_url = "https://example.com/token",
    userinfo_url = "https://example.com/userinfo",
    use_nonce = FALSE,
    use_pkce = TRUE,
    id_token_required = FALSE,
    id_token_validation = FALSE,
    token_auth_style = "body",
    tls_client_certificate_bound_access_tokens = TRUE,
    mtls_endpoint_aliases = list(
      userinfo_endpoint = "https://example.com/mtls/userinfo"
    )
  )
  client <- oauth_client(
    provider = provider,
    client_id = "abc",
    client_secret = "",
    redirect_uri = "http://localhost:8100/callback",
    scopes = character(0)
  )
  token <- OAuthToken(
    access_token = "at",
    token_type = "Bearer",
    userinfo = list()
  )

  captured_req <- NULL
  testthat::local_mocked_bindings(
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

  req_options <- captured_req$options
  if (is.null(req_options)) {
    req_options <- list()
  }

  expect_identical(captured_req$url, "https://example.com/userinfo")
  expect_false("sslcert" %in% names(req_options))
  expect_false("sslkey" %in% names(req_options))
  expect_identical(userinfo$sub, "user-123")
})

test_that("handle_callback preserves certificate-bound context for automatic userinfo", {
  files <- list(
    cert_file = mtls_pem_fixture("client-cert.pem"),
    key_file = mtls_pem_fixture("client-key.pem"),
    ca_file = mtls_pem_fixture("ca-cert.pem")
  )

  provider <- oauth_provider(
    name = "example",
    auth_url = "https://example.com/auth",
    token_url = "https://example.com/token",
    userinfo_url = "https://example.com/userinfo",
    use_nonce = FALSE,
    use_pkce = TRUE,
    id_token_required = FALSE,
    id_token_validation = FALSE,
    userinfo_required = TRUE,
    token_auth_style = "body",
    mtls_endpoint_aliases = list(
      userinfo_endpoint = "https://example.com/mtls/userinfo"
    )
  )
  client <- make_mtls_test_client(
    provider,
    cert_file = files$cert_file,
    key_file = files$key_file,
    ca_file = files$ca_file,
    client_secret = ""
  )

  browser_token <- valid_browser_token()
  cert_thumbprint <- shinyOAuth:::tls_client_cert_thumbprint_s256(
    files$cert_file,
    key_file = files$key_file,
    key_password = "password"
  )
  auth_url <- shinyOAuth:::prepare_call(client, browser_token = browser_token)
  enc <- parse_query_param(auth_url, "state")
  jwt_access_token <- build_mtls_access_jwt(list(
    cnf = list(`x5t#S256` = cert_thumbprint)
  ))

  captured_req <- NULL
  testthat::with_mocked_bindings(
    swap_code_for_token_set = function(client, code, code_verifier) {
      list(
        access_token = jwt_access_token,
        expires_in = 3600,
        token_type = "Bearer"
      )
    },
    tls_client_cert_thumbprint_s256 = function(cert_file, ...) {
      expect_identical(cert_file, files$cert_file)
      cert_thumbprint
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
    .package = "shinyOAuth",
    {
      token <- shinyOAuth:::handle_callback(
        client,
        code = "code",
        payload = enc,
        browser_token = browser_token
      )

      expect_identical(captured_req$url, "https://example.com/mtls/userinfo")
      expect_identical(captured_req$options$sslcert, files$cert_file)
      expect_identical(captured_req$options$sslkey, files$key_file)
      expect_identical(token@userinfo$sub, "user-123")
      expect_identical(token@cnf$`x5t#S256`, cert_thumbprint)
    }
  )
})

test_that("refresh_token preserves certificate-bound context for automatic userinfo", {
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
    userinfo_required = TRUE,
    token_auth_style = "body",
    mtls_endpoint_aliases = list(
      userinfo_endpoint = "https://example.com/mtls/userinfo"
    )
  )
  client <- make_mtls_test_client(
    provider,
    cert_file = files$cert_file,
    key_file = files$key_file,
    ca_file = files$ca_file,
    client_secret = ""
  )
  token <- OAuthToken(
    access_token = "old-at",
    refresh_token = "old-rt",
    expires_at = as.numeric(Sys.time()) + 60,
    userinfo = list()
  )
  jwt_access_token <- build_mtls_access_jwt(list(
    cnf = list(`x5t#S256` = "thumbprint")
  ))

  captured_req <- NULL
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
    tls_client_cert_thumbprint_s256 = function(cert_file, ...) {
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

  refreshed <- shinyOAuth::refresh_token(client, token, introspect = FALSE)

  expect_identical(captured_req$url, "https://example.com/mtls/userinfo")
  expect_identical(captured_req$options$sslcert, files$cert_file)
  expect_identical(captured_req$options$sslkey, files$key_file)
  expect_identical(refreshed@userinfo$sub, "user-123")
  expect_identical(refreshed@cnf$`x5t#S256`, "thumbprint")
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

test_that("certificate-bound introspection and revocation use mTLS aliases without mTLS auth style", {
  files <- make_mtls_test_files()
  on.exit(unlink(unlist(files), force = TRUE), add = TRUE)

  provider <- oauth_provider(
    name = "example",
    auth_url = "https://example.com/auth",
    token_url = "https://example.com/token",
    introspection_url = "https://example.com/introspect",
    revocation_url = "https://example.com/revoke",
    use_nonce = FALSE,
    use_pkce = TRUE,
    id_token_required = FALSE,
    id_token_validation = FALSE,
    token_auth_style = "body",
    tls_client_certificate_bound_access_tokens = TRUE,
    mtls_endpoint_aliases = list(
      introspection_endpoint = "https://example.com/mtls/introspect",
      revocation_endpoint = "https://example.com/mtls/revoke"
    )
  )
  client <- make_mtls_test_client(
    provider,
    cert_file = files$cert_file,
    key_file = files$key_file,
    ca_file = files$ca_file,
    client_secret = ""
  )
  token <- OAuthToken(
    access_token = "at",
    refresh_token = "rt",
    expires_at = as.numeric(Sys.time()) + 60,
    userinfo = list(),
    cnf = list(`x5t#S256` = "thumbprint")
  )

  captured_urls <- character(0)
  captured_reqs <- list()
  testthat::local_mocked_bindings(
    tls_client_cert_thumbprint_s256 = function(cert_file, ...) {
      expect_identical(cert_file, files$cert_file)
      "thumbprint"
    },
    req_with_dpop_retry = function(...) {
      stop("DPoP retry should not run for revocation or introspection")
    },
    req_with_retry = function(req, ...) {
      captured_urls <<- c(captured_urls, as.character(req$url))
      captured_reqs[[length(captured_urls)]] <<- req

      if (grepl("introspect", as.character(req$url), fixed = TRUE)) {
        return(httr2::response(
          url = req$url,
          status = 200,
          headers = list("content-type" = "application/json"),
          body = charToRaw('{"active":true}')
        ))
      }

      httr2::response(
        url = req$url,
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw("{}")
      )
    },
    .package = "shinyOAuth"
  )

  introspection <- shinyOAuth::introspect_token(
    client,
    token,
    which = "access",
    async = FALSE
  )
  revocation <- shinyOAuth::revoke_token(
    client,
    token,
    which = "access",
    async = FALSE
  )

  expect_true(isTRUE(introspection$active))
  expect_true(isTRUE(revocation$revoked))
  expect_identical(
    captured_urls,
    c(
      "https://example.com/mtls/introspect",
      "https://example.com/mtls/revoke"
    )
  )
  expect_identical(captured_reqs[[1]]$options$sslcert, files$cert_file)
  expect_identical(captured_reqs[[2]]$options$sslcert, files$cert_file)
})

test_that("certificate binding uses the key-matched certificate from PEM bundles", {
  cert_file <- mtls_pem_fixture("client-cert.pem")
  key_file <- mtls_pem_fixture("client-key.pem")
  ca_file <- mtls_pem_fixture("ca-cert.pem")
  bundle_file <- tempfile(fileext = ".pem")
  on.exit(unlink(bundle_file, force = TRUE), add = TRUE)

  writeLines(c(readLines(ca_file), readLines(cert_file)), bundle_file)

  provider <- oauth_provider(
    name = "example",
    auth_url = "https://example.com/auth",
    token_url = "https://example.com/token",
    use_nonce = FALSE,
    use_pkce = TRUE,
    id_token_required = FALSE,
    id_token_validation = FALSE,
    token_auth_style = "body",
    tls_client_certificate_bound_access_tokens = TRUE
  )
  client <- oauth_client(
    provider = provider,
    client_id = "abc",
    client_secret = "",
    redirect_uri = "http://localhost:8100/callback",
    scopes = character(0),
    tls_client_cert_file = bundle_file,
    tls_client_key_file = key_file,
    tls_client_ca_file = ca_file
  )
  token <- OAuthToken(
    access_token = "at",
    token_type = "Bearer",
    userinfo = list(),
    cnf = list(
      `x5t#S256` = shinyOAuth:::tls_client_cert_thumbprint_s256(cert_file)
    )
  )

  expect_identical(
    shinyOAuth:::tls_client_cert_thumbprint_s256(
      bundle_file,
      key_file = key_file
    ),
    shinyOAuth:::tls_client_cert_thumbprint_s256(cert_file)
  )
  expect_invisible(shinyOAuth:::validate_token_certificate_binding(
    token,
    client
  ))
})

test_that("certificate thumbprints are cached for repeated PEM lookups", {
  cert_file <- mtls_pem_fixture("client-cert.pem")
  key_file <- mtls_pem_fixture("client-key.pem")
  ca_file <- mtls_pem_fixture("ca-cert.pem")
  bundle_a <- tempfile(fileext = ".pem")
  bundle_b <- tempfile(fileext = ".pem")
  on.exit(unlink(c(bundle_a, bundle_b), force = TRUE), add = TRUE)

  writeLines(c(readLines(ca_file), readLines(cert_file)), bundle_a)
  writeLines(readLines(cert_file), bundle_b)

  original_read_keyed_client_certificate <-
    shinyOAuth:::read_keyed_client_certificate
  parse_count <- 0L
  testthat::local_mocked_bindings(
    read_keyed_client_certificate = function(...) {
      parse_count <<- parse_count + 1L
      original_read_keyed_client_certificate(...)
    },
    .package = "shinyOAuth"
  )

  thumbprint_a <- shinyOAuth:::tls_client_cert_thumbprint_s256(
    bundle_a,
    key_file = key_file
  )
  thumbprint_a_cached <- shinyOAuth:::tls_client_cert_thumbprint_s256(
    bundle_a,
    key_file = key_file
  )
  thumbprint_b <- shinyOAuth:::tls_client_cert_thumbprint_s256(
    bundle_b,
    key_file = key_file
  )

  expect_identical(thumbprint_a_cached, thumbprint_a)
  expect_identical(thumbprint_b, thumbprint_a)
  expect_identical(parse_count, 2L)
})
