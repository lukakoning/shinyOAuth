test_that("client_secret_jwt composes client_assertion and omits secret in body", {
  prov <- oauth_provider(
    name = "example",
    auth_url = "https://example.com/auth",
    token_url = "https://example.com/token",
    issuer = "https://example.com",
    use_nonce = FALSE,
    use_pkce = TRUE,
    token_auth_style = "client_secret_jwt",
    id_token_required = FALSE,
    id_token_validation = FALSE
  )
  cli <- oauth_client(
    provider = prov,
    client_id = "abc",
    client_secret = paste(rep("s", 32), collapse = ""),
    redirect_uri = "http://localhost:8100",
    scopes = c("openid")
  )

  captured <- NULL
  # Capture the form params passed to req_body_form and return request
  testthat::local_mocked_bindings(
    req_body_form = function(req, ...) {
      captured <<- list(...)
      req
    },
    .package = "httr2"
  )
  # Return a simple JSON token response
  testthat::local_mocked_bindings(
    req_with_retry = function(req) {
      httr2::response(
        url = cli@provider@token_url,
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw(
          '{"access_token":"at","expires_in":3600,"token_type":"Bearer"}'
        )
      )
    }
  )

  ts <- shinyOAuth:::swap_code_for_token_set(
    cli,
    code = "code",
    code_verifier = "ver"
  )
  expect_equal(ts$access_token, "at")
  # Ensure client assertion fields present
  expect_identical(
    captured$client_assertion_type,
    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
  )
  expect_true(
    is.character(captured$client_assertion) && nzchar(captured$client_assertion)
  )
  # Ensure client_secret not sent in body
  expect_false("client_secret" %in% names(captured))
})

test_that("private_key_jwt composes client_assertion with kid and claims", {
  prov <- oauth_provider(
    name = "example",
    auth_url = "https://example.com/auth",
    token_url = "https://example.com/token",
    issuer = "https://example.com",
    use_nonce = FALSE,
    use_pkce = TRUE,
    token_auth_style = "private_key_jwt",
    id_token_required = FALSE,
    id_token_validation = FALSE
  )
  key <- openssl::rsa_keygen()
  cli <- oauth_client(
    provider = prov,
    client_id = "abc",
    client_secret = "",
    client_private_key = key,
    client_private_key_kid = "kid-123",
    redirect_uri = "http://localhost:8100",
    scopes = c("openid")
  )

  captured <- NULL
  testthat::local_mocked_bindings(
    req_body_form = function(req, ...) {
      captured <<- list(...)
      req
    },
    .package = "httr2"
  )
  testthat::local_mocked_bindings(
    req_with_retry = function(req) {
      httr2::response(
        url = cli@provider@token_url,
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw(
          '{"access_token":"at","expires_in":3600,"token_type":"Bearer"}'
        )
      )
    }
  )

  ts <- shinyOAuth:::swap_code_for_token_set(
    cli,
    code = "code",
    code_verifier = "ver"
  )
  expect_equal(ts$access_token, "at")
  # Validate assertion header/payload basics
  assertion <- captured$client_assertion
  hdr <- shinyOAuth:::parse_jwt_header(assertion)
  pl <- shinyOAuth:::parse_jwt_payload(assertion)
  expect_identical(hdr$typ, "JWT")
  expect_true(toupper(hdr$alg) %in% c("RS256", "PS256", "ES256", "EDDSA"))
  expect_identical(hdr$kid, "kid-123")
  expect_identical(pl$iss, "abc")
  expect_identical(pl$sub, "abc")
  expect_identical(pl$aud, prov@token_url)
  expect_true(is.numeric(pl$iat) && is.numeric(pl$exp) && pl$exp > pl$iat)
  expect_true(is.character(pl$jti) && nzchar(pl$jti))
})

test_that("client_assertion_audience overrides aud for token endpoint assertions", {
  prov <- oauth_provider(
    name = "example",
    auth_url = "https://example.com/auth",
    token_url = "https://example.com/token",
    issuer = "https://example.com",
    use_nonce = FALSE,
    use_pkce = TRUE,
    token_auth_style = "private_key_jwt",
    id_token_required = FALSE,
    id_token_validation = FALSE
  )
  key <- openssl::rsa_keygen()
  cli <- oauth_client(
    provider = prov,
    client_id = "abc",
    client_secret = "",
    client_private_key = key,
    redirect_uri = "http://localhost:8100",
    scopes = c("openid"),
    # Intentionally differ from token_url to verify override is respected
    client_assertion_audience = "https://example.com/token/"
  )

  captured <- NULL
  testthat::local_mocked_bindings(
    req_body_form = function(req, ...) {
      captured <<- list(...)
      req
    },
    .package = "httr2"
  )
  testthat::local_mocked_bindings(
    req_with_retry = function(req) {
      httr2::response(
        url = cli@provider@token_url,
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw(
          '{"access_token":"at","expires_in":3600,"token_type":"Bearer","refresh_token":"rt"}'
        )
      )
    }
  )

  ts <- shinyOAuth:::swap_code_for_token_set(
    cli,
    code = "code",
    code_verifier = "ver"
  )
  expect_equal(ts$access_token, "at")

  pl <- shinyOAuth:::parse_jwt_payload(captured$client_assertion)
  expect_identical(pl$aud, "https://example.com/token/")

  # Also cover refresh_token() path which uses the same resolver
  tok <- OAuthToken(
    access_token = "at-old",
    refresh_token = "rt",
    expires_at = as.numeric(Sys.time()) + 60,
    id_token = NA_character_
  )

  captured2 <- NULL
  testthat::local_mocked_bindings(
    req_body_form = function(req, ...) {
      captured2 <<- list(...)
      req
    },
    .package = "httr2"
  )
  testthat::local_mocked_bindings(
    req_with_retry = function(req) {
      httr2::response(
        url = cli@provider@token_url,
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw(
          '{"access_token":"at-new","expires_in":3600,"token_type":"Bearer"}'
        )
      )
    }
  )

  tok2 <- refresh_token(cli, tok, async = FALSE, introspect = FALSE)
  expect_identical(tok2@access_token, "at-new")
  pl2 <- shinyOAuth:::parse_jwt_payload(captured2$client_assertion)
  expect_identical(pl2$aud, "https://example.com/token/")
})

test_that("client_assertion_audience overrides aud for introspection/revocation assertions", {
  prov <- oauth_provider(
    name = "example",
    auth_url = "https://example.com/auth",
    token_url = "https://example.com/token",
    introspection_url = "https://example.com/introspect",
    revocation_url = "https://example.com/revoke",
    issuer = "https://example.com",
    use_nonce = FALSE,
    use_pkce = TRUE,
    token_auth_style = "private_key_jwt",
    id_token_required = FALSE,
    id_token_validation = FALSE
  )
  key <- openssl::rsa_keygen()
  cli <- oauth_client(
    provider = prov,
    client_id = "abc",
    client_secret = "",
    client_private_key = key,
    redirect_uri = "http://localhost:8100",
    scopes = c("openid"),
    client_assertion_audience = "https://example.com/token/"
  )
  tok <- OAuthToken(
    access_token = "at",
    refresh_token = "rt",
    expires_at = as.numeric(Sys.time()) + 60,
    id_token = NA_character_
  )

  # Revocation
  captured_revoke <- NULL
  testthat::local_mocked_bindings(
    req_body_form = function(req, ...) {
      captured_revoke <<- list(...)
      req
    },
    .package = "httr2"
  )
  testthat::local_mocked_bindings(
    req_with_retry = function(req) {
      httr2::response(
        url = prov@revocation_url,
        status = 200,
        headers = list("content-type" = "text/plain"),
        body = raw(0)
      )
    }
  )
  res_revoke <- revoke_token(cli, tok, which = "access", async = FALSE)
  expect_true(isTRUE(res_revoke$supported))
  expect_true(isTRUE(res_revoke$revoked))
  pl_revoke <- shinyOAuth:::parse_jwt_payload(captured_revoke$client_assertion)
  expect_identical(pl_revoke$aud, "https://example.com/token/")

  # Introspection
  captured_intro <- NULL
  testthat::local_mocked_bindings(
    req_body_form = function(req, ...) {
      captured_intro <<- list(...)
      req
    },
    .package = "httr2"
  )
  testthat::local_mocked_bindings(
    req_with_retry = function(req) {
      httr2::response(
        url = prov@introspection_url,
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw('{"active":true}')
      )
    }
  )
  res_intro <- introspect_token(cli, tok, which = "access", async = FALSE)
  expect_true(isTRUE(res_intro$supported))
  expect_true(isTRUE(res_intro$active))
  pl_intro <- shinyOAuth:::parse_jwt_payload(captured_intro$client_assertion)
  expect_identical(pl_intro$aud, "https://example.com/token/")
})
