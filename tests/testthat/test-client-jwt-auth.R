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
    req_with_retry = function(req, ...) {
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
  expect_equal(ts[["access_token"]], "at")
  # Ensure client assertion fields present
  expect_identical(
    captured[["client_assertion_type"]],
    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
  )
  expect_true(
    is.character(captured[["client_assertion"]]) &&
      nzchar(captured[["client_assertion"]])
  )
  # Ensure client_secret not sent in body
  expect_false("client_secret" %in% names(captured))
})

test_that("client_secret_jwt enforces RFC 7518 HMAC secret lengths", {
  prov <- oauth_provider(
    name = "example",
    auth_url = "https://example.com/auth",
    token_url = "https://example.com/token",
    issuer = "https://example.com",
    use_nonce = FALSE,
    use_pkce = TRUE,
    token_auth_style = "client_secret_jwt",
    token_endpoint_auth_signing_alg_values_supported = c("HS384", "HS512"),
    id_token_required = FALSE,
    id_token_validation = FALSE
  )

  cases <- c(HS384 = 48L, HS512 = 64L)
  for (alg in names(cases)) {
    expect_error(
      oauth_client(
        provider = prov,
        client_id = "abc",
        client_secret = strrep("s", cases[[alg]] - 1L),
        redirect_uri = "http://localhost:8100",
        scopes = c("openid"),
        client_assertion_alg = alg
      ),
      regexp = paste0(
        "client_assertion_alg '",
        alg,
        "'.*>= ",
        cases[[alg]],
        " bytes"
      ),
      info = alg
    )
  }

  expect_silent(
    oauth_client(
      provider = prov,
      client_id = "abc",
      client_secret = strrep("s", 64L),
      redirect_uri = "http://localhost:8100",
      scopes = c("openid"),
      client_assertion_alg = "HS512"
    )
  )
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
    client_assertion_private_key = key,
    client_assertion_private_key_kid = "kid-123",
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
    req_with_retry = function(req, ...) {
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
  expect_equal(ts[["access_token"]], "at")
  # Validate assertion header/payload basics
  assertion <- captured[["client_assertion"]]
  hdr <- shinyOAuth:::parse_jwt_header(assertion)
  pl <- shinyOAuth:::parse_jwt_payload(assertion)
  expect_identical(hdr[["typ"]], "JWT")
  expect_identical(hdr[["alg"]], "RS256")
  expect_identical(hdr[["kid"]], "kid-123")
  expect_identical(pl[["iss"]], "abc")
  expect_identical(pl[["sub"]], "abc")
  expect_identical(pl[["aud"]], prov@token_url)
  expect_true(
    is.numeric(pl[["iat"]]) &&
      is.numeric(pl[["exp"]]) &&
      pl[["exp"]] > pl[["iat"]]
  )
  expect_true(
    is.character(pl[["jti"]]) &&
      nzchar(pl[["jti"]])
  )
})

test_that("provider metadata rejects unsupported JWT client assertion algs", {
  prov_private <- oauth_provider(
    name = "example",
    auth_url = "https://example.com/auth",
    token_url = "https://example.com/token",
    issuer = "https://example.com",
    use_nonce = FALSE,
    use_pkce = TRUE,
    token_auth_style = "private_key_jwt",
    token_endpoint_auth_signing_alg_values_supported = c("PS256"),
    id_token_required = FALSE,
    id_token_validation = FALSE
  )
  key <- openssl::rsa_keygen()

  expect_error(
    oauth_client(
      provider = prov_private,
      client_id = "abc",
      client_secret = "",
      client_assertion_private_key = key,
      redirect_uri = "http://localhost:8100",
      scopes = c("openid")
    ),
    regexp = paste(
      "client_assertion_alg 'RS256' is not supported by",
      "provider token_endpoint_auth_signing_alg_values_supported"
    )
  )

  prov_secret <- oauth_provider(
    name = "example",
    auth_url = "https://example.com/auth",
    token_url = "https://example.com/token",
    issuer = "https://example.com",
    use_nonce = FALSE,
    use_pkce = TRUE,
    token_auth_style = "client_secret_jwt",
    token_endpoint_auth_signing_alg_values_supported = c("HS512"),
    id_token_required = FALSE,
    id_token_validation = FALSE
  )

  expect_error(
    oauth_client(
      provider = prov_secret,
      client_id = "abc",
      client_secret = paste(rep("s", 32), collapse = ""),
      redirect_uri = "http://localhost:8100",
      scopes = c("openid"),
      client_assertion_alg = "HS256"
    ),
    regexp = paste(
      "client_assertion_alg 'HS256' is not supported by",
      "provider token_endpoint_auth_signing_alg_values_supported"
    )
  )
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
    client_assertion_private_key = key,
    redirect_uri = "http://localhost:8100",
    scopes = c("openid"),
    # Intentionally differ from token_url to verify override is respected
    client_assertion_audience = "https://example.com/token/",
    # Disable scope validation since this test is about JWT assertions
    scope_validation = "none"
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
    req_with_retry = function(req, ...) {
      httr2::response(
        url = cli@provider@token_url,
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw(
          '{"access_token":"at","expires_in":3600,"token_type":"Bearer","refresh_token":"rt","scope":"openid"}'
        )
      )
    },
    .package = "shinyOAuth"
  )

  ts <- shinyOAuth:::swap_code_for_token_set(
    cli,
    code = "code",
    code_verifier = "ver"
  )
  expect_equal(ts[["access_token"]], "at")

  pl <- shinyOAuth:::parse_jwt_payload(captured[["client_assertion"]])
  expect_identical(pl[["aud"]], "https://example.com/token/")

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
    req_with_retry = function(req, ...) {
      httr2::response(
        url = cli@provider@token_url,
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw(
          '{"access_token":"at-new","expires_in":3600,"token_type":"Bearer","scope":"openid"}'
        )
      )
    },
    .package = "shinyOAuth"
  )

  tok2 <- refresh_token(cli, tok, async = FALSE, introspect = FALSE)
  expect_identical(tok2@access_token, "at-new")
  pl2 <- shinyOAuth:::parse_jwt_payload(captured2[["client_assertion"]])
  expect_identical(pl2[["aud"]], "https://example.com/token/")
})

test_that("oauth_client_secret_apple composes expected ES256 JWT", {
  testthat::skip_if_not_installed("jose")

  key <- openssl::ec_keygen(curve = "P-256")
  secret <- oauth_client_secret_apple(
    client_id = "com.example.web",
    team_id = "ABCDEFGHIJ",
    key_id = "ABC123DEFG",
    private_key = key,
    expires_in = 300,
    issued_at = 1700000000
  )

  header <- shinyOAuth:::parse_jwt_header(secret)
  payload <- shinyOAuth:::parse_jwt_payload(secret)

  expect_identical(header[["alg"]], "ES256")
  expect_identical(header[["kid"]], "ABC123DEFG")
  expect_identical(payload[["iss"]], "ABCDEFGHIJ")
  expect_identical(payload[["sub"]], "com.example.web")
  expect_identical(payload[["aud"]], "https://appleid.apple.com")
  expect_equal(payload[["iat"]], 1700000000)
  expect_equal(payload[["exp"]], 1700000300)
})

test_that("oauth_client_secret_apple validates expiration and key type", {
  expect_error(
    oauth_client_secret_apple(
      client_id = "com.example.web",
      team_id = "ABCDEFGHIJ",
      key_id = "ABC123DEFG",
      private_key = openssl::ec_keygen(curve = "P-256"),
      expires_in = 15777001
    ),
    regexp = "15777000"
  )

  expect_error(
    oauth_client_secret_apple(
      client_id = "com.example.web",
      team_id = "ABCDEFGHIJ",
      key_id = "ABC123DEFG",
      private_key = openssl::rsa_keygen()
    ),
    regexp = "ES256-compatible"
  )
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
    client_assertion_private_key = key,
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
    req_with_retry = function(req, ...) {
      httr2::response(
        url = prov@revocation_url,
        status = 200,
        headers = list("content-type" = "text/plain"),
        body = raw(0)
      )
    }
  )
  res_revoke <- revoke_token(cli, tok, which = "access", async = FALSE)
  expect_true(isTRUE(res_revoke[["supported"]]))
  expect_true(isTRUE(res_revoke[["revoked"]]))
  pl_revoke <- shinyOAuth:::parse_jwt_payload(
    captured_revoke[["client_assertion"]]
  )
  expect_identical(pl_revoke[["aud"]], "https://example.com/token/")

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
    req_with_retry = function(req, ...) {
      httr2::response(
        url = prov@introspection_url,
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw('{"active":true}')
      )
    }
  )
  res_intro <- introspect_token(cli, tok, which = "access", async = FALSE)
  expect_true(isTRUE(res_intro[["supported"]]))
  expect_true(isTRUE(res_intro[["active"]]))
  pl_intro <- shinyOAuth:::parse_jwt_payload(
    captured_intro[["client_assertion"]]
  )
  expect_identical(pl_intro[["aud"]], "https://example.com/token/")
})

test_that("revocation and introspection retries rebuild JWT client assertions", {
  request_body_text <- function(req) {
    body <- req[["body"]] %||% NULL
    if (is.null(body)) {
      return(NA_character_)
    }
    if (identical(body[["type"]], "raw")) {
      return(rawToChar(body[["data"]]))
    }
    if (identical(body[["type"]], "form")) {
      data <- body[["data"]] %||% list()
      if (!length(data)) {
        return("")
      }

      parts <- unlist(
        lapply(seq_along(data), function(i) {
          nm <- names(data)[[i]]
          paste0(
            nm,
            "=",
            utils::URLencode(as.character(data[[i]])[[1]], reserved = TRUE)
          )
        }),
        use.names = FALSE
      )
      return(paste(parts, collapse = "&"))
    }

    NA_character_
  }

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
  cli <- oauth_client(
    provider = prov,
    client_id = "abc",
    client_secret = "",
    client_assertion_private_key = openssl::rsa_keygen(),
    redirect_uri = "http://localhost:8100",
    scopes = c("openid")
  )
  tok <- OAuthToken(
    access_token = "at",
    refresh_token = "rt",
    expires_at = as.numeric(Sys.time()) + 60,
    id_token = NA_character_
  )
  seen_jtis <- new.env(parent = emptyenv())
  seen_jtis$revoke <- character(0)
  seen_jtis$introspect <- character(0)

  withr::local_options(list(
    shinyOAuth.retry_max_tries = 2L,
    shinyOAuth.retry_backoff_base = 0.01,
    shinyOAuth.retry_backoff_cap = 0.01
  ))

  testthat::local_mocked_bindings(
    req_perform = function(req) {
      body_text <- request_body_text(req)
      assertion <- parse_query_param(
        paste0("https://example.com/?", body_text),
        "client_assertion",
        decode = TRUE
      )
      payload <- shinyOAuth:::parse_jwt_payload(assertion)
      bucket <- if (
        identical(as.character(req[["url"]]), prov@revocation_url)
      ) {
        "revoke"
      } else {
        "introspect"
      }
      seen_jtis[[bucket]] <- c(
        seen_jtis[[bucket]],
        payload[["jti"]] %||% NA_character_
      )

      if (length(seen_jtis[[bucket]]) == 1L) {
        return(httr2::response(
          url = as.character(req[["url"]]),
          status = 500,
          headers = list("content-type" = "application/json"),
          body = charToRaw("{}")
        ))
      }

      if (identical(bucket, "revoke")) {
        return(httr2::response(
          url = as.character(req[["url"]]),
          status = 200,
          headers = list("content-type" = "text/plain"),
          body = raw(0)
        ))
      }

      httr2::response(
        url = as.character(req[["url"]]),
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw('{"active":true}')
      )
    },
    .package = "httr2"
  )
  testthat::local_mocked_bindings(
    Sys.sleep = function(time) invisible(NULL),
    .package = "base"
  )

  revoke_res <- revoke_token(cli, tok, which = "access", async = FALSE)
  intro_res <- introspect_token(cli, tok, which = "access", async = FALSE)

  expect_true(isTRUE(revoke_res[["revoked"]]))
  expect_true(isTRUE(intro_res[["active"]]))
  expect_length(seen_jtis$revoke, 2L)
  expect_length(unique(seen_jtis$revoke), 2L)
  expect_length(seen_jtis$introspect, 2L)
  expect_length(unique(seen_jtis$introspect), 2L)
})
