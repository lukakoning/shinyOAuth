# Tests for OIDC Core 12.2: iss/aud consistency during token refresh
# verifies that verify_token_set() rejects refresh ID tokens with
# mismatched iss or aud relative to the original ID token.

# Helper: build a fake JWT from a named-list payload
make_fake_jwt <- function(payload) {
  paste(
    shinyOAuth:::base64url_encode(charToRaw('{"alg":"none"}')),
    shinyOAuth:::base64url_encode(charToRaw(jsonlite::toJSON(
      payload,
      auto_unbox = TRUE
    ))),
    "",
    sep = "."
  )
}

# Helper: build a standard provider+client pair for refresh tests
make_refresh_client <- function(
  id_token_validation = TRUE,
  issuer = "https://issuer.example.com",
  client_id = "abc"
) {
  prov <- oauth_provider(
    name = "oidc-example",
    auth_url = paste0(issuer, "/auth"),
    token_url = paste0(issuer, "/token"),
    issuer = issuer,
    id_token_validation = id_token_validation,
    id_token_required = FALSE,
    use_nonce = FALSE,
    use_pkce = TRUE,
    token_auth_style = "body"
  )
  oauth_client(
    provider = prov,
    client_id = client_id,
    client_secret = "",
    redirect_uri = "http://localhost:8100",
    state_store = cachem::cache_mem(max_age = 600),
    state_key = paste0(
      "0123456789abcdefghijklmnopqrstuvwxyz",
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    )
  )
}

# --- iss validation (validated path: id_token_validation = TRUE) ----------

test_that("refresh rejects new id_token with mismatched iss (validated path)", {
  withr::local_options(shinyOAuth.skip_id_sig = TRUE)
  cli <- make_refresh_client(id_token_validation = TRUE)

  original <- make_fake_jwt(list(
    iss = "https://issuer.example.com",
    sub = "user-1",
    aud = "abc",
    exp = as.numeric(Sys.time()) + 3600,
    iat = as.numeric(Sys.time()) - 60
  ))

  # New token has a different issuer
  new_jwt <- make_fake_jwt(list(
    iss = "https://other-issuer.example.com",
    sub = "user-1",
    aud = "abc",
    exp = as.numeric(Sys.time()) + 3600,
    iat = as.numeric(Sys.time())
  ))

  testthat::local_mocked_bindings(
    req_with_retry = function(req) {
      body <- sprintf(
        '{"access_token":"new_at","token_type":"Bearer","expires_in":3600,"id_token":"%s"}',
        new_jwt
      )
      httr2::response(
        url = as.character(req$url),
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw(body)
      )
    },
    .package = "shinyOAuth"
  )

  t <- OAuthToken(
    access_token = "old_at",
    refresh_token = "rt",
    expires_at = as.numeric(Sys.time()) + 10,
    id_token = original
  )

  # Should reject because validate_id_token() checks iss == provider@issuer
  # and the new iss doesn't match provider config ("https://issuer.example.com")
  expect_error(
    refresh_token(cli, t, async = FALSE, introspect = FALSE),
    class = "shinyOAuth_id_token_error"
  )
})

test_that("refresh rejects new id_token with mismatched iss (non-validated path)", {
  # id_token_validation = FALSE means signature/claims are not fully checked,

  # but OIDC 12.2 iss comparison against original must still fire.
  cli <- make_refresh_client(id_token_validation = FALSE)

  original <- make_fake_jwt(list(
    iss = "https://issuer.example.com",
    sub = "user-1",
    aud = "abc",
    exp = as.numeric(Sys.time()) + 3600,
    iat = as.numeric(Sys.time()) - 60
  ))

  new_jwt <- make_fake_jwt(list(
    iss = "https://other-issuer.example.com",
    sub = "user-1",
    aud = "abc",
    exp = as.numeric(Sys.time()) + 3600,
    iat = as.numeric(Sys.time())
  ))

  testthat::local_mocked_bindings(
    req_with_retry = function(req) {
      body <- sprintf(
        '{"access_token":"new_at","token_type":"Bearer","expires_in":3600,"id_token":"%s"}',
        new_jwt
      )
      httr2::response(
        url = as.character(req$url),
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw(body)
      )
    },
    .package = "shinyOAuth"
  )

  t <- OAuthToken(
    access_token = "old_at",
    refresh_token = "rt",
    expires_at = as.numeric(Sys.time()) + 10,
    id_token = original
  )

  expect_error(
    refresh_token(cli, t, async = FALSE, introspect = FALSE),
    regexp = "iss.*does not match the original",
    class = "shinyOAuth_id_token_error"
  )
})

# --- aud validation (validated path) ----------------------------------------

test_that("refresh rejects new id_token with mismatched aud (validated path)", {
  withr::local_options(shinyOAuth.skip_id_sig = TRUE)
  cli <- make_refresh_client(id_token_validation = TRUE)

  # Original has aud = ["abc", "resource-api"]
  original <- make_fake_jwt(list(
    iss = "https://issuer.example.com",
    sub = "user-1",
    aud = c("abc", "resource-api"),
    azp = "abc",
    exp = as.numeric(Sys.time()) + 3600,
    iat = as.numeric(Sys.time()) - 60
  ))

  # New token has aud = ["abc"] only (dropped resource-api)
  new_jwt <- make_fake_jwt(list(
    iss = "https://issuer.example.com",
    sub = "user-1",
    aud = "abc",
    exp = as.numeric(Sys.time()) + 3600,
    iat = as.numeric(Sys.time())
  ))

  testthat::local_mocked_bindings(
    req_with_retry = function(req) {
      body <- sprintf(
        '{"access_token":"new_at","token_type":"Bearer","expires_in":3600,"id_token":"%s"}',
        new_jwt
      )
      httr2::response(
        url = as.character(req$url),
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw(body)
      )
    },
    .package = "shinyOAuth"
  )

  t <- OAuthToken(
    access_token = "old_at",
    refresh_token = "rt",
    expires_at = as.numeric(Sys.time()) + 10,
    id_token = original
  )

  expect_error(
    refresh_token(cli, t, async = FALSE, introspect = FALSE),
    regexp = "aud.*does not match the original",
    class = "shinyOAuth_id_token_error"
  )
})

test_that("refresh rejects new id_token with mismatched aud (non-validated path)", {
  cli <- make_refresh_client(id_token_validation = FALSE)

  original <- make_fake_jwt(list(
    iss = "https://issuer.example.com",
    sub = "user-1",
    aud = c("abc", "resource-api"),
    azp = "abc",
    exp = as.numeric(Sys.time()) + 3600,
    iat = as.numeric(Sys.time()) - 60
  ))

  new_jwt <- make_fake_jwt(list(
    iss = "https://issuer.example.com",
    sub = "user-1",
    aud = "abc",
    exp = as.numeric(Sys.time()) + 3600,
    iat = as.numeric(Sys.time())
  ))

  testthat::local_mocked_bindings(
    req_with_retry = function(req) {
      body <- sprintf(
        '{"access_token":"new_at","token_type":"Bearer","expires_in":3600,"id_token":"%s"}',
        new_jwt
      )
      httr2::response(
        url = as.character(req$url),
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw(body)
      )
    },
    .package = "shinyOAuth"
  )

  t <- OAuthToken(
    access_token = "old_at",
    refresh_token = "rt",
    expires_at = as.numeric(Sys.time()) + 10,
    id_token = original
  )

  expect_error(
    refresh_token(cli, t, async = FALSE, introspect = FALSE),
    regexp = "aud.*does not match the original",
    class = "shinyOAuth_id_token_error"
  )
})

# --- Happy paths: matching iss/aud accepted ---------------------------------

test_that("refresh accepts new id_token with matching iss and aud (validated path)", {
  withr::local_options(shinyOAuth.skip_id_sig = TRUE)
  cli <- make_refresh_client(id_token_validation = TRUE)

  original <- make_fake_jwt(list(
    iss = "https://issuer.example.com",
    sub = "user-1",
    aud = "abc",
    exp = as.numeric(Sys.time()) + 3600,
    iat = as.numeric(Sys.time()) - 60
  ))

  new_jwt <- make_fake_jwt(list(
    iss = "https://issuer.example.com",
    sub = "user-1",
    aud = "abc",
    exp = as.numeric(Sys.time()) + 3600,
    iat = as.numeric(Sys.time())
  ))

  testthat::local_mocked_bindings(
    req_with_retry = function(req) {
      body <- sprintf(
        '{"access_token":"new_at","token_type":"Bearer","expires_in":3600,"id_token":"%s"}',
        new_jwt
      )
      httr2::response(
        url = as.character(req$url),
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw(body)
      )
    },
    .package = "shinyOAuth"
  )

  t <- OAuthToken(
    access_token = "old_at",
    refresh_token = "rt",
    expires_at = as.numeric(Sys.time()) + 10,
    id_token = original
  )

  t2 <- refresh_token(cli, t, async = FALSE, introspect = FALSE)
  expect_true(S7::S7_inherits(t2, OAuthToken))
  expect_identical(t2@access_token, "new_at")
  expect_identical(t2@id_token, new_jwt)
})

test_that("refresh accepts matching iss/aud with multi-audience (validated path)", {
  withr::local_options(shinyOAuth.skip_id_sig = TRUE)
  cli <- make_refresh_client(id_token_validation = TRUE)

  # Both original and new have same multi-audience set
  original <- make_fake_jwt(list(
    iss = "https://issuer.example.com",
    sub = "user-1",
    aud = c("abc", "resource-api"),
    azp = "abc",
    exp = as.numeric(Sys.time()) + 3600,
    iat = as.numeric(Sys.time()) - 60
  ))

  new_jwt <- make_fake_jwt(list(
    iss = "https://issuer.example.com",
    sub = "user-1",
    aud = c("resource-api", "abc"), # Same set, different order
    azp = "abc",
    exp = as.numeric(Sys.time()) + 3600,
    iat = as.numeric(Sys.time())
  ))

  testthat::local_mocked_bindings(
    req_with_retry = function(req) {
      body <- sprintf(
        '{"access_token":"new_at","token_type":"Bearer","expires_in":3600,"id_token":"%s"}',
        new_jwt
      )
      httr2::response(
        url = as.character(req$url),
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw(body)
      )
    },
    .package = "shinyOAuth"
  )

  t <- OAuthToken(
    access_token = "old_at",
    refresh_token = "rt",
    expires_at = as.numeric(Sys.time()) + 10,
    id_token = original
  )

  t2 <- refresh_token(cli, t, async = FALSE, introspect = FALSE)
  expect_true(S7::S7_inherits(t2, OAuthToken))
  expect_identical(t2@access_token, "new_at")
})

test_that("refresh accepts matching iss/aud (non-validated path)", {
  cli <- make_refresh_client(id_token_validation = FALSE)

  original <- make_fake_jwt(list(
    iss = "https://issuer.example.com",
    sub = "user-1",
    aud = "abc",
    exp = as.numeric(Sys.time()) + 3600,
    iat = as.numeric(Sys.time()) - 60
  ))

  new_jwt <- make_fake_jwt(list(
    iss = "https://issuer.example.com",
    sub = "user-1",
    aud = "abc",
    exp = as.numeric(Sys.time()) + 3600,
    iat = as.numeric(Sys.time())
  ))

  testthat::local_mocked_bindings(
    req_with_retry = function(req) {
      body <- sprintf(
        '{"access_token":"new_at","token_type":"Bearer","expires_in":3600,"id_token":"%s"}',
        new_jwt
      )
      httr2::response(
        url = as.character(req$url),
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw(body)
      )
    },
    .package = "shinyOAuth"
  )

  t <- OAuthToken(
    access_token = "old_at",
    refresh_token = "rt",
    expires_at = as.numeric(Sys.time()) + 10,
    id_token = original
  )

  t2 <- refresh_token(cli, t, async = FALSE, introspect = FALSE)
  expect_true(S7::S7_inherits(t2, OAuthToken))
  expect_identical(t2@access_token, "new_at")
})

# --- Trailing-slash tolerance -----------------------------------------------

test_that("refresh iss comparison tolerates trailing slash difference", {
  withr::local_options(shinyOAuth.skip_id_sig = TRUE)
  cli <- make_refresh_client(id_token_validation = TRUE)

  # Original has trailing slash, new does not (or vice versa)
  original <- make_fake_jwt(list(
    iss = "https://issuer.example.com/",
    sub = "user-1",
    aud = "abc",
    exp = as.numeric(Sys.time()) + 3600,
    iat = as.numeric(Sys.time()) - 60
  ))

  new_jwt <- make_fake_jwt(list(
    iss = "https://issuer.example.com",
    sub = "user-1",
    aud = "abc",
    exp = as.numeric(Sys.time()) + 3600,
    iat = as.numeric(Sys.time())
  ))

  testthat::local_mocked_bindings(
    req_with_retry = function(req) {
      body <- sprintf(
        '{"access_token":"new_at","token_type":"Bearer","expires_in":3600,"id_token":"%s"}',
        new_jwt
      )
      httr2::response(
        url = as.character(req$url),
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw(body)
      )
    },
    .package = "shinyOAuth"
  )

  t <- OAuthToken(
    access_token = "old_at",
    refresh_token = "rt",
    expires_at = as.numeric(Sys.time()) + 10,
    id_token = original
  )

  # Should succeed despite trailing slash difference
  t2 <- refresh_token(cli, t, async = FALSE, introspect = FALSE)
  expect_true(S7::S7_inherits(t2, OAuthToken))
})

# --- verify_token_set directly (unit-level) ----------------------------------

test_that("verify_token_set rejects mismatched iss on refresh (direct call)", {
  cli <- make_refresh_client(id_token_validation = FALSE)

  original <- make_fake_jwt(list(
    iss = "https://issuer.example.com",
    sub = "user-1",
    aud = "abc",
    exp = as.numeric(Sys.time()) + 3600,
    iat = as.numeric(Sys.time()) - 60
  ))

  new_jwt <- make_fake_jwt(list(
    iss = "https://evil.example.com",
    sub = "user-1",
    aud = "abc",
    exp = as.numeric(Sys.time()) + 3600,
    iat = as.numeric(Sys.time())
  ))

  token_set <- list(
    access_token = "new_at",
    token_type = "Bearer",
    id_token = new_jwt,
    expires_in = 3600
  )

  expect_error(
    shinyOAuth:::verify_token_set(
      cli,
      token_set = token_set,
      nonce = NULL,
      is_refresh = TRUE,
      original_id_token = original
    ),
    regexp = "iss.*does not match the original",
    class = "shinyOAuth_id_token_error"
  )
})

test_that("verify_token_set rejects mismatched aud on refresh (direct call)", {
  cli <- make_refresh_client(id_token_validation = FALSE)

  original <- make_fake_jwt(list(
    iss = "https://issuer.example.com",
    sub = "user-1",
    aud = c("abc", "other-api"),
    azp = "abc",
    exp = as.numeric(Sys.time()) + 3600,
    iat = as.numeric(Sys.time()) - 60
  ))

  new_jwt <- make_fake_jwt(list(
    iss = "https://issuer.example.com",
    sub = "user-1",
    aud = c("abc", "different-api"), # changed additional audience
    azp = "abc",
    exp = as.numeric(Sys.time()) + 3600,
    iat = as.numeric(Sys.time())
  ))

  token_set <- list(
    access_token = "new_at",
    token_type = "Bearer",
    id_token = new_jwt,
    expires_in = 3600
  )

  expect_error(
    shinyOAuth:::verify_token_set(
      cli,
      token_set = token_set,
      nonce = NULL,
      is_refresh = TRUE,
      original_id_token = original
    ),
    regexp = "aud.*does not match the original",
    class = "shinyOAuth_id_token_error"
  )
})

test_that("verify_token_set accepts matching iss/aud on refresh (direct call)", {
  cli <- make_refresh_client(id_token_validation = FALSE)

  original <- make_fake_jwt(list(
    iss = "https://issuer.example.com",
    sub = "user-1",
    aud = "abc",
    exp = as.numeric(Sys.time()) + 3600,
    iat = as.numeric(Sys.time()) - 60
  ))

  new_jwt <- make_fake_jwt(list(
    iss = "https://issuer.example.com",
    sub = "user-1",
    aud = "abc",
    exp = as.numeric(Sys.time()) + 3600,
    iat = as.numeric(Sys.time())
  ))

  token_set <- list(
    access_token = "new_at",
    token_type = "Bearer",
    id_token = new_jwt,
    expires_in = 3600
  )

  result <- shinyOAuth:::verify_token_set(
    cli,
    token_set = token_set,
    nonce = NULL,
    is_refresh = TRUE,
    original_id_token = original
  )
  expect_identical(result$access_token, "new_at")
})
