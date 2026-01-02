testthat::test_that("refresh_token errors when missing refresh token", {
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  t <- OAuthToken(
    access_token = "at",
    refresh_token = NA_character_,
    expires_at = as.numeric(Sys.time()) + 10,
    id_token = NA_character_
  )
  testthat::expect_error(
    refresh_token(cli, t, async = FALSE),
    class = "shinyOAuth_input_error"
  )
})

testthat::test_that("refresh_token success updates tokens and preserves when not rotated", {
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  # Ensure provider expects body auth to exercise param paths
  cli@provider@token_auth_style <- "body"

  # Case A: rotation -> new refresh_token returned
  testthat::local_mocked_bindings(
    req_with_retry = function(req) {
      # Verify body form has grant_type=refresh_token
      # We can't easily read it here; assume methods__token builds it correctly.
      httr2::response(
        url = as.character(req$url),
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw(
          '{"access_token":"new_at","refresh_token":"new_rt","expires_in":3600}'
        )
      )
    },
    .package = "shinyOAuth"
  )
  t <- OAuthToken(
    access_token = "old_at",
    refresh_token = "old_rt",
    expires_at = as.numeric(Sys.time()) + 10,
    id_token = NA_character_
  )
  t2 <- refresh_token(cli, t, async = FALSE, introspect = FALSE)
  testthat::expect_true(S7::S7_inherits(t2, OAuthToken))
  testthat::expect_identical(t2@access_token, "new_at")
  testthat::expect_identical(t2@refresh_token, "new_rt")
  testthat::expect_true(is.finite(t2@expires_at))

  # Case B: no rotation -> provider omits refresh_token or empty -> keep old
  testthat::local_mocked_bindings(
    req_with_retry = function(req) {
      httr2::response(
        url = as.character(req$url),
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw('{"access_token":"newer_at","expires_in":"60"}')
      )
    },
    .package = "shinyOAuth"
  )
  kept_rt <- t2@refresh_token
  t3 <- refresh_token(cli, t2, async = FALSE, introspect = FALSE)
  testthat::expect_identical(t3@access_token, "newer_at")
  testthat::expect_identical(t3@refresh_token, kept_rt)
  # expires_in was a quoted string -> coerce_expires_in -> finite expires_at
  testthat::expect_true(is.finite(t3@expires_at))
})

testthat::test_that("refresh_token can fetch userinfo and optionally introspect", {
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  # Set URLs first to satisfy provider validation when toggling userinfo_required
  cli@provider@userinfo_url <- "https://example.com/userinfo"
  cli@provider@introspection_url <- "https://example.com/introspect"
  cli@provider@userinfo_required <- TRUE

  # First, mock both token response and userinfo + introspection
  calls <- list(token = 0L, userinfo = 0L, introspection = 0L)
  testthat::local_mocked_bindings(
    req_with_retry = function(req) {
      url <- as.character(req$url)
      if (grepl("/token", url, fixed = TRUE)) {
        calls$token <<- calls$token + 1L
        httr2::response(
          url = url,
          status = 200,
          headers = list("content-type" = "application/json"),
          body = charToRaw('{"access_token":"at3","expires_in":120}')
        )
      } else if (grepl("/userinfo", url, fixed = TRUE)) {
        calls$userinfo <<- calls$userinfo + 1L
        httr2::response(
          url = url,
          status = 200,
          headers = list("content-type" = "application/json"),
          body = charToRaw('{"sub":"u-42"}')
        )
      } else if (grepl("/introspect", url, fixed = TRUE)) {
        calls$introspection <<- calls$introspection + 1L
        httr2::response(
          url = url,
          status = 200,
          headers = list("content-type" = "application/json"),
          body = charToRaw('{"active":true}')
        )
      } else {
        httr2::response(url = url, status = 200)
      }
    },
    .package = "shinyOAuth"
  )

  t <- OAuthToken(
    access_token = "old",
    refresh_token = "rt",
    expires_at = as.numeric(Sys.time()) + 10,
    id_token = NA_character_
  )
  t4 <- refresh_token(cli, t, async = FALSE, introspect = TRUE)
  testthat::expect_true(S7::S7_inherits(t4, OAuthToken))
  testthat::expect_true(is.list(t4@userinfo))
  testthat::expect_identical(t4@userinfo$sub, "u-42")
  # We expect at least one token call and one userinfo call
  testthat::expect_gte(calls$token, 1L)
  testthat::expect_gte(calls$userinfo, 1L)
  # Introspection is best-effort/optional, but with introspect=TRUE and URL set,
  # it should have been called once.
  testthat::expect_gte(calls$introspection, 1L)
})

testthat::test_that("refresh_token treats expires_in = 0 as expiring now", {
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)

  testthat::local_mocked_bindings(
    req_with_retry = function(req) {
      httr2::response(
        url = as.character(req$url),
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw('{"access_token":"new_at","expires_in":0}')
      )
    },
    .package = "shinyOAuth"
  )

  t <- OAuthToken(
    access_token = "old_at",
    refresh_token = "rt",
    expires_at = as.numeric(Sys.time()) + 10,
    id_token = NA_character_
  )

  before <- as.numeric(Sys.time())
  testthat::expect_warning(
    t2 <- refresh_token(cli, t, async = FALSE, introspect = FALSE),
    regexp = "expires_in = 0",
    fixed = TRUE
  )
  after <- as.numeric(Sys.time())

  testthat::expect_true(is.finite(t2@expires_at))
  testthat::expect_gte(t2@expires_at, before)
  testthat::expect_lte(t2@expires_at, after + 1)
})

testthat::test_that("refresh_token rejects negative expires_in", {
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)

  testthat::local_mocked_bindings(
    req_with_retry = function(req) {
      httr2::response(
        url = as.character(req$url),
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw('{"access_token":"new_at","expires_in":-1}')
      )
    },
    .package = "shinyOAuth"
  )

  t <- OAuthToken(
    access_token = "old_at",
    refresh_token = "rt",
    expires_at = as.numeric(Sys.time()) + 10,
    id_token = NA_character_
  )

  testthat::expect_error(
    refresh_token(cli, t, async = FALSE, introspect = FALSE),
    class = "shinyOAuth_token_error"
  )
})

testthat::test_that("refresh_token succeeds with id_token_validation=TRUE when refresh response omits id_token", {
  # Per OIDC spec, refresh responses may omit the ID token. When

  # id_token_validation = TRUE the semantics are "validate if present",
  # not "require presence". This test ensures we don't regress to treating
  # id_token_validation as making the ID token mandatory during refresh.
  prov <- oauth_provider(
    name = "oidc-example",
    auth_url = "https://issuer.example.com/auth",
    token_url = "https://issuer.example.com/token",
    issuer = "https://issuer.example.com",
    id_token_validation = TRUE,
    id_token_required = FALSE,
    use_nonce = FALSE,
    use_pkce = TRUE,
    token_auth_style = "body"
  )
  cli <- oauth_client(
    provider = prov,
    client_id = "abc",
    client_secret = "",
    redirect_uri = "http://localhost:8100",
    state_store = cachem::cache_mem(max_age = 600),
    state_key = paste0(
      "0123456789abcdefghijklmnopqrstuvwxyz",
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    )
  )

  # Mock a refresh response that does NOT include an id_token
  testthat::local_mocked_bindings(
    req_with_retry = function(req) {
      httr2::response(
        url = as.character(req$url),
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw(
          '{"access_token":"new_at","token_type":"Bearer","expires_in":3600}'
        )
      )
    },
    .package = "shinyOAuth"
  )

  t <- OAuthToken(
    access_token = "old_at",
    refresh_token = "rt",
    expires_at = as.numeric(Sys.time()) + 10,
    id_token = NA_character_
  )

  # Should succeed: id_token_validation = TRUE means validate-if-present,
  # not require-presence. Refresh responses commonly omit the ID token.
  t2 <- refresh_token(cli, t, async = FALSE, introspect = FALSE)
  testthat::expect_true(S7::S7_inherits(t2, OAuthToken))
  testthat::expect_identical(t2@access_token, "new_at")
})

testthat::test_that("refresh_token rejects new id_token with mismatched sub (OIDC 12.2)", {
  # OIDC Core Section 12.2 requires that if a new ID token is returned during
  # refresh, its sub claim MUST match the original. This prevents token
  # substitution attacks where a malicious provider returns a different user's
  # ID token.

  # Create a valid original ID token (we'll mock validation to skip signature)
  original_sub <- "user-123"

  prov <- oauth_provider(
    name = "oidc-example",
    auth_url = "https://issuer.example.com/auth",
    token_url = "https://issuer.example.com/token",
    issuer = "https://issuer.example.com",
    id_token_validation = TRUE,
    id_token_required = FALSE,
    use_nonce = FALSE,
    use_pkce = TRUE,
    token_auth_style = "body"
  )
  cli <- oauth_client(
    provider = prov,
    client_id = "abc",
    client_secret = "",
    redirect_uri = "http://localhost:8100",
    state_store = cachem::cache_mem(max_age = 600),
    state_key = paste0(
      "0123456789abcdefghijklmnopqrstuvwxyz",
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    )
  )

  # Create a fake original ID token payload with sub=user-123
  original_payload <- list(
    iss = "https://issuer.example.com",
    sub = original_sub,
    aud = "abc",
    exp = as.numeric(Sys.time()) + 3600,
    iat = as.numeric(Sys.time())
  )
  original_id_token <- paste(
    shinyOAuth:::base64url_encode(charToRaw('{"alg":"none"}')),
    shinyOAuth:::base64url_encode(charToRaw(jsonlite::toJSON(
      original_payload,
      auto_unbox = TRUE
    ))),
    "",
    sep = "."
  )

  # Create a new ID token with DIFFERENT sub
  new_payload <- list(
    iss = "https://issuer.example.com",
    sub = "attacker-456", # Different user!
    aud = "abc",
    exp = as.numeric(Sys.time()) + 3600,
    iat = as.numeric(Sys.time())
  )
  new_id_token <- paste(
    shinyOAuth:::base64url_encode(charToRaw('{"alg":"none"}')),
    shinyOAuth:::base64url_encode(charToRaw(jsonlite::toJSON(
      new_payload,
      auto_unbox = TRUE
    ))),
    "",
    sep = "."
  )

  # Mock refresh response returning the mismatched ID token
  testthat::local_mocked_bindings(
    req_with_retry = function(req) {
      body <- sprintf(
        '{"access_token":"new_at","token_type":"Bearer","expires_in":3600,"id_token":"%s"}',
        new_id_token
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

  # Skip signature validation for this test (we're testing claim logic)
  withr::local_options(shinyOAuth.skip_id_sig = TRUE)

  t <- OAuthToken(
    access_token = "old_at",
    refresh_token = "rt",
    expires_at = as.numeric(Sys.time()) + 10,
    id_token = original_id_token
  )

  # Should fail: new ID token has different sub than original
  testthat::expect_error(
    refresh_token(cli, t, async = FALSE, introspect = FALSE),
    class = "shinyOAuth_id_token_error"
  )
})

testthat::test_that("refresh_token accepts new id_token with matching sub (OIDC 12.2)", {
  # Happy path: new ID token has same sub as original - should succeed
  original_sub <- "user-123"

  # Skip signature validation for this test (we're testing claim logic)
  withr::local_options(shinyOAuth.skip_id_sig = TRUE)

  prov <- oauth_provider(
    name = "oidc-example",
    auth_url = "https://issuer.example.com/auth",
    token_url = "https://issuer.example.com/token",
    issuer = "https://issuer.example.com",
    id_token_validation = TRUE,
    id_token_required = FALSE,
    use_nonce = FALSE,
    use_pkce = TRUE,
    token_auth_style = "body"
  )
  cli <- oauth_client(
    provider = prov,
    client_id = "abc",
    client_secret = "",
    redirect_uri = "http://localhost:8100",
    state_store = cachem::cache_mem(max_age = 600),
    state_key = paste0(
      "0123456789abcdefghijklmnopqrstuvwxyz",
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    )
  )

  # Original ID token
  original_payload <- list(
    iss = "https://issuer.example.com",
    sub = original_sub,
    aud = "abc",
    exp = as.numeric(Sys.time()) + 3600,
    iat = as.numeric(Sys.time()) - 100
  )
  original_id_token <- paste(
    shinyOAuth:::base64url_encode(charToRaw('{"alg":"none"}')),
    shinyOAuth:::base64url_encode(charToRaw(jsonlite::toJSON(
      original_payload,
      auto_unbox = TRUE
    ))),
    "",
    sep = "."
  )

  # New ID token with SAME sub (different iat to simulate re-issuance)
  new_payload <- list(
    iss = "https://issuer.example.com",
    sub = original_sub, # Same user
    aud = "abc",
    exp = as.numeric(Sys.time()) + 3600,
    iat = as.numeric(Sys.time())
  )
  new_id_token <- paste(
    shinyOAuth:::base64url_encode(charToRaw('{"alg":"none"}')),
    shinyOAuth:::base64url_encode(charToRaw(jsonlite::toJSON(
      new_payload,
      auto_unbox = TRUE
    ))),
    "",
    sep = "."
  )

  testthat::local_mocked_bindings(
    req_with_retry = function(req) {
      body <- sprintf(
        '{"access_token":"new_at","token_type":"Bearer","expires_in":3600,"id_token":"%s"}',
        new_id_token
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
    id_token = original_id_token
  )

  # Should succeed: sub matches
  t2 <- refresh_token(cli, t, async = FALSE, introspect = FALSE)
  testthat::expect_true(S7::S7_inherits(t2, OAuthToken))
  testthat::expect_identical(t2@access_token, "new_at")
  # New ID token should be stored
  testthat::expect_identical(t2@id_token, new_id_token)
})

testthat::test_that("refresh_token rejects new id_token when original id_token is missing", {
  # Strict policy: if refresh returns an ID token, we require an original
  # ID token from login to enforce OIDC Core §12.2 sub continuity.

  withr::local_options(shinyOAuth.skip_id_sig = TRUE)

  prov <- oauth_provider(
    name = "oidc-example",
    auth_url = "https://issuer.example.com/auth",
    token_url = "https://issuer.example.com/token",
    issuer = "https://issuer.example.com",
    id_token_validation = TRUE,
    id_token_required = FALSE,
    use_nonce = FALSE,
    use_pkce = TRUE,
    token_auth_style = "body"
  )
  cli <- oauth_client(
    provider = prov,
    client_id = "abc",
    client_secret = "",
    redirect_uri = "http://localhost:8100",
    state_store = cachem::cache_mem(max_age = 600),
    state_key = paste0(
      "0123456789abcdefghijklmnopqrstuvwxyz",
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    )
  )

  # Refresh returns an ID token, but the session has no original ID token.
  new_payload <- list(
    iss = "https://issuer.example.com",
    sub = "user-123",
    aud = "abc",
    exp = as.numeric(Sys.time()) + 3600,
    iat = as.numeric(Sys.time()) - 10
  )
  new_id_token <- paste(
    shinyOAuth:::base64url_encode(charToRaw('{"alg":"none"}')),
    shinyOAuth:::base64url_encode(charToRaw(jsonlite::toJSON(
      new_payload,
      auto_unbox = TRUE
    ))),
    "",
    sep = "."
  )

  testthat::local_mocked_bindings(
    req_with_retry = function(req) {
      body <- sprintf(
        '{"access_token":"new_at","token_type":"Bearer","expires_in":3600,"id_token":"%s"}',
        new_id_token
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
    id_token = NA_character_
  )

  testthat::expect_error(
    refresh_token(cli, t, async = FALSE, introspect = FALSE),
    class = "shinyOAuth_id_token_error"
  )
})

testthat::test_that("refresh_token rejects new id_token when original id_token is missing even if id_token_validation=FALSE", {
  # Even if callers skip signature/claim validation, we still cannot accept a
  # refresh-returned ID token without an original to bind identity.

  prov <- oauth_provider(
    name = "oidc-example",
    auth_url = "https://issuer.example.com/auth",
    token_url = "https://issuer.example.com/token",
    issuer = "https://issuer.example.com",
    id_token_validation = FALSE,
    id_token_required = FALSE,
    use_nonce = FALSE,
    use_pkce = TRUE,
    token_auth_style = "body"
  )
  cli <- oauth_client(
    provider = prov,
    client_id = "abc",
    client_secret = "",
    redirect_uri = "http://localhost:8100",
    state_store = cachem::cache_mem(max_age = 600),
    state_key = paste0(
      "0123456789abcdefghijklmnopqrstuvwxyz",
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    )
  )

  new_payload <- list(
    iss = "https://issuer.example.com",
    sub = "user-123",
    aud = "abc",
    exp = as.numeric(Sys.time()) + 3600,
    iat = as.numeric(Sys.time()) - 10
  )
  new_id_token <- paste(
    shinyOAuth:::base64url_encode(charToRaw('{"alg":"none"}')),
    shinyOAuth:::base64url_encode(charToRaw(jsonlite::toJSON(
      new_payload,
      auto_unbox = TRUE
    ))),
    "",
    sep = "."
  )

  testthat::local_mocked_bindings(
    req_with_retry = function(req) {
      body <- sprintf(
        '{"access_token":"new_at","token_type":"Bearer","expires_in":3600,"id_token":"%s"}',
        new_id_token
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
    id_token = NA_character_
  )

  testthat::expect_error(
    refresh_token(cli, t, async = FALSE, introspect = FALSE),
    class = "shinyOAuth_id_token_error"
  )
})

testthat::test_that("refresh_token preserves original id_token when refresh omits it", {
  # When refresh response omits id_token, the original should be preserved
  original_sub <- "user-123"

  prov <- oauth_provider(
    name = "oidc-example",
    auth_url = "https://issuer.example.com/auth",
    token_url = "https://issuer.example.com/token",
    issuer = "https://issuer.example.com",
    id_token_validation = TRUE,
    id_token_required = FALSE,
    use_nonce = FALSE,
    use_pkce = TRUE,
    token_auth_style = "body"
  )
  cli <- oauth_client(
    provider = prov,
    client_id = "abc",
    client_secret = "",
    redirect_uri = "http://localhost:8100",
    state_store = cachem::cache_mem(max_age = 600),
    state_key = paste0(
      "0123456789abcdefghijklmnopqrstuvwxyz",
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    )
  )

  original_payload <- list(
    iss = "https://issuer.example.com",
    sub = original_sub,
    aud = "abc",
    exp = as.numeric(Sys.time()) + 3600,
    iat = as.numeric(Sys.time())
  )
  original_id_token <- paste(
    shinyOAuth:::base64url_encode(charToRaw('{"alg":"none"}')),
    shinyOAuth:::base64url_encode(charToRaw(jsonlite::toJSON(
      original_payload,
      auto_unbox = TRUE
    ))),
    "",
    sep = "."
  )

  # Refresh response WITHOUT id_token
  testthat::local_mocked_bindings(
    req_with_retry = function(req) {
      httr2::response(
        url = as.character(req$url),
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw(
          '{"access_token":"new_at","token_type":"Bearer","expires_in":3600}'
        )
      )
    },
    .package = "shinyOAuth"
  )

  t <- OAuthToken(
    access_token = "old_at",
    refresh_token = "rt",
    expires_at = as.numeric(Sys.time()) + 10,
    id_token = original_id_token
  )

  t2 <- refresh_token(cli, t, async = FALSE, introspect = FALSE)
  testthat::expect_true(S7::S7_inherits(t2, OAuthToken))
  testthat::expect_identical(t2@access_token, "new_at")
  # Original ID token should be preserved

  testthat::expect_identical(t2@id_token, original_id_token)
})

testthat::test_that("refresh_token fails when original id_token is unparseable but new id_token present", {
  # If we have an original id_token that we can't parse to extract sub,
  # but the refresh returns a new id_token, we should fail (can't verify sub)

  prov <- oauth_provider(
    name = "oidc-example",
    auth_url = "https://issuer.example.com/auth",
    token_url = "https://issuer.example.com/token",
    issuer = "https://issuer.example.com",
    id_token_validation = TRUE,
    id_token_required = FALSE,
    use_nonce = FALSE,
    use_pkce = TRUE,
    token_auth_style = "body"
  )
  cli <- oauth_client(
    provider = prov,
    client_id = "abc",
    client_secret = "",
    redirect_uri = "http://localhost:8100",
    state_store = cachem::cache_mem(max_age = 600),
    state_key = paste0(
      "0123456789abcdefghijklmnopqrstuvwxyz",
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    )
  )

  # Corrupt/unparseable original ID token
  corrupt_id_token <- "not.a.valid.jwt"

  # Valid new ID token in refresh response
  new_payload <- list(
    iss = "https://issuer.example.com",
    sub = "user-123",
    aud = "abc",
    exp = as.numeric(Sys.time()) + 3600,
    iat = as.numeric(Sys.time())
  )
  new_id_token <- paste(
    shinyOAuth:::base64url_encode(charToRaw('{"alg":"none"}')),
    shinyOAuth:::base64url_encode(charToRaw(jsonlite::toJSON(
      new_payload,
      auto_unbox = TRUE
    ))),
    "",
    sep = "."
  )

  testthat::local_mocked_bindings(
    req_with_retry = function(req) {
      body <- sprintf(
        '{"access_token":"new_at","token_type":"Bearer","expires_in":3600,"id_token":"%s"}',
        new_id_token
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

  withr::local_options(shinyOAuth.skip_id_sig = TRUE)

  t <- OAuthToken(
    access_token = "old_at",
    refresh_token = "rt",
    expires_at = as.numeric(Sys.time()) + 10,
    id_token = corrupt_id_token
  )

  # Should fail: can't verify sub because original is unparseable
  testthat::expect_error(
    refresh_token(cli, t, async = FALSE, introspect = FALSE),
    class = "shinyOAuth_id_token_error"
  )
})

testthat::test_that("refresh with id_token_required=TRUE succeeds when response omits id_token", {
  # id_token_required only applies to initial login, not refresh
  # This ensures we don't regress by requiring id_token during refresh

  prov <- oauth_provider(
    name = "oidc-example",
    auth_url = "https://issuer.example.com/auth",
    token_url = "https://issuer.example.com/token",
    issuer = "https://issuer.example.com",
    id_token_validation = TRUE,
    id_token_required = TRUE, # Would fail on login without id_token
    use_nonce = FALSE,
    use_pkce = TRUE,
    token_auth_style = "body"
  )
  cli <- oauth_client(
    provider = prov,
    client_id = "abc",
    client_secret = "",
    redirect_uri = "http://localhost:8100",
    state_store = cachem::cache_mem(max_age = 600),
    state_key = paste0(
      "0123456789abcdefghijklmnopqrstuvwxyz",
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    )
  )

  # Response without id_token
  testthat::local_mocked_bindings(
    req_with_retry = function(req) {
      httr2::response(
        url = as.character(req$url),
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw(
          '{"access_token":"new_at","token_type":"Bearer","expires_in":3600}'
        )
      )
    },
    .package = "shinyOAuth"
  )

  t <- OAuthToken(
    access_token = "old_at",
    refresh_token = "rt",
    expires_at = as.numeric(Sys.time()) + 10,
    id_token = NA_character_
  )

  # Should succeed: id_token_required doesn't apply during refresh
  t2 <- refresh_token(cli, t, async = FALSE, introspect = FALSE)
  testthat::expect_true(S7::S7_inherits(t2, OAuthToken))
  testthat::expect_identical(t2@access_token, "new_at")
})

testthat::test_that("refresh_token validates new id_token claims (issuer, aud, exp)", {
  # When refresh returns a new ID token, it gets full claim validation
  # (issuer, audience, exp, etc.) just like during initial login

  withr::local_options(shinyOAuth.skip_id_sig = TRUE)

  prov <- oauth_provider(
    name = "oidc-example",
    auth_url = "https://issuer.example.com/auth",
    token_url = "https://issuer.example.com/token",
    issuer = "https://issuer.example.com",
    id_token_validation = TRUE,
    id_token_required = FALSE,
    use_nonce = FALSE,
    use_pkce = TRUE,
    token_auth_style = "body"
  )
  cli <- oauth_client(
    provider = prov,
    client_id = "abc",
    client_secret = "",
    redirect_uri = "http://localhost:8100",
    state_store = cachem::cache_mem(max_age = 600),
    state_key = paste0(
      "0123456789abcdefghijklmnopqrstuvwxyz",
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    )
  )

  original_payload <- list(
    iss = "https://issuer.example.com",
    sub = "user-123",
    aud = "abc",
    exp = as.numeric(Sys.time()) + 3600,
    iat = as.numeric(Sys.time())
  )
  original_id_token <- paste(
    shinyOAuth:::base64url_encode(charToRaw('{"alg":"none"}')),
    shinyOAuth:::base64url_encode(charToRaw(jsonlite::toJSON(
      original_payload,
      auto_unbox = TRUE
    ))),
    "",
    sep = "."
  )

  t <- OAuthToken(
    access_token = "old_at",
    refresh_token = "rt",
    expires_at = as.numeric(Sys.time()) + 10,
    id_token = original_id_token
  )

  # Test 1: Wrong issuer in new ID token should fail
  bad_issuer_payload <- list(
    iss = "https://attacker.example.com", # Wrong!
    sub = "user-123",
    aud = "abc",
    exp = as.numeric(Sys.time()) + 3600,
    iat = as.numeric(Sys.time())
  )
  bad_issuer_token <- paste(
    shinyOAuth:::base64url_encode(charToRaw('{"alg":"none"}')),
    shinyOAuth:::base64url_encode(charToRaw(jsonlite::toJSON(
      bad_issuer_payload,
      auto_unbox = TRUE
    ))),
    "",
    sep = "."
  )

  testthat::local_mocked_bindings(
    req_with_retry = function(req) {
      body <- sprintf(
        '{"access_token":"new_at","token_type":"Bearer","expires_in":3600,"id_token":"%s"}',
        bad_issuer_token
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

  testthat::expect_error(
    refresh_token(cli, t, async = FALSE, introspect = FALSE),
    class = "shinyOAuth_id_token_error"
  )
})

testthat::test_that("refresh_token validates new id_token audience", {
  # Audience mismatch should fail validation

  withr::local_options(shinyOAuth.skip_id_sig = TRUE)

  prov <- oauth_provider(
    name = "oidc-example",
    auth_url = "https://issuer.example.com/auth",
    token_url = "https://issuer.example.com/token",
    issuer = "https://issuer.example.com",
    id_token_validation = TRUE,
    id_token_required = FALSE,
    use_nonce = FALSE,
    use_pkce = TRUE,
    token_auth_style = "body"
  )
  cli <- oauth_client(
    provider = prov,
    client_id = "abc",
    client_secret = "",
    redirect_uri = "http://localhost:8100",
    state_store = cachem::cache_mem(max_age = 600),
    state_key = paste0(
      "0123456789abcdefghijklmnopqrstuvwxyz",
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    )
  )

  original_payload <- list(
    iss = "https://issuer.example.com",
    sub = "user-123",
    aud = "abc",
    exp = as.numeric(Sys.time()) + 3600,
    iat = as.numeric(Sys.time())
  )
  original_id_token <- paste(
    shinyOAuth:::base64url_encode(charToRaw('{"alg":"none"}')),
    shinyOAuth:::base64url_encode(charToRaw(jsonlite::toJSON(
      original_payload,
      auto_unbox = TRUE
    ))),
    "",
    sep = "."
  )

  t <- OAuthToken(
    access_token = "old_at",
    refresh_token = "rt",
    expires_at = as.numeric(Sys.time()) + 10,
    id_token = original_id_token
  )

  # Wrong audience in new ID token
  bad_aud_payload <- list(
    iss = "https://issuer.example.com",
    sub = "user-123",
    aud = "wrong-client-id", # Wrong!
    exp = as.numeric(Sys.time()) + 3600,
    iat = as.numeric(Sys.time())
  )
  bad_aud_token <- paste(
    shinyOAuth:::base64url_encode(charToRaw('{"alg":"none"}')),
    shinyOAuth:::base64url_encode(charToRaw(jsonlite::toJSON(
      bad_aud_payload,
      auto_unbox = TRUE
    ))),
    "",
    sep = "."
  )

  testthat::local_mocked_bindings(
    req_with_retry = function(req) {
      body <- sprintf(
        '{"access_token":"new_at","token_type":"Bearer","expires_in":3600,"id_token":"%s"}',
        bad_aud_token
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

  testthat::expect_error(
    refresh_token(cli, t, async = FALSE, introspect = FALSE),
    class = "shinyOAuth_id_token_error"
  )
})

testthat::test_that("refresh_token rejects expired new id_token", {
  # Expired ID token should fail validation

  withr::local_options(shinyOAuth.skip_id_sig = TRUE)

  prov <- oauth_provider(
    name = "oidc-example",
    auth_url = "https://issuer.example.com/auth",
    token_url = "https://issuer.example.com/token",
    issuer = "https://issuer.example.com",
    id_token_validation = TRUE,
    id_token_required = FALSE,
    use_nonce = FALSE,
    use_pkce = TRUE,
    token_auth_style = "body"
  )
  cli <- oauth_client(
    provider = prov,
    client_id = "abc",
    client_secret = "",
    redirect_uri = "http://localhost:8100",
    state_store = cachem::cache_mem(max_age = 600),
    state_key = paste0(
      "0123456789abcdefghijklmnopqrstuvwxyz",
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    )
  )

  original_payload <- list(
    iss = "https://issuer.example.com",
    sub = "user-123",
    aud = "abc",
    exp = as.numeric(Sys.time()) + 3600,
    iat = as.numeric(Sys.time())
  )
  original_id_token <- paste(
    shinyOAuth:::base64url_encode(charToRaw('{"alg":"none"}')),
    shinyOAuth:::base64url_encode(charToRaw(jsonlite::toJSON(
      original_payload,
      auto_unbox = TRUE
    ))),
    "",
    sep = "."
  )

  t <- OAuthToken(
    access_token = "old_at",
    refresh_token = "rt",
    expires_at = as.numeric(Sys.time()) + 10,
    id_token = original_id_token
  )

  # Expired ID token
  expired_payload <- list(
    iss = "https://issuer.example.com",
    sub = "user-123",
    aud = "abc",
    exp = as.numeric(Sys.time()) - 3600, # Already expired!
    iat = as.numeric(Sys.time()) - 7200
  )
  expired_token <- paste(
    shinyOAuth:::base64url_encode(charToRaw('{"alg":"none"}')),
    shinyOAuth:::base64url_encode(charToRaw(jsonlite::toJSON(
      expired_payload,
      auto_unbox = TRUE
    ))),
    "",
    sep = "."
  )

  testthat::local_mocked_bindings(
    req_with_retry = function(req) {
      body <- sprintf(
        '{"access_token":"new_at","token_type":"Bearer","expires_in":3600,"id_token":"%s"}',
        expired_token
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

  testthat::expect_error(
    refresh_token(cli, t, async = FALSE, introspect = FALSE),
    class = "shinyOAuth_id_token_error"
  )
})

testthat::test_that("refresh_token validates userinfo_id_token_match when both present", {
  # When userinfo_required + userinfo_id_token_match are enabled and refresh
  # returns a new ID token, the subjects must still match

  withr::local_options(shinyOAuth.skip_id_sig = TRUE)

  prov <- oauth_provider(
    name = "oidc-example",
    auth_url = "https://issuer.example.com/auth",
    token_url = "https://issuer.example.com/token",
    userinfo_url = "https://issuer.example.com/userinfo",
    issuer = "https://issuer.example.com",
    id_token_validation = TRUE,
    id_token_required = FALSE,
    userinfo_required = TRUE,
    userinfo_id_token_match = TRUE,
    userinfo_id_selector = function(ui) ui$sub,
    use_nonce = FALSE,
    use_pkce = TRUE,
    token_auth_style = "body"
  )
  cli <- oauth_client(
    provider = prov,
    client_id = "abc",
    client_secret = "",
    redirect_uri = "http://localhost:8100",
    state_store = cachem::cache_mem(max_age = 600),
    state_key = paste0(
      "0123456789abcdefghijklmnopqrstuvwxyz",
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    )
  )

  original_payload <- list(
    iss = "https://issuer.example.com",
    sub = "user-123",
    aud = "abc",
    exp = as.numeric(Sys.time()) + 3600,
    iat = as.numeric(Sys.time())
  )
  original_id_token <- paste(
    shinyOAuth:::base64url_encode(charToRaw('{"alg":"none"}')),
    shinyOAuth:::base64url_encode(charToRaw(jsonlite::toJSON(
      original_payload,
      auto_unbox = TRUE
    ))),
    "",
    sep = "."
  )

  t <- OAuthToken(
    access_token = "old_at",
    refresh_token = "rt",
    expires_at = as.numeric(Sys.time()) + 10,
    id_token = original_id_token
  )

  # New ID token with correct sub
  new_payload <- list(
    iss = "https://issuer.example.com",
    sub = "user-123",
    aud = "abc",
    exp = as.numeric(Sys.time()) + 3600,
    iat = as.numeric(Sys.time())
  )
  new_id_token <- paste(
    shinyOAuth:::base64url_encode(charToRaw('{"alg":"none"}')),
    shinyOAuth:::base64url_encode(charToRaw(jsonlite::toJSON(
      new_payload,
      auto_unbox = TRUE
    ))),
    "",
    sep = "."
  )

  # Mock userinfo to return DIFFERENT subject - should fail validation
  testthat::local_mocked_bindings(
    req_with_retry = function(req) {
      url <- as.character(req$url)
      if (grepl("userinfo", url)) {
        # Userinfo returns different sub
        httr2::response(
          url = url,
          status = 200,
          headers = list("content-type" = "application/json"),
          body = charToRaw('{"sub":"different-user-456"}')
        )
      } else {
        # Token endpoint
        body <- sprintf(
          '{"access_token":"new_at","token_type":"Bearer","expires_in":3600,"id_token":"%s"}',
          new_id_token
        )
        httr2::response(
          url = url,
          status = 200,
          headers = list("content-type" = "application/json"),
          body = charToRaw(body)
        )
      }
    },
    .package = "shinyOAuth"
  )

  testthat::expect_error(
    refresh_token(cli, t, async = FALSE, introspect = FALSE),
    class = "shinyOAuth_userinfo_mismatch"
  )
})

testthat::test_that("refresh_token skips userinfo_id_token_match when id_token missing", {
  # When refresh omits id_token but userinfo is fetched, skip the match check

  prov <- oauth_provider(
    name = "oidc-example",
    auth_url = "https://issuer.example.com/auth",
    token_url = "https://issuer.example.com/token",
    userinfo_url = "https://issuer.example.com/userinfo",
    issuer = "https://issuer.example.com",
    id_token_validation = TRUE,
    id_token_required = FALSE,
    userinfo_required = TRUE,
    userinfo_id_token_match = TRUE,
    userinfo_id_selector = function(ui) ui$sub,
    use_nonce = FALSE,
    use_pkce = TRUE,
    token_auth_style = "body"
  )
  cli <- oauth_client(
    provider = prov,
    client_id = "abc",
    client_secret = "",
    redirect_uri = "http://localhost:8100",
    state_store = cachem::cache_mem(max_age = 600),
    state_key = paste0(
      "0123456789abcdefghijklmnopqrstuvwxyz",
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    )
  )

  t <- OAuthToken(
    access_token = "old_at",
    refresh_token = "rt",
    expires_at = as.numeric(Sys.time()) + 10,
    id_token = NA_character_
  )

  testthat::local_mocked_bindings(
    req_with_retry = function(req) {
      url <- as.character(req$url)
      if (grepl("userinfo", url)) {
        httr2::response(
          url = url,
          status = 200,
          headers = list("content-type" = "application/json"),
          body = charToRaw('{"sub":"user-123"}')
        )
      } else {
        # Token endpoint - no id_token
        httr2::response(
          url = url,
          status = 200,
          headers = list("content-type" = "application/json"),
          body = charToRaw(
            '{"access_token":"new_at","token_type":"Bearer","expires_in":3600}'
          )
        )
      }
    },
    .package = "shinyOAuth"
  )

  # Should succeed - no id_token to match against
  t2 <- refresh_token(cli, t, async = FALSE, introspect = FALSE)
  testthat::expect_true(S7::S7_inherits(t2, OAuthToken))
  testthat::expect_identical(t2@access_token, "new_at")
})

testthat::test_that("refresh_token succeeds when userinfo and id_token subjects match", {
  # Happy path: userinfo_id_token_match validation passes when subjects match

  withr::local_options(shinyOAuth.skip_id_sig = TRUE)

  prov <- oauth_provider(
    name = "oidc-example",
    auth_url = "https://issuer.example.com/auth",
    token_url = "https://issuer.example.com/token",
    userinfo_url = "https://issuer.example.com/userinfo",
    issuer = "https://issuer.example.com",
    id_token_validation = TRUE,
    id_token_required = FALSE,
    userinfo_required = TRUE,
    userinfo_id_token_match = TRUE,
    userinfo_id_selector = function(ui) ui$sub,
    use_nonce = FALSE,
    use_pkce = TRUE,
    token_auth_style = "body"
  )
  cli <- oauth_client(
    provider = prov,
    client_id = "abc",
    client_secret = "",
    redirect_uri = "http://localhost:8100",
    state_store = cachem::cache_mem(max_age = 600),
    state_key = paste0(
      "0123456789abcdefghijklmnopqrstuvwxyz",
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    )
  )

  original_payload <- list(
    iss = "https://issuer.example.com",
    sub = "user-123",
    aud = "abc",
    exp = as.numeric(Sys.time()) + 3600,
    iat = as.numeric(Sys.time())
  )
  original_id_token <- paste(
    shinyOAuth:::base64url_encode(charToRaw('{"alg":"none"}')),
    shinyOAuth:::base64url_encode(charToRaw(jsonlite::toJSON(
      original_payload,
      auto_unbox = TRUE
    ))),
    "",
    sep = "."
  )

  t <- OAuthToken(
    access_token = "old_at",
    refresh_token = "rt",
    expires_at = as.numeric(Sys.time()) + 10,
    id_token = original_id_token,
    userinfo = list(sub = "user-123", name = "Old Name")
  )

  # New ID token with same sub
  new_payload <- list(
    iss = "https://issuer.example.com",
    sub = "user-123",
    aud = "abc",
    exp = as.numeric(Sys.time()) + 3600,
    iat = as.numeric(Sys.time())
  )
  new_id_token <- paste(
    shinyOAuth:::base64url_encode(charToRaw('{"alg":"none"}')),
    shinyOAuth:::base64url_encode(charToRaw(jsonlite::toJSON(
      new_payload,
      auto_unbox = TRUE
    ))),
    "",
    sep = "."
  )

  # Mock userinfo to return MATCHING subject with updated info
  testthat::local_mocked_bindings(
    req_with_retry = function(req) {
      url <- as.character(req$url)
      if (grepl("userinfo", url)) {
        httr2::response(
          url = url,
          status = 200,
          headers = list("content-type" = "application/json"),
          body = charToRaw(
            '{"sub":"user-123","name":"Updated Name","email":"user@example.com"}'
          )
        )
      } else {
        # Token endpoint
        body <- sprintf(
          '{"access_token":"new_at","token_type":"Bearer","expires_in":3600,"id_token":"%s"}',
          new_id_token
        )
        httr2::response(
          url = url,
          status = 200,
          headers = list("content-type" = "application/json"),
          body = charToRaw(body)
        )
      }
    },
    .package = "shinyOAuth"
  )

  # Should succeed - subjects match
  t2 <- refresh_token(cli, t, async = FALSE, introspect = FALSE)
  testthat::expect_true(S7::S7_inherits(t2, OAuthToken))
  testthat::expect_identical(t2@access_token, "new_at")
  # Userinfo should be updated
  testthat::expect_identical(t2@userinfo$name, "Updated Name")
  testthat::expect_identical(t2@userinfo$email, "user@example.com")
  # ID token should be updated
  testthat::expect_identical(t2@id_token, new_id_token)
})

testthat::test_that("refresh_token updates userinfo even when id_token omitted", {
  # When refresh omits id_token but userinfo_required is TRUE,

  # userinfo should still be fetched and updated

  prov <- oauth_provider(
    name = "oidc-example",
    auth_url = "https://issuer.example.com/auth",
    token_url = "https://issuer.example.com/token",
    userinfo_url = "https://issuer.example.com/userinfo",
    issuer = "https://issuer.example.com",
    id_token_validation = TRUE,
    id_token_required = FALSE,
    userinfo_required = TRUE,
    userinfo_id_token_match = TRUE,
    userinfo_id_selector = function(ui) ui$sub,
    use_nonce = FALSE,
    use_pkce = TRUE,
    token_auth_style = "body"
  )
  cli <- oauth_client(
    provider = prov,
    client_id = "abc",
    client_secret = "",
    redirect_uri = "http://localhost:8100",
    state_store = cachem::cache_mem(max_age = 600),
    state_key = paste0(
      "0123456789abcdefghijklmnopqrstuvwxyz",
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    )
  )

  original_payload <- list(
    iss = "https://issuer.example.com",
    sub = "user-123",
    aud = "abc",
    exp = as.numeric(Sys.time()) + 3600,
    iat = as.numeric(Sys.time())
  )
  original_id_token <- paste(
    shinyOAuth:::base64url_encode(charToRaw('{"alg":"none"}')),
    shinyOAuth:::base64url_encode(charToRaw(jsonlite::toJSON(
      original_payload,
      auto_unbox = TRUE
    ))),
    "",
    sep = "."
  )

  t <- OAuthToken(
    access_token = "old_at",
    refresh_token = "rt",
    expires_at = as.numeric(Sys.time()) + 10,
    id_token = original_id_token,
    userinfo = list(sub = "user-123", name = "Old Name")
  )

  testthat::local_mocked_bindings(
    req_with_retry = function(req) {
      url <- as.character(req$url)
      if (grepl("userinfo", url)) {
        httr2::response(
          url = url,
          status = 200,
          headers = list("content-type" = "application/json"),
          body = charToRaw('{"sub":"user-123","name":"Fresh Name"}')
        )
      } else {
        # Token endpoint - no id_token returned
        httr2::response(
          url = url,
          status = 200,
          headers = list("content-type" = "application/json"),
          body = charToRaw(
            '{"access_token":"new_at","token_type":"Bearer","expires_in":3600}'
          )
        )
      }
    },
    .package = "shinyOAuth"
  )

  t2 <- refresh_token(cli, t, async = FALSE, introspect = FALSE)
  testthat::expect_true(S7::S7_inherits(t2, OAuthToken))
  testthat::expect_identical(t2@access_token, "new_at")
  # Userinfo should be updated with fresh data
  testthat::expect_identical(t2@userinfo$name, "Fresh Name")
  # Original id_token should be preserved (refresh didn't return a new one)
  testthat::expect_identical(t2@id_token, original_id_token)
})
