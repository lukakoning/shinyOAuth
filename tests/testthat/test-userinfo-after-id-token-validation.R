# Regression test: userinfo must be fetched AFTER ID token validation
# This ensures cryptographic validation occurs before making external calls
# or exposing PII via the userinfo endpoint.

test_that("login flow: get_userinfo is called after validate_id_token", {
  # Create a provider with OIDC features that require ID token validation
  # and userinfo fetch

  prov <- oauth_provider(
    name = "test",
    auth_url = "https://test.example.com/auth",
    token_url = "https://test.example.com/token",
    userinfo_url = "https://test.example.com/userinfo",
    issuer = "https://test.example.com",
    use_nonce = TRUE,
    use_pkce = TRUE,
    pkce_method = "S256",
    userinfo_required = TRUE,
    id_token_required = TRUE,
    id_token_validation = TRUE,
    userinfo_id_token_match = FALSE,
    token_auth_style = "body",
    jwks_cache = cachem::cache_mem(max_age = 60),
    allowed_algs = c("RS256"),
    allowed_token_types = c("Bearer")
  )

  cli <- oauth_client(
    provider = prov,
    client_id = "test-client",
    client_secret = "",
    redirect_uri = "http://localhost:8100",
    scopes = c("openid", "profile"),
    state_store = cachem::cache_mem(max_age = 600),
    state_key = paste0(
      "0123456789abcdefghijklmnopqrstuvwxyz",
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    )
  )

  tok <- valid_browser_token()
  url <- shinyOAuth:::prepare_call(cli, browser_token = tok)
  enc <- parse_query_param(url, "state")

  # Track call order
  call_order <- character()

  result <- testthat::with_mocked_bindings(
    swap_code_for_token_set = function(client, code, code_verifier) {
      list(
        access_token = "test-access-token",
        token_type = "Bearer",
        expires_in = 3600,
        id_token = "header.payload.signature",
        scope = "openid profile"
      )
    },
    validate_id_token = function(
      client,
      id_token,
      expected_nonce = NULL,
      expected_sub = NULL
    ) {
      call_order <<- c(call_order, "validate_id_token")
      invisible(list(sub = "user123", iss = "https://test.example.com"))
    },
    get_userinfo = function(oauth_client, token) {
      call_order <<- c(call_order, "get_userinfo")
      list(sub = "user123", name = "Test User")
    },
    .package = "shinyOAuth",
    {
      shinyOAuth:::handle_callback(
        cli,
        code = "auth-code",
        payload = enc,
        browser_token = tok
      )
    }
  )

  # Verify both functions were called

  expect_true("validate_id_token" %in% call_order)
  expect_true("get_userinfo" %in% call_order)

  # Verify ordering: validate_id_token MUST be called before get_userinfo
  validate_pos <- which(call_order == "validate_id_token")[1]
  userinfo_pos <- which(call_order == "get_userinfo")[1]
  expect_lt(
    validate_pos,
    userinfo_pos,
    label = "validate_id_token must be called before get_userinfo"
  )
})

test_that("login flow: get_userinfo not called when ID token validation fails", {
  # Ensure that if ID token validation fails, we never reach the userinfo call
  prov <- oauth_provider(
    name = "test",
    auth_url = "https://test.example.com/auth",
    token_url = "https://test.example.com/token",
    userinfo_url = "https://test.example.com/userinfo",
    issuer = "https://test.example.com",
    use_nonce = TRUE,
    use_pkce = TRUE,
    pkce_method = "S256",
    userinfo_required = TRUE,
    id_token_required = TRUE,
    id_token_validation = TRUE,
    userinfo_id_token_match = FALSE,
    token_auth_style = "body",
    jwks_cache = cachem::cache_mem(max_age = 60),
    allowed_algs = c("RS256"),
    allowed_token_types = c("Bearer")
  )

  cli <- oauth_client(
    provider = prov,
    client_id = "test-client",
    client_secret = "",
    redirect_uri = "http://localhost:8100",
    scopes = c("openid", "profile"),
    state_store = cachem::cache_mem(max_age = 600),
    state_key = paste0(
      "0123456789abcdefghijklmnopqrstuvwxyz",
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    )
  )

  tok <- valid_browser_token()
  url <- shinyOAuth:::prepare_call(cli, browser_token = tok)
  enc <- parse_query_param(url, "state")

  userinfo_called <- FALSE

  expect_error(
    testthat::with_mocked_bindings(
      swap_code_for_token_set = function(client, code, code_verifier) {
        list(
          access_token = "test-access-token",
          token_type = "Bearer",
          expires_in = 3600,
          id_token = "header.payload.signature",
          scope = "openid profile"
        )
      },
      validate_id_token = function(
        client,
        id_token,
        expected_nonce = NULL,
        expected_sub = NULL
      ) {
        shinyOAuth:::err_id_token("Simulated ID token validation failure")
      },
      get_userinfo = function(oauth_client, token) {
        userinfo_called <<- TRUE
        list(sub = "user123")
      },
      .package = "shinyOAuth",
      {
        shinyOAuth:::handle_callback(
          cli,
          code = "auth-code",
          payload = enc,
          browser_token = tok
        )
      }
    ),
    class = "shinyOAuth_id_token_error"
  )

  # userinfo should NOT have been called because ID token validation failed first

  expect_false(
    userinfo_called,
    label = "get_userinfo must not be called when ID token validation fails"
  )
})

# Tests for verify_token_set behavior with userinfo/id_token subject match -----
# These lock in the behavior that verify_token_set:
# - Does NOT perform userinfo/id_token match during initial login (is_refresh = FALSE)
#   because handle_callback now does it explicitly after fetching userinfo
# - Only performs the match during refresh when BOTH userinfo and id_token are present

test_that("verify_token_set: initial login does not call userinfo match (no userinfo yet)", {
  # During initial login, verify_token_set is called BEFORE userinfo is fetched,
  # so it should NOT attempt to validate the userinfo/id_token subject match.
  # That check is now done by handle_callback after fetching userinfo.

  # Generate an ID token for validation
  key <- openssl::rsa_keygen(2048)
  now <- as.integer(Sys.time())
  claims <- jose::jwt_claim(
    iss = "https://test.example.com",
    aud = "test-client",
    sub = "user123",
    iat = now - 10,
    exp = now + 3600
  )
  id_token <- jose::jwt_encode_sig(claims, key)

  prov <- oauth_provider(
    name = "test",
    auth_url = "https://test.example.com/auth",
    token_url = "https://test.example.com/token",
    userinfo_url = "https://test.example.com/userinfo",
    issuer = "https://test.example.com",
    use_nonce = FALSE,
    use_pkce = FALSE,
    userinfo_required = TRUE,
    id_token_required = FALSE,
    id_token_validation = TRUE, # Required when userinfo_id_token_match = TRUE
    userinfo_id_token_match = TRUE, # Enabled, but should not run in verify_token_set for initial login
    token_auth_style = "body",
    allowed_token_types = c("Bearer"),
    jwks_cache = cachem::cache_mem(max_age = 60)
  )

  cli <- oauth_client(
    provider = prov,
    client_id = "test-client",
    client_secret = "secret",
    redirect_uri = "http://localhost:8100",
    scopes = c("openid"),
    scope_validation = "none"
  )

  # Token set WITH id_token but WITHOUT userinfo (simulating state when verify_token_set is called)
  token_set <- list(
    access_token = "test-access-token",
    token_type = "Bearer",
    expires_in = 3600,
    id_token = id_token,
    userinfo = NULL, # Not yet fetched
    scope = "openid"
  )

  match_called <- FALSE

  # Mock validate_id_token to avoid JWKS fetch, and verify match is not called
  result <- testthat::with_mocked_bindings(
    validate_id_token = function(
      client,
      id_token,
      expected_nonce = NULL,
      expected_sub = NULL
    ) {
      invisible(list(sub = "user123"))
    },
    verify_userinfo_id_token_subject_match = function(
      client,
      userinfo,
      id_token
    ) {
      match_called <<- TRUE
      stop("Should not be called during initial login")
    },
    .package = "shinyOAuth",
    {
      shinyOAuth:::verify_token_set(
        cli,
        token_set = token_set,
        nonce = NULL,
        is_refresh = FALSE # Initial login
      )
    }
  )

  expect_false(
    match_called,
    label = "verify_userinfo_id_token_subject_match must not be called during initial login"
  )
  expect_type(result, "list")
})

test_that("verify_token_set: refresh with both userinfo and id_token calls match", {
  # During refresh, if BOTH userinfo and id_token are present, the match should run

  # Generate valid ID tokens for the test
  key <- openssl::rsa_keygen(2048)
  now <- as.integer(Sys.time())
  claims <- jose::jwt_claim(
    iss = "https://test.example.com",
    aud = "test-client",
    sub = "user123",
    iat = now - 10,
    exp = now + 3600
  )
  id_token <- jose::jwt_encode_sig(claims, key)
  original_id_token <- id_token # Same token for original

  prov <- oauth_provider(
    name = "test",
    auth_url = "https://test.example.com/auth",
    token_url = "https://test.example.com/token",
    userinfo_url = "https://test.example.com/userinfo",
    issuer = "https://test.example.com",
    use_nonce = FALSE,
    use_pkce = FALSE,
    userinfo_required = TRUE,
    id_token_required = FALSE,
    id_token_validation = TRUE, # Required when userinfo_id_token_match = TRUE
    userinfo_id_token_match = TRUE,
    token_auth_style = "body",
    allowed_token_types = c("Bearer"),
    jwks_cache = cachem::cache_mem(max_age = 60)
  )

  cli <- oauth_client(
    provider = prov,
    client_id = "test-client",
    client_secret = "secret",
    redirect_uri = "http://localhost:8100",
    scopes = c("openid"),
    scope_validation = "none"
  )

  # Token set WITH both userinfo and id_token
  token_set <- list(
    access_token = "test-access-token",
    token_type = "Bearer",
    expires_in = 3600,
    id_token = id_token,
    userinfo = list(sub = "user123", name = "Test User"),
    scope = "openid"
  )

  match_called <- FALSE

  result <- testthat::with_mocked_bindings(
    validate_id_token = function(
      client,
      id_token,
      expected_nonce = NULL,
      expected_sub = NULL
    ) {
      invisible(list(sub = "user123"))
    },
    verify_userinfo_id_token_subject_match = function(
      client,
      userinfo,
      id_token
    ) {
      match_called <<- TRUE
      invisible(TRUE)
    },
    .package = "shinyOAuth",
    {
      shinyOAuth:::verify_token_set(
        cli,
        token_set = token_set,
        nonce = NULL,
        is_refresh = TRUE,
        original_id_token = original_id_token # Required for OIDC 12.2 check
      )
    }
  )

  expect_true(
    match_called,
    label = "verify_userinfo_id_token_subject_match must be called during refresh when both present"
  )
})

test_that("verify_token_set: refresh without userinfo skips match", {
  # During refresh, if userinfo is missing, skip the match check

  key <- openssl::rsa_keygen(2048)
  now <- as.integer(Sys.time())
  claims <- jose::jwt_claim(
    iss = "https://test.example.com",
    aud = "test-client",
    sub = "user123",
    iat = now - 10,
    exp = now + 3600
  )
  id_token <- jose::jwt_encode_sig(claims, key)
  original_id_token <- id_token

  prov <- oauth_provider(
    name = "test",
    auth_url = "https://test.example.com/auth",
    token_url = "https://test.example.com/token",
    userinfo_url = "https://test.example.com/userinfo",
    issuer = "https://test.example.com",
    use_nonce = FALSE,
    use_pkce = FALSE,
    userinfo_required = TRUE,
    id_token_required = FALSE,
    id_token_validation = TRUE, # Required when userinfo_id_token_match = TRUE
    userinfo_id_token_match = TRUE,
    token_auth_style = "body",
    allowed_token_types = c("Bearer"),
    jwks_cache = cachem::cache_mem(max_age = 60)
  )

  cli <- oauth_client(
    provider = prov,
    client_id = "test-client",
    client_secret = "secret",
    redirect_uri = "http://localhost:8100",
    scopes = c("openid"),
    scope_validation = "none"
  )

  # Token set with id_token but NO userinfo
  token_set <- list(
    access_token = "test-access-token",
    token_type = "Bearer",
    expires_in = 3600,
    id_token = id_token,
    userinfo = NULL, # Missing
    scope = "openid"
  )

  match_called <- FALSE

  result <- testthat::with_mocked_bindings(
    validate_id_token = function(
      client,
      id_token,
      expected_nonce = NULL,
      expected_sub = NULL
    ) {
      invisible(list(sub = "user123"))
    },
    verify_userinfo_id_token_subject_match = function(
      client,
      userinfo,
      id_token
    ) {
      match_called <<- TRUE
      stop("Should not be called when userinfo is missing")
    },
    .package = "shinyOAuth",
    {
      shinyOAuth:::verify_token_set(
        cli,
        token_set = token_set,
        nonce = NULL,
        is_refresh = TRUE,
        original_id_token = original_id_token
      )
    }
  )

  expect_false(
    match_called,
    label = "verify_userinfo_id_token_subject_match must not be called when userinfo missing"
  )
})

test_that("verify_token_set: refresh without id_token skips match", {
  # During refresh, if id_token is missing, skip the match check

  prov <- oauth_provider(
    name = "test",
    auth_url = "https://test.example.com/auth",
    token_url = "https://test.example.com/token",
    userinfo_url = "https://test.example.com/userinfo",
    issuer = "https://test.example.com",
    use_nonce = FALSE,
    use_pkce = FALSE,
    userinfo_required = TRUE,
    id_token_required = FALSE,
    id_token_validation = TRUE, # Required when userinfo_id_token_match = TRUE
    userinfo_id_token_match = TRUE,
    token_auth_style = "body",
    allowed_token_types = c("Bearer"),
    jwks_cache = cachem::cache_mem(max_age = 60)
  )

  cli <- oauth_client(
    provider = prov,
    client_id = "test-client",
    client_secret = "secret",
    redirect_uri = "http://localhost:8100",
    scopes = c("openid"),
    scope_validation = "none"
  )

  # Token set with userinfo but NO id_token
  token_set <- list(
    access_token = "test-access-token",
    token_type = "Bearer",
    expires_in = 3600,
    id_token = NULL, # Missing - OIDC 12.2 allows this during refresh
    userinfo = list(sub = "user123", name = "Test User"),
    scope = "openid"
  )

  match_called <- FALSE

  result <- testthat::with_mocked_bindings(
    verify_userinfo_id_token_subject_match = function(
      client,
      userinfo,
      id_token
    ) {
      match_called <<- TRUE
      stop("Should not be called when id_token is missing")
    },
    .package = "shinyOAuth",
    {
      shinyOAuth:::verify_token_set(
        cli,
        token_set = token_set,
        nonce = NULL,
        is_refresh = TRUE
        # No original_id_token needed since there's no id_token in response
      )
    }
  )

  expect_false(
    match_called,
    label = "verify_userinfo_id_token_subject_match must not be called when id_token missing"
  )
})

# Test that handle_callback DOES perform userinfo/id_token match after fetching userinfo

test_that("handle_callback: userinfo/id_token match IS performed after userinfo fetch", {
  # This test confirms that handle_callback explicitly calls

  # verify_userinfo_id_token_subject_match AFTER fetching userinfo,
  # when userinfo_id_token_match = TRUE.

  prov <- oauth_provider(
    name = "test",
    auth_url = "https://test.example.com/auth",
    token_url = "https://test.example.com/token",
    userinfo_url = "https://test.example.com/userinfo",
    issuer = "https://test.example.com",
    use_nonce = TRUE,
    use_pkce = TRUE,
    pkce_method = "S256",
    userinfo_required = TRUE,
    id_token_required = TRUE,
    id_token_validation = TRUE,
    userinfo_id_token_match = TRUE, # This is the key setting
    token_auth_style = "body",
    jwks_cache = cachem::cache_mem(max_age = 60),
    allowed_algs = c("RS256"),
    allowed_token_types = c("Bearer")
  )

  cli <- oauth_client(
    provider = prov,
    client_id = "test-client",
    client_secret = "",
    redirect_uri = "http://localhost:8100",
    scopes = c("openid", "profile"),
    state_store = cachem::cache_mem(max_age = 600),
    state_key = paste0(
      "0123456789abcdefghijklmnopqrstuvwxyz",
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    )
  )

  tok <- valid_browser_token()
  url <- shinyOAuth:::prepare_call(cli, browser_token = tok)
  enc <- parse_query_param(url, "state")

  match_called <- FALSE
  match_args <- list()

  result <- testthat::with_mocked_bindings(
    swap_code_for_token_set = function(client, code, code_verifier) {
      list(
        access_token = "test-access-token",
        token_type = "Bearer",
        expires_in = 3600,
        id_token = "header.payload.signature",
        scope = "openid profile"
      )
    },
    validate_id_token = function(
      client,
      id_token,
      expected_nonce = NULL,
      expected_sub = NULL
    ) {
      invisible(list(sub = "user123", iss = "https://test.example.com"))
    },
    get_userinfo = function(oauth_client, token) {
      list(sub = "user123", name = "Test User")
    },
    verify_userinfo_id_token_subject_match = function(
      client,
      userinfo,
      id_token
    ) {
      match_called <<- TRUE
      match_args <<- list(userinfo = userinfo, id_token = id_token)
      invisible(NULL)
    },
    .package = "shinyOAuth",
    {
      shinyOAuth:::handle_callback(
        cli,
        code = "auth-code",
        payload = enc,
        browser_token = tok
      )
    }
  )

  # The match MUST have been called
  expect_true(
    match_called,
    label = "verify_userinfo_id_token_subject_match must be called during handle_callback"
  )

  # Verify it was called with the correct arguments
  expect_equal(match_args$userinfo, list(sub = "user123", name = "Test User"))
  expect_equal(match_args$id_token, "header.payload.signature")
})

test_that("handle_callback: userinfo/id_token mismatch aborts login", {
  # When userinfo_id_token_match = TRUE and subjects don't match,
  # handle_callback must abort with the appropriate error.

  prov <- oauth_provider(
    name = "test",
    auth_url = "https://test.example.com/auth",
    token_url = "https://test.example.com/token",
    userinfo_url = "https://test.example.com/userinfo",
    issuer = "https://test.example.com",
    use_nonce = TRUE,
    use_pkce = TRUE,
    pkce_method = "S256",
    userinfo_required = TRUE,
    id_token_required = TRUE,
    id_token_validation = TRUE,
    userinfo_id_token_match = TRUE,
    token_auth_style = "body",
    jwks_cache = cachem::cache_mem(max_age = 60),
    allowed_algs = c("RS256"),
    allowed_token_types = c("Bearer")
  )

  cli <- oauth_client(
    provider = prov,
    client_id = "test-client",
    client_secret = "",
    redirect_uri = "http://localhost:8100",
    scopes = c("openid", "profile"),
    state_store = cachem::cache_mem(max_age = 600),
    state_key = paste0(
      "0123456789abcdefghijklmnopqrstuvwxyz",
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    )
  )

  tok <- valid_browser_token()
  url <- shinyOAuth:::prepare_call(cli, browser_token = tok)
  enc <- parse_query_param(url, "state")

  # Let the real verify_userinfo_id_token_subject_match run - it should detect mismatch

  expect_error(
    testthat::with_mocked_bindings(
      swap_code_for_token_set = function(client, code, code_verifier) {
        list(
          access_token = "test-access-token",
          token_type = "Bearer",
          expires_in = 3600,
          id_token = "header.payload.signature",
          scope = "openid profile"
        )
      },
      validate_id_token = function(
        client,
        id_token,
        expected_nonce = NULL,
        expected_sub = NULL
      ) {
        # ID token says sub = "user123"
        invisible(list(sub = "user123", iss = "https://test.example.com"))
      },
      get_userinfo = function(oauth_client, token) {
        # Userinfo says sub = "different-user" - MISMATCH!
        list(sub = "different-user", name = "Imposter")
      },
      .package = "shinyOAuth",
      {
        shinyOAuth:::handle_callback(
          cli,
          code = "auth-code",
          payload = enc,
          browser_token = tok
        )
      }
    ),
    class = "shinyOAuth_userinfo_error"
  )
})
