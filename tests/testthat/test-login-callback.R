test_that("payload_verify_issued_at rejects future and old payloads", {
  cli <- make_test_client(
    use_pkce = TRUE,
    use_nonce = FALSE,
    state_max_age = 600,
    state_payload_max_age = 2
  )

  # Build a fake payload and validate
  now <- as.numeric(Sys.time())
  p <- list(
    state = "stat",
    client_id = cli@client_id,
    redirect_uri = cli@redirect_uri,
    scopes = cli@scopes,
    provider = shinyOAuth:::provider_fingerprint(cli@provider),
    issued_at = now
  )
  expect_silent(shinyOAuth:::payload_verify_issued_at(cli, p))

  # Future issued_at
  p2 <- p
  p2$issued_at <- now + 3600
  expect_error(
    shinyOAuth:::payload_verify_issued_at(cli, p2),
    class = "shinyOAuth_state_error",
    regexp = "in the future"
  )

  # Too old: set max_age small and backdate
  p3 <- p
  p3$issued_at <- now - 10
  cli2 <- make_test_client(
    use_pkce = TRUE,
    use_nonce = FALSE,
    state_max_age = 600,
    state_payload_max_age = 1
  )
  expect_error(
    shinyOAuth:::payload_verify_issued_at(cli2, p3),
    class = "shinyOAuth_state_error",
    regexp = "too old"
  )
})

test_that("payload_verify_client_binding enforces client_id/redirect/scopes/provider", {
  cli <- make_test_client(
    use_pkce = TRUE,
    use_nonce = FALSE,
    scopes = c("openid", "profile")
  )
  base <- list(
    state = "s",
    client_id = cli@client_id,
    redirect_uri = cli@redirect_uri,
    scopes = cli@scopes,
    provider = shinyOAuth:::provider_fingerprint(cli@provider),
    issued_at = as.numeric(Sys.time())
  )
  expect_silent(shinyOAuth:::payload_verify_client_binding(cli, base))

  # Robustness: allow equivalent representations
  base2 <- base
  base2$scopes <- paste(cli@scopes, collapse = " ")
  expect_silent(shinyOAuth:::payload_verify_client_binding(cli, base2))

  base3 <- base
  base3$scopes <- as.list(cli@scopes)
  expect_silent(shinyOAuth:::payload_verify_client_binding(cli, base3))

  bad <- base
  bad$client_id <- "other"
  expect_error(
    shinyOAuth:::payload_verify_client_binding(cli, bad),
    class = "shinyOAuth_state_error",
    regexp = "client_id mismatch"
  )
  bad <- base
  bad$redirect_uri <- "http://localhost:9999"
  expect_error(
    shinyOAuth:::payload_verify_client_binding(cli, bad),
    class = "shinyOAuth_state_error",
    regexp = "redirect_uri mismatch"
  )
  bad <- base
  bad$scopes <- c("x")
  expect_error(
    shinyOAuth:::payload_verify_client_binding(cli, bad),
    class = "shinyOAuth_state_error",
    regexp = "scopes do not match"
  )
  bad <- base
  bad$provider <- paste0(base$provider, "-tamper")
  expect_error(
    shinyOAuth:::payload_verify_client_binding(cli, bad),
    class = "shinyOAuth_state_error",
    regexp = "provider fingerprint mismatch"
  )
})

test_that("handle_callback validates browser token, PKCE verifier, and nonce", {
  # Cover browser_token mismatch and PKCE verifier missing
  cli <- make_test_client(use_pkce = TRUE, use_nonce = TRUE)

  tok <- valid_browser_token()
  url <- shinyOAuth:::prepare_call(cli, browser_token = tok)
  enc <- parse_query_param(url, "state")
  payload <- shinyOAuth:::state_decrypt_gcm(enc, key = cli@state_key)

  # Tamper browser token at callback (valid hex/length but mismatched)
  wrong_tok <- paste0("ff", substring(tok, 3))
  expect_error(
    shinyOAuth:::handle_callback(
      cli,
      code = "abc",
      payload = enc,
      browser_token = wrong_tok
    ),
    class = "shinyOAuth_state_error",
    regexp = "Browser token mismatch|Browser token"
  )

  # Re-prepare to have state in store again
  url2 <- shinyOAuth:::prepare_call(cli, browser_token = tok)
  enc2 <- parse_query_param(url2, "state")

  # Stub token exchange to avoid network: we need PKCE verifier present
  testthat::with_mocked_bindings(
    swap_code_for_token_set = function(client, code, code_verifier) {
      testthat::expect_true(
        shinyOAuth:::validate_code_verifier(code_verifier) %||% TRUE
      )
      # Provider has an issuer (OIDC-like), so default policy enforces Bearer
      list(
        access_token = "at",
        expires_in = 3600,
        id_token = "dummy.jwt.token",
        token_type = "Bearer"
      )
    },
    validate_id_token = function(
      client,
      id_token,
      expected_nonce = NULL,
      expected_sub = NULL,
      expected_access_token = NULL,
      max_age = NULL
    ) {
      # Pretend success if expected_nonce non-empty
      if (isTRUE(client@provider@use_nonce)) {
        testthat::expect_true(
          is.character(expected_nonce) && nzchar(expected_nonce)
        )
      }
      invisible(list(sub = "u", iss = client@provider@issuer %||% ""))
    },
    .package = "shinyOAuth",
    {
      # Success path with correct browser token
      tok_obj <- shinyOAuth:::handle_callback(
        cli,
        code = "abc",
        payload = enc2,
        browser_token = tok
      )
      expect_true(
        is.character(tok_obj@access_token) && nzchar(tok_obj@access_token)
      )
    }
  )
})

test_that("handle_callback rejects oversized authorization code", {
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)

  tok <- valid_browser_token()
  url <- shinyOAuth:::prepare_call(cli, browser_token = tok)
  enc <- parse_query_param(url, "state")

  expect_error(
    shinyOAuth:::handle_callback(
      cli,
      code = strrep("a", 5000),
      payload = enc,
      browser_token = tok
    ),
    class = "shinyOAuth_state_error",
    regexp = "authorization code|Callback query parameter 'code'|exceeded maximum length"
  )
})

test_that("handle_callback rejects oversized payload before hashing/auditing", {
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)

  digested <- FALSE
  testthat::with_mocked_bindings(
    string_digest = function(x) {
      digested <<- TRUE
      "digest"
    },
    .package = "shinyOAuth",
    {
      expect_error(
        shinyOAuth:::handle_callback(
          cli,
          code = "abc",
          payload = strrep("a", 9000),
          browser_token = valid_browser_token()
        ),
        class = "shinyOAuth_state_error",
        regexp = "Callback query parameter 'state'|exceeded maximum length"
      )
    }
  )
  expect_false(digested)
})

test_that("handle_callback rejects oversized browser_token before hashing/auditing", {
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)

  digested <- FALSE
  testthat::with_mocked_bindings(
    string_digest = function(x) {
      digested <<- TRUE
      "digest"
    },
    .package = "shinyOAuth",
    {
      expect_error(
        shinyOAuth:::handle_callback(
          cli,
          code = "abc",
          payload = "x",
          browser_token = strrep("b", 300)
        ),
        class = "shinyOAuth_state_error",
        regexp = "Callback query parameter 'browser_token'|exceeded maximum length"
      )
    }
  )
  expect_false(digested)
})

test_that("state store is single-use during handle_callback", {
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  tok <- valid_browser_token()
  url <- shinyOAuth:::prepare_call(cli, browser_token = tok)
  enc <- parse_query_param(url, "state")

  # First callback consumes state key and succeeds through stub
  testthat::with_mocked_bindings(
    swap_code_for_token_set = function(client, code, code_verifier) {
      list(access_token = "at", expires_in = 1)
    },
    .package = "shinyOAuth",
    {
      t1 <- shinyOAuth:::handle_callback(
        cli,
        code = "c1",
        payload = enc,
        browser_token = tok
      )
      expect_true(is.character(t1@access_token) && nzchar(t1@access_token))
    }
  )

  # Second callback with same state should fail at state lookup
  expect_error(
    shinyOAuth:::handle_callback(
      cli,
      code = "c2",
      payload = enc,
      browser_token = tok
    ),
    class = "shinyOAuth_state_error",
    regexp = "State access failed|state"
  )
})

test_that("handle_callback errors when PKCE verifier missing and when browser token format invalid", {
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  tok <- valid_browser_token()
  url <- shinyOAuth:::prepare_call(cli, browser_token = tok)
  enc <- parse_query_param(url, "state")
  payload <- shinyOAuth:::state_decrypt_gcm(enc, key = cli@state_key)
  key <- shinyOAuth:::state_cache_key(payload$state)

  ssv <- cli@state_store$get(key, missing = NULL)
  # Simulate missing verifier (removing field from state store entry)
  ssv$pkce_code_verifier <- NULL
  cli@state_store$set(key, ssv)

  # Early validation in state_store_get_remove now catches malformed entries
  expect_error(
    shinyOAuth:::handle_callback(
      cli,
      code = "abc",
      payload = enc,
      browser_token = tok
    ),
    class = "shinyOAuth_state_error",
    regexp = "malformed.*missing required fields"
  )

  # Re-prepare and use malformed browser token
  url2 <- shinyOAuth:::prepare_call(cli, browser_token = tok)
  enc2 <- parse_query_param(url2, "state")
  badtok <- substr(tok, 1, nchar(tok) - 1) # wrong length
  expect_error(
    shinyOAuth:::handle_callback(
      cli,
      code = "abc",
      payload = enc2,
      browser_token = badtok
    ),
    class = "shinyOAuth_state_error",
    regexp = "Invalid browser token|browser token"
  )
})

test_that("verify_token_set enforces id_token requirement when provider demands it", {
  # Provider that requires id_token but we won't supply it
  prov <- make_test_provider(use_pkce = TRUE, use_nonce = FALSE)
  prov@id_token_required <- TRUE
  prov@id_token_validation <- FALSE
  cli <- oauth_client(
    provider = prov,
    client_id = "abc",
    client_secret = "",
    redirect_uri = "http://localhost:8100",
    scopes = character(0),
    state_store = cachem::cache_mem(max_age = 600),
    state_key = paste0(
      "0123456789abcdefghijklmnopqrstuvwxyz",
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    )
  )
  expect_error(
    shinyOAuth:::verify_token_set(
      cli,
      list(access_token = "at", expires_in = 10),
      nonce = NULL
    ),
    class = "shinyOAuth_id_token_error",
    regexp = "ID token required"
  )
})

test_that("handle_callback fails when nonce is required but missing in state store", {
  cli <- make_test_client(use_pkce = TRUE, use_nonce = TRUE)
  tok <- valid_browser_token()
  url <- shinyOAuth:::prepare_call(cli, browser_token = tok)
  enc <- parse_query_param(url, "state")
  payload <- shinyOAuth:::state_decrypt_gcm(enc, key = cli@state_key)
  key <- shinyOAuth:::state_cache_key(payload$state)
  ssv <- cli@state_store$get(key, missing = NULL)

  ssv$nonce <- NULL
  cli@state_store$set(key, ssv)

  # Early validation in state_store_get_remove now catches malformed entries
  # (nonce field removed = missing required field)
  expect_error(
    shinyOAuth:::handle_callback(
      cli,
      code = "abc",
      payload = enc,
      browser_token = tok
    ),
    class = "shinyOAuth_state_error",
    regexp = "malformed.*missing required fields"
  )
})

test_that("handle_callback fails when PKCE verifier is malformed (not NULL)", {
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  tok <- valid_browser_token()
  url <- shinyOAuth:::prepare_call(cli, browser_token = tok)
  enc <- parse_query_param(url, "state")
  payload <- shinyOAuth:::state_decrypt_gcm(enc, key = cli@state_key)
  key <- shinyOAuth:::state_cache_key(payload$state)
  ssv <- cli@state_store$get(key, missing = NULL)

  # Set verifier to a too-short value (RFC 7636 requires 43-128 chars)
  ssv$pkce_code_verifier <- "tooshort"
  cli@state_store$set(key, ssv)

  expect_error(
    shinyOAuth:::handle_callback(
      cli,
      code = "abc",
      payload = enc,
      browser_token = tok
    ),
    class = "shinyOAuth_pkce_error",
    regexp = "code_verifier|length"
  )

  # Re-prepare and test invalid characters
  url2 <- shinyOAuth:::prepare_call(cli, browser_token = tok)
  enc2 <- parse_query_param(url2, "state")
  payload2 <- shinyOAuth:::state_decrypt_gcm(enc2, key = cli@state_key)
  key2 <- shinyOAuth:::state_cache_key(payload2$state)
  ssv2 <- cli@state_store$get(key2, missing = NULL)

  # Valid length but invalid chars (contains '!')
  ssv2$pkce_code_verifier <- paste0("!", strrep("a", 50))
  cli@state_store$set(key2, ssv2)

  expect_error(
    shinyOAuth:::handle_callback(
      cli,
      code = "abc",
      payload = enc2,
      browser_token = tok
    ),
    class = "shinyOAuth_pkce_error",
    regexp = "code_verifier|invalid characters"
  )
})

test_that("handle_callback fails when nonce is malformed (not NULL)", {
  cli <- make_test_client(use_pkce = TRUE, use_nonce = TRUE)
  tok <- valid_browser_token()
  url <- shinyOAuth:::prepare_call(cli, browser_token = tok)
  enc <- parse_query_param(url, "state")
  payload <- shinyOAuth:::state_decrypt_gcm(enc, key = cli@state_key)
  key <- shinyOAuth:::state_cache_key(payload$state)
  ssv <- cli@state_store$get(key, missing = NULL)

  # Set nonce to a too-short value (validate_oidc_nonce requires >= 22 chars)
  ssv$nonce <- "short"
  cli@state_store$set(key, ssv)

  # Stub token swap to avoid network (nonce validation happens after swap)
  testthat::with_mocked_bindings(
    swap_code_for_token_set = function(client, code, code_verifier) {
      list(
        access_token = "at",
        token_type = "Bearer",
        expires_in = 10,
        id_token = "dummy.jwt.token"
      )
    },
    .package = "shinyOAuth",
    {
      expect_error(
        shinyOAuth:::handle_callback(
          cli,
          code = "abc",
          payload = enc,
          browser_token = tok
        ),
        class = "shinyOAuth_pkce_error",
        regexp = "nonce|length"
      )
    }
  )

  # Re-prepare and test invalid characters
  url2 <- shinyOAuth:::prepare_call(cli, browser_token = tok)
  enc2 <- parse_query_param(url2, "state")
  payload2 <- shinyOAuth:::state_decrypt_gcm(enc2, key = cli@state_key)
  key2 <- shinyOAuth:::state_cache_key(payload2$state)
  ssv2 <- cli@state_store$get(key2, missing = NULL)

  # Valid length but invalid chars (contains '!')
  ssv2$nonce <- "abc!defghijklmnopqrstuvwxyz"
  cli@state_store$set(key2, ssv2)

  testthat::with_mocked_bindings(
    swap_code_for_token_set = function(client, code, code_verifier) {
      list(
        access_token = "at",
        token_type = "Bearer",
        expires_in = 10,
        id_token = "dummy.jwt.token"
      )
    },
    .package = "shinyOAuth",
    {
      expect_error(
        shinyOAuth:::handle_callback(
          cli,
          code = "abc",
          payload = enc2,
          browser_token = tok
        ),
        class = "shinyOAuth_pkce_error",
        regexp = "nonce|invalid characters"
      )
    }
  )
})
