# Adversarial tests: verify that external callers cannot bypass state-store
# replay protections via handle_callback(). The public API must always
# decrypt/validate the payload and consume the state entry itself.

test_that("handle_callback() does not accept decrypted_payload bypass arg", {
  # Public handle_callback() must NOT have a decrypted_payload parameter
  # that callers can use to skip state_payload_decrypt_validate()
  expect_false(
    "decrypted_payload" %in% names(formals(shinyOAuth::handle_callback))
  )
})

test_that("handle_callback() does not accept state_store_values bypass arg", {
  # Public handle_callback() must NOT have a state_store_values parameter
  # that callers can use to skip state_store_get_remove()
  expect_false(
    "state_store_values" %in% names(formals(shinyOAuth::handle_callback))
  )
})

test_that("handle_callback_internal is NOT exported", {
  # The internal helper with bypass hooks must not be accessible via ::

  exports <- getNamespaceExports("shinyOAuth")
  expect_false("handle_callback_internal" %in% exports)
})

test_that("handle_callback always consumes state store even when attacker supplies extra args", {
  # Even if an attacker somehow passes extra arguments, the public entry
  # point must still go through full state validation and state store consume.
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  tok <- valid_browser_token()
  url <- shinyOAuth:::prepare_call(cli, browser_token = tok)
  enc <- parse_query_param(url, "state")

  # Pre-decrypt payload and pre-fetch state store values (simulating what
  # an attacker with knowledge of internals might try)
  pre_payload <- shinyOAuth:::state_decrypt_gcm(enc, key = cli@state_key)
  shinyOAuth:::payload_verify_issued_at(cli, pre_payload)
  shinyOAuth:::payload_verify_client_binding(cli, pre_payload)
  key <- shinyOAuth:::state_cache_key(pre_payload$state)
  pre_state <- cli@state_store$get(key, missing = NULL)

  # Now REMOVE the state from the store to simulate single-use consumption
  cli@state_store$remove(key)

  # Attempting to pass bypass args should fail because handle_callback()
  # ignores them and tries to decrypt/consume itself — state is already gone
  expect_error(
    shinyOAuth::handle_callback(
      oauth_client = cli,
      code = "attacker_code",
      payload = enc,
      browser_token = tok,
      decrypted_payload = pre_payload,
      state_store_values = pre_state
    ),
    # The extra args are silently ignored (R passes them via ...) OR
    # rejected outright. Either way the callback must fail because the
    # state was already consumed from the store.
    regexp = "unused argument|State access failed|state"
  )
})

test_that("handle_callback enforces state-store consume on every call (replay blocked)", {
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  tok <- valid_browser_token()
  url <- shinyOAuth:::prepare_call(cli, browser_token = tok)
  enc <- parse_query_param(url, "state")

  # First call: stub token swap to succeed
  testthat::with_mocked_bindings(
    swap_code_for_token_set = function(client, code, code_verifier) {
      list(access_token = "at", expires_in = 3600)
    },
    .package = "shinyOAuth",
    {
      t1 <- shinyOAuth::handle_callback(
        cli,
        code = "c1",
        payload = enc,
        browser_token = tok
      )
      expect_true(is.character(t1@access_token) && nzchar(t1@access_token))
    }
  )

  # Second call with same payload must fail — state already consumed
  expect_error(
    shinyOAuth::handle_callback(
      cli,
      code = "c2",
      payload = enc,
      browser_token = tok
    ),
    class = "shinyOAuth_state_error",
    regexp = "State access failed|state"
  )
})

test_that("handle_callback_internal exists as non-exported function with bypass params", {
  # Verify the internal function exists and has the bypass parameters
  fn <- shinyOAuth:::handle_callback_internal
  expect_true(is.function(fn))
  fmls <- names(formals(fn))
  expect_true("decrypted_payload" %in% fmls)
  expect_true("state_store_values" %in% fmls)
})
