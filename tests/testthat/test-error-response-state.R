# Tests for error-response state consumption behavior
# When OAuth provider returns ?error=... with a state parameter, the module
# should consume the state from the state store to reduce stale entries.

testthat::test_that("error response with state consumes state from store", {
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))

  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)

  # Track audit events
  events <- list()
  old <- options(shinyOAuth.audit_hook = function(e) {
    events[[length(events) + 1]] <<- e
  })
  on.exit(options(old), add = TRUE)

  shiny::testServer(
    app = oauth_module_server,
    args = list(
      id = "auth",
      client = cli,
      auto_redirect = FALSE
    ),
    expr = {
      # Build auth URL to populate state store
      url <- values$build_auth_url()
      enc <- parse_query_param(url, "state")
      testthat::expect_true(is.character(enc) && nzchar(enc))

      # Verify state is in store before error response
      payload <- shinyOAuth:::state_payload_decrypt_validate(cli, enc)
      key <- shinyOAuth:::state_cache_key(payload$state)
      before <- cli@state_store$get(key, missing = NULL)
      testthat::expect_false(is.null(before))

      # Simulate provider error response with state
      values$.process_query(paste0("?error=access_denied&state=", enc))
      session$flushReact()

      # Error should be surfaced
      testthat::expect_identical(values$error, "access_denied")
      testthat::expect_false(values$authenticated)

      # State should be consumed from store
      after <- cli@state_store$get(key, missing = NULL)
      testthat::expect_null(after)
    }
  )

  # Check audit event was emitted (type field has "audit_" prefix)
  event_types <- vapply(events, function(e) e$type %||% "", character(1))
  testthat::expect_true(
    "audit_error_state_consumed" %in% event_types,
    info = "Expected audit_error_state_consumed audit event"
  )
})

testthat::test_that("unsolicited error response without state is rejected as invalid_state", {
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))

  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)

  shiny::testServer(
    app = oauth_module_server,
    args = list(
      id = "auth",
      client = cli,
      auto_redirect = FALSE
    ),
    expr = {
      # Simulate unsolicited provider error without state parameter
      values$.process_query(
        "?error=server_error&error_description=Something%20broke"
      )
      session$flushReact()

      testthat::expect_identical(values$error, "invalid_state")
      testthat::expect_match(values$error_description %||% "", "state")
      testthat::expect_false(values$authenticated)
    }
  )
})

testthat::test_that("error response with state is validated even before browser_token is available", {
  # Do NOT skip browser token for this test
  withr::local_options(list(shinyOAuth.skip_browser_token = FALSE))

  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)

  shiny::testServer(
    app = oauth_module_server,
    args = list(
      id = "auth",
      client = cli,
      auto_redirect = FALSE
    ),
    expr = {
      # Initially no browser token
      testthat::expect_null(values$browser_token)

      # Manually inject a state into the store for testing
      # (normally build_auth_url would do this, but it requires browser_token)
      state_val <- shinyOAuth:::random_urlsafe(64)
      key <- shinyOAuth:::state_cache_key(state_val)
      cli@state_store$set(
        key,
        list(
          browser_token = valid_browser_token(),
          pkce_code_verifier = "test",
          nonce = NA_character_
        )
      )

      # Create encrypted state payload
      payload <- list(
        state = state_val,
        client_id = cli@client_id,
        redirect_uri = cli@redirect_uri,
        scopes = cli@scopes,
        provider = shinyOAuth:::provider_fingerprint(cli@provider),
        issued_at = as.numeric(Sys.time())
      )
      enc <- shinyOAuth:::state_encrypt_gcm(payload, key = cli@state_key)

      # Process error with state but no browser_token
      values$.process_query(paste0("?error=access_denied&state=", enc))
      session$flushReact()

      # Error is surfaced and state is consumed immediately.
      testthat::expect_null(values$pending_error)
      testthat::expect_identical(values$error, "access_denied")
      testthat::expect_false(values$authenticated)

      # State should already be consumed from store.
      after <- cli@state_store$get(key, missing = NULL)
      testthat::expect_null(after)
    }
  )
})

testthat::test_that("error response without state is rejected after login initiation", {
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))

  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)

  shiny::testServer(
    app = oauth_module_server,
    args = list(
      id = "auth",
      client = cli,
      auto_redirect = FALSE
    ),
    expr = {
      # Build auth URL to get valid state
      url <- values$build_auth_url()
      enc <- parse_query_param(url, "state")
      payload <- shinyOAuth:::state_payload_decrypt_validate(cli, enc)
      key <- shinyOAuth:::state_cache_key(payload$state)

      # Error callback missing state should be rejected as invalid_state,
      # even though a valid login state exists in the store.
      values$.process_query("?error=access_denied")
      session$flushReact()

      testthat::expect_identical(values$error, "invalid_state")
      testthat::expect_match(values$error_description %||% "", "state")
      testthat::expect_false(values$authenticated)

      # Existing valid state must remain untouched because callback was invalid.
      still_present <- cli@state_store$get(key, missing = NULL)
      testthat::expect_false(is.null(still_present))
    }
  )
})

testthat::test_that("state consumption failure rejects callback as invalid_state", {
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))

  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)

  # Track audit events
  events <- list()
  old <- options(shinyOAuth.audit_hook = function(e) {
    events[[length(events) + 1]] <<- e
  })
  on.exit(options(old), add = TRUE)

  shiny::testServer(
    app = oauth_module_server,
    args = list(
      id = "auth",
      client = cli,
      auto_redirect = FALSE
    ),
    expr = {
      # Build a valid URL to get a properly encrypted state
      url <- values$build_auth_url()
      enc <- parse_query_param(url, "state")

      # Pre-remove the state from store to cause consumption failure
      payload <- shinyOAuth:::state_payload_decrypt_validate(cli, enc)
      key <- shinyOAuth:::state_cache_key(payload$state)
      cli@state_store$remove(key)

      # Process error with valid-looking but already-consumed state
      values$.process_query(paste0("?error=consent_required&state=", enc))
      session$flushReact()

      testthat::expect_identical(values$error, "invalid_state")
      testthat::expect_match(values$error_description %||% "", "state")
      testthat::expect_false(values$authenticated)
    }
  )

  # Check that consumption failure was audited (type field has "audit_" prefix)
  event_types <- vapply(events, function(e) e$type %||% "", character(1))
  testthat::expect_true(
    "audit_error_state_consumption_failed" %in% event_types,
    info = "Expected audit_error_state_consumption_failed audit event"
  )
})

testthat::test_that("error response with invalid state is rejected as invalid_state", {
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))

  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)

  # Track audit events
  events <- list()
  old <- options(shinyOAuth.audit_hook = function(e) {
    events[[length(events) + 1]] <<- e
  })
  on.exit(options(old), add = TRUE)

  shiny::testServer(
    app = oauth_module_server,
    args = list(
      id = "auth",
      client = cli,
      auto_redirect = FALSE
    ),
    expr = {
      # Simulate error with garbage/tampered state
      values$.process_query("?error=invalid_request&state=garbage_state_value")
      session$flushReact()

      testthat::expect_identical(values$error, "invalid_state")
      testthat::expect_match(values$error_description %||% "", "state")
      testthat::expect_false(values$authenticated)
    }
  )

  # Check that consumption failure was audited (type field has "audit_" prefix)
  event_types <- vapply(events, function(e) e$type %||% "", character(1))
  testthat::expect_true(
    "audit_error_state_consumption_failed" %in% event_types,
    info = "Expected audit_error_state_consumption_failed audit event for invalid state"
  )
})

testthat::test_that("error response with error_description preserves it", {
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))

  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)

  shiny::testServer(
    app = oauth_module_server,
    args = list(
      id = "auth",
      client = cli,
      auto_redirect = FALSE
    ),
    expr = {
      # Build auth URL to get valid state
      url <- values$build_auth_url()
      enc <- parse_query_param(url, "state")

      # Simulate error with description and state
      query <- paste0(
        "?error=temporarily_unavailable",
        "&error_description=Try%20again%20later",
        "&state=",
        enc
      )
      values$.process_query(query)
      session$flushReact()

      testthat::expect_identical(values$error, "temporarily_unavailable")
      testthat::expect_match(values$error_description, "Try again later")
    }
  )
})

testthat::test_that("error response with valid state never triggers login", {
  # This test ensures that even with a completely valid state (that could

  # otherwise be used for login), an error response does NOT result in

  # authentication. The state is consumed for cleanup, but no token is issued.
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))

  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)

  shiny::testServer(
    app = oauth_module_server,
    args = list(
      id = "auth",
      client = cli,
      auto_redirect = FALSE
    ),
    expr = {
      # Build auth URL to populate state store with valid state
      url <- values$build_auth_url()
      enc <- parse_query_param(url, "state")
      testthat::expect_true(is.character(enc) && nzchar(enc))

      # Verify state is valid and in store
      payload <- shinyOAuth:::state_payload_decrypt_validate(cli, enc)
      key <- shinyOAuth:::state_cache_key(payload$state)
      state_entry <- cli@state_store$get(key, missing = NULL)
      testthat::expect_false(is.null(state_entry))

      # Process error response (even though state is perfectly valid)
      values$.process_query(paste0("?error=access_denied&state=", enc))
      session$flushReact()

      # CRITICAL: No token should be set
      testthat::expect_null(values$token)

      # CRITICAL: authenticated must be FALSE
      testthat::expect_false(values$authenticated)

      # Error should be surfaced
      testthat::expect_identical(values$error, "access_denied")

      # State should be consumed (cleanup) but not used for login
      after <- cli@state_store$get(key, missing = NULL)
      testthat::expect_null(after)
    }
  )
})

testthat::test_that("error response does not trigger token exchange", {
  # Ensure that swap_code_for_token_set is NEVER called for error responses
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))

  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)

  token_exchange_called <- FALSE

  shiny::testServer(
    app = oauth_module_server,
    args = list(
      id = "auth",
      client = cli,
      auto_redirect = FALSE
    ),
    expr = {
      # Build auth URL to get valid state
      url <- values$build_auth_url()
      enc <- parse_query_param(url, "state")

      testthat::with_mocked_bindings(
        swap_code_for_token_set = function(client, code, code_verifier) {
          token_exchange_called <<- TRUE
          list(access_token = "should_not_be_called", expires_in = 3600)
        },
        .package = "shinyOAuth",
        {
          # Process error response with valid state
          values$.process_query(paste0("?error=server_error&state=", enc))
          session$flushReact()
        }
      )

      # Token exchange should NOT have been called
      testthat::expect_false(token_exchange_called)

      # Confirm error state, not authenticated
      testthat::expect_identical(values$error, "server_error")
      testthat::expect_null(values$token)
      testthat::expect_false(values$authenticated)
    }
  )
})
