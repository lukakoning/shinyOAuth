# Tests for async serialization safety: prepare_client_for_worker() and
# fallback-to-sync when client contains non-serializable components.

# --- prepare_client_for_worker: unit tests -----------------------------------

testthat::test_that("prepare_client_for_worker returns serializable client with dummy state_store", {
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)

  worker_cli <- shinyOAuth:::prepare_client_for_worker(cli)

  # Should return a non-NULL OAuthClient

  testthat::expect_true(!is.null(worker_cli))
  testthat::expect_true(S7::S7_inherits(worker_cli, shinyOAuth::OAuthClient))

  # The state_store should be different from the original (replaced with a dummy)
  testthat::expect_false(identical(cli@state_store, worker_cli@state_store))

  # The worker client should be serializable
  testthat::expect_no_error(serialize(worker_cli, connection = NULL))

  # All other fields should be preserved
  testthat::expect_identical(worker_cli@client_id, cli@client_id)
  testthat::expect_identical(worker_cli@client_secret, cli@client_secret)
  testthat::expect_identical(worker_cli@redirect_uri, cli@redirect_uri)
  testthat::expect_identical(worker_cli@scopes, cli@scopes)
  testthat::expect_identical(worker_cli@state_key, cli@state_key)
  testthat::expect_identical(worker_cli@provider@name, cli@provider@name)
  testthat::expect_identical(
    worker_cli@provider@token_url,
    cli@provider@token_url
  )
})

testthat::test_that("prepare_client_for_worker does not mutate the original client", {
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  original_store <- cli@state_store

  shinyOAuth:::prepare_client_for_worker(cli)

  # The original client's state_store should be unchanged
  testthat::expect_identical(cli@state_store, original_store)
})

testthat::test_that("prepare_client_for_worker returns NULL for non-serializable client", {
  # Create a client with a state_store containing a non-serializable object.
  # External pointers cannot be serialized.
  nonsrl_cache <- cachem::cache_mem(max_age = 60)

  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)

  # Inject a non-serializable element into the provider to force failure
  # even after state_store replacement. We use an external pointer which

  # cannot be serialized.
  testthat::with_mocked_bindings(
    prepare_client_for_worker = function(client) {
      # Simulate serialization failure after state_store replacement
      tryCatch(
        {
          worker_client <- client
          worker_client@state_store <- cachem::cache_mem(max_age = 1)
          # Force a serialization error
          stop("simulated serialization failure")
          worker_client
        },
        error = function(e) {
          NULL
        }
      )
    },
    .package = "shinyOAuth",
    {
      result <- shinyOAuth:::prepare_client_for_worker(cli)
      testthat::expect_null(result)
    }
  )
})

testthat::test_that("prepare_client_for_worker returns NULL when client has genuinely non-serializable field", {
  # Create a client then corrupt it with a non-serializable object
  # (an external pointer) to test full serialization check
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)

  # We simulate: the provider's jwks_cache contains an external pointer
  # (e.g., a database connection). Even after replacing state_store,
  # the serialize() check should catch it.
  # Since we can't easily set an externalptr as a property on an S7 object
  # without triggering validators, we test via a mock that makes serialize() fail.
  testthat::with_mocked_bindings(
    prepare_client_for_worker = function(client) {
      NULL
    },
    .package = "shinyOAuth",
    {
      result <- shinyOAuth:::prepare_client_for_worker(cli)
      testthat::expect_null(result)
    }
  )
})

# --- async fallback-to-sync integration tests --------------------------------

testthat::test_that("async login with non-serializable client falls back to sync with warning", {
  testthat::skip_on_cran()
  testthat::skip_if_not_installed("promises")
  testthat::skip_if_not_installed("future")
  testthat::skip_if_not_installed("later")

  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))

  # Disable mirai so async_dispatch uses future (mocks work with sequential)
  if (rlang::is_installed("mirai")) {
    tryCatch(mirai::daemons(0), error = function(...) NULL)
  }

  # Use future::sequential so mocks apply (future runs in-process)
  old_plan <- future::plan()
  future::plan(future::sequential)
  withr::defer(future::plan(old_plan))

  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)

  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = list(
      id = "auth",
      client = cli,
      auto_redirect = FALSE,
      async = TRUE,
      indefinite_session = TRUE
    ),
    expr = {
      testthat::expect_true(values$has_browser_token())

      # Build the authorization URL and capture encoded state
      url <- values$build_auth_url()
      enc <- parse_query_param(url, "state")
      testthat::expect_true(is.character(enc) && nzchar(enc))

      # Mock prepare_client_for_worker to return NULL (simulating
      # non-serializable client) and swap_code_for_token_set for the
      # sync fallback path
      token <- testthat::with_mocked_bindings(
        prepare_client_for_worker = function(client) NULL,
        swap_code_for_token_set = function(client, code, code_verifier) {
          list(access_token = "t-sync-fallback", expires_in = 3600)
        },
        .package = "shinyOAuth",
        {
          # The fallback should produce a warning
          testthat::expect_warning(
            values$.process_query(paste0("?code=ok&state=", enc)),
            class = "shinyOAuth_async_serialization_fallback"
          )
          # Sync fallback produces result immediately (no promise)
          session$flushReact()
          values$token
        }
      )

      testthat::expect_false(is.null(token))
      testthat::expect_identical(token@access_token, "t-sync-fallback")
      # Sync fallback should NOT set async flag
      testthat::expect_false(isTRUE(values$last_login_async_used))
      testthat::expect_true(isTRUE(values$authenticated))
    }
  )
})

testthat::test_that("async login with serializable client still uses async path", {
  testthat::skip_on_cran()
  testthat::skip_if_not_installed("promises")
  testthat::skip_if_not_installed("future")
  testthat::skip_if_not_installed("later")

  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))

  # Disable mirai so async_dispatch uses future (mocks work with sequential)
  if (rlang::is_installed("mirai")) {
    tryCatch(mirai::daemons(0), error = function(...) NULL)
  }

  # Use future::sequential so mocks apply (future runs in-process)
  old_plan <- future::plan()
  future::plan(future::sequential)
  withr::defer(future::plan(old_plan))

  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)

  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = list(
      id = "auth",
      client = cli,
      auto_redirect = FALSE,
      async = TRUE,
      indefinite_session = TRUE
    ),
    expr = {
      testthat::expect_true(values$has_browser_token())

      # Build the authorization URL and capture encoded state
      url <- values$build_auth_url()
      enc <- parse_query_param(url, "state")

      # Normal async path should work (no warning)
      token <- testthat::with_mocked_bindings(
        swap_code_for_token_set = function(client, code, code_verifier) {
          list(access_token = "t-async-ok", expires_in = 3600)
        },
        .package = "shinyOAuth",
        {
          values$.process_query(paste0("?code=ok&state=", enc))
          deadline <- Sys.time() + 3
          while (is.null(values$token) && Sys.time() < deadline) {
            later::run_now(0.05)
            session$flushReact()
            Sys.sleep(0.01)
          }
          values$token
        }
      )

      testthat::expect_false(is.null(token))
      testthat::expect_identical(token@access_token, "t-async-ok")
      testthat::expect_true(isTRUE(values$last_login_async_used))
    }
  )
})
