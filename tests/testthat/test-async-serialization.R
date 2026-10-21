# Tests for async serialization safety: prepare_client_for_worker() and
# fallback-to-sync when client contains non-serializable components.

# --- prepare_client_for_worker: unit tests -----------------------------------

process_bound_jwks_cache <- function(connection) {
  memory <- cachem::cache_mem(max_age = 300)
  custom_cache(
    get = function(key, missing = NULL) {
      seek(connection, where = 0)
      memory[["get"]](key, missing = missing)
    },
    set = function(key, value) {
      seek(connection, where = 0)
      memory[["set"]](key, value)
    },
    remove = function(key) memory[["remove"]](key)
  )
}

testthat::test_that("process-bound caches fall back during PAR, JAR and JARM preparation", {
  testthat::skip_if_not_installed("promises")
  withr::local_options(shinyOAuth.skip_browser_token = TRUE)
  key <- openssl::rsa_keygen()
  jwk <- canonicalize_local_public_jwk(jsonlite::parse_json(
    jose::write_jwk(key[["pubkey"]])
  ))
  connection <- file(withr::local_tempfile(), "w+b")
  withr::defer(close(connection))
  for (mode in c("par", "request", "request_uri", "jarm", "jarm-invalid")) {
    cli <- make_test_client(use_nonce = FALSE)
    cli@provider@issuer <- "https://example.com"
    cli@provider@jwks_uri <- "https://example.com/jwks"
    cli@provider@jwks_cache <- process_bound_jwks_cache(connection)
    if (mode == "par") cli@provider@par_url <- "https://example.com/par"
    if (mode %in% c("request", "request_uri")) {
      cli@provider@request_uri_parameter_supported <- TRUE
      S7::props(cli) <- list(client_assertion_private_key = key,
        request_object_mode = mode, request_object_signing_alg = "RS256")
    }
    if (startsWith(mode, "jarm")) {
      cli@provider@response_modes_supported <- c("query", "query.jwt")
      cli@provider@jarm_signing_alg_values_supported <- "RS256"
      S7::props(cli) <- list(response_mode = "query.jwt",
        jarm_signed_response_alg = "RS256")
    }
    pushes <- 0L
    published <- 0L
    testthat::local_mocked_bindings(
      async_dispatch = function(...) stop("Unsafe cache was dispatched"),
      publish_shiny_request_object = function(...) {
        published <<- published + 1L
        "https://app.example.com/request"
      },
      req_with_retry = function(req, ...) {
        par <- endsWith(req[["url"]], "/par")
        if (par) pushes <<- pushes + 1L
        body <- if (par) list(request_uri = "urn:test:cache-par", expires_in = 300) else
          list(keys = list(jwk))
        httr2::response(status_code = if (par) 201L else 200L,
          headers = list("content-type" = "application/json"),
          body = charToRaw(jsonlite::toJSON(body, auto_unbox = TRUE)))
      },
      .package = "shinyOAuth"
    )
    shiny::testServer(oauth_module_server, args = list(id = "auth", client = cli,
      async = TRUE, auto_redirect = FALSE, request_uri_base_url = "https://app.example.com"), {
      result <- suppressWarnings(values[["build_auth_url"]]())
      url <- NULL
      if (promises::is.promise(result)) {
        promises::then(result, function(value) {
          url <<- value
        })
        poll_for_async(function() !is.null(url), session)
      } else {
        url <- result
      }
      testthat::expect_null(values[["error"]], info = mode)
      testthat::expect_true(is_valid_string(url), info = mode)
      if (mode == "par") {
        testthat::expect_identical(pushes, 1L)
        testthat::expect_identical(parse_query_param(url, "request_uri", decode = TRUE),
          "urn:test:cache-par")
      } else if (mode == "request") {
        testthat::expect_true(is_valid_string(parse_query_param(url, "request", decode = TRUE)))
      } else if (mode == "request_uri") {
        testthat::expect_identical(published, 1L)
      } else {
        state <- parse_query_param(url, "state", decode = TRUE)
        payload <- state_decrypt_gcm(state, cli@state_key)
        state_key <- state_cache_key(payload[["state"]])
        jwt <- jose::jwt_encode_sig(jose::jwt_claim(
          iss = cli@provider@issuer, aud = cli@client_id,
          exp = as.numeric(Sys.time()) + 120, state = state, error = "access_denied"
        ), if (mode == "jarm") key else openssl::rsa_keygen(), header = list(alg = "RS256"))
        suppressWarnings(values[[".process_query"]](paste0("?response=", jwt)))
        poll_for_async(function() !is.null(values[["error"]]), session)
        if (mode == "jarm") {
          testthat::expect_identical(values[["error"]], "access_denied")
          testthat::expect_null(cli@state_store[["get"]](state_key, missing = NULL))
        } else {
          testthat::expect_false(identical(values[["error"]], "access_denied"))
          testthat::expect_false(is.null(cli@state_store[["get"]](state_key, missing = NULL)))
        }
      }
    })
  }
})

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

testthat::test_that("serialization does not qualify a process-bound JWKS cache for dispatch", {
  testthat::skip_if_not_installed("callr")
  path <- withr::local_tempfile()
  # Keep a connection number unavailable in a fresh worker, independently of
  # that worker's startup pipes. All connections remain valid in this process.
  connections <- lapply(seq_len(20), function(i) file(path, "w+b"))
  withr::defer(lapply(connections, close))
  cache <- process_bound_jwks_cache(connections[[length(connections)]])
  cache[["set"]]("present", "parent-value")
  testthat::expect_identical(cache[["get"]]("present"), "parent-value")
  bytes <- serialize(cache, NULL)
  testthat::expect_true(is.raw(bytes))
  worker <- callr::r(function(bytes) {
    cache <- unserialize(bytes)
    tryCatch({
      cache[["get"]]("present")
      FALSE
    }, error = function(...) TRUE)
  }, args = list(bytes = bytes))
  testthat::expect_true(worker)
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  cli@provider@jwks_cache <- cache
  testthat::expect_no_error(serialize(cli, NULL))
  testthat::expect_null(prepare_client_for_worker(cli))
  testthat::expect_identical(cli@provider@jwks_cache, cache)
})

testthat::test_that("explicit worker-safe caches reconnect and remain usable in a real worker", {
  testthat::skip_if_not_installed("callr")
  directory <- withr::local_tempdir()
  cache <- local({
    path <- directory
    custom_cache(
      get = function(key, missing = NULL) {
        file <- file.path(path, key)
        if (file.exists(file)) readRDS(file) else missing
      },
      set = function(key, value) saveRDS(value, file.path(path, key)),
      remove = function(key) unlink(file.path(path, key)),
      worker_safe = TRUE
    )
  })
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  cli@provider@jwks_cache <- cache
  cache[["set"]]("key", "parent-value")
  prepared <- prepare_client_for_worker(cli)
  testthat::expect_false(is.null(prepared))
  worker <- callr::r(function(client) {
    loadNamespace("shinyOAuth")
    value <- client@provider@jwks_cache[["get"]]("key")
    client@provider@jwks_cache[["set"]]("key", "worker-value")
    list(pid = Sys.getpid(), value = value)
  }, args = list(client = prepared))
  testthat::expect_false(identical(worker[["pid"]], Sys.getpid()))
  testthat::expect_identical(worker[["value"]], "parent-value")
  testthat::expect_identical(cache[["get"]]("key"), "worker-value")
  cli@provider@jwks_cache <- cachem::cache_disk(directory)
  testthat::expect_false(is.null(prepare_client_for_worker(cli)))
})

# --- async fallback-to-sync integration tests --------------------------------

testthat::test_that("async login with a process-bound JWKS cache falls back before code redemption", {
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
  connection <- file(withr::local_tempfile(), "w+b")
  withr::defer(close(connection))
  cli@provider@jwks_cache <- process_bound_jwks_cache(connection)
  cli@provider@issuer <- "https://issuer.example.com"
  cli@provider@jwks_uri <- "https://issuer.example.com/jwks"
  cli@provider@id_token_required <- TRUE
  cli@provider@id_token_validation <- TRUE
  cli@scopes <- "openid"
  key <- openssl::rsa_keygen()
  jwk <- canonicalize_local_public_jwk(jsonlite::parse_json(
    jose::write_jwk(key[["pubkey"]])
  ))
  now <- floor(as.numeric(Sys.time()))
  jwt <- jose::jwt_encode_sig(jose::jwt_claim(
    iss = cli@provider@issuer, aud = cli@client_id, sub = "subject",
    iat = now, exp = now + 300
  ), key, header = list(alg = "RS256"))
  exchanges <- 0L
  refresh_exchanges <- 0L

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
      testthat::expect_true(values[["has_browser_token"]]())

      # Build the authorization URL and capture encoded state
      url <- values[["build_auth_url"]]()
      enc <- parse_query_param(url, "state")
      testthat::expect_true(is.character(enc) && nzchar(enc))

      # Keep preparation, cache access, state consumption and signature checks
      # real. Substitute only the two HTTP responses.
      token <- testthat::with_mocked_bindings(
        swap_code_for_token_set = function(client, code, code_verifier) {
          exchanges <<- exchanges + 1L
          list(
            access_token = "t-sync-fallback",
            token_type = "Bearer",
            expires_in = 3600,
            id_token = jwt,
            refresh_token = "original-refresh"
          )
        },
        req_with_retry = function(req, ...) {
          body <- if (endsWith(req[["url"]], "/token")) {
            refresh_exchanges <<- refresh_exchanges + 1L
            list(access_token = "refreshed-access", token_type = "Bearer",
              expires_in = 3600, id_token = jwt, refresh_token = "rotated-refresh")
          } else {
            list(keys = list(jwk))
          }
          httr2::response(status_code = 200L,
            headers = list("content-type" = "application/json"),
            body = charToRaw(jsonlite::toJSON(body, auto_unbox = TRUE)))
        },
        .package = "shinyOAuth",
        {
          # The fallback should produce a warning
          rlang::reset_warning_verbosity("shinyOAuth-async-serialization-fallback")
          testthat::expect_warning(
            values[[".process_query"]](paste0("?code=ok&state=", enc)),
            class = "shinyOAuth_async_serialization_fallback"
          )
          # Sync fallback produces result immediately (no promise)
          session[["flushReact"]]()
          token <- values[["token"]]
          refreshed <- NULL
          refresh_error <- NULL
          testthat::with_mocked_bindings(
            async_dispatch = function(...) stop("Unsafe cache was dispatched"),
            .package = "shinyOAuth",
            {
              promise <- suppressWarnings(refresh_token(cli, token, async = TRUE,
                introspect = FALSE))
              testthat::expect_true(promises::is.promise(promise))
              promises::then(promise,
                onFulfilled = function(value) {
                  refreshed <<- value
                },
                onRejected = function(error) {
                  refresh_error <<- error
                })
              poll_for_async(function() !is.null(refreshed) || !is.null(refresh_error), session)
            }
          )
          testthat::expect_null(refresh_error)
          testthat::expect_true(refreshed@id_token_validated)
          testthat::expect_identical(refreshed@refresh_token, "rotated-refresh")
          testthat::expect_identical(refresh_exchanges, 1L)
          token
        }
      )

      testthat::expect_null(values[["error"]], info = values[["error_description"]])
      testthat::expect_false(is.null(token))
      testthat::expect_identical(token@access_token, "t-sync-fallback")
      testthat::expect_true(token@id_token_validated)
      testthat::expect_identical(exchanges, 1L)
      # Sync fallback should NOT set async flag
      testthat::expect_false(isTRUE(values[["last_login_async_used"]]))
      testthat::expect_true(isTRUE(values[["authenticated"]]))
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
      testthat::expect_true(values[["has_browser_token"]]())

      # Build the authorization URL and capture encoded state
      url <- values[["build_auth_url"]]()
      enc <- parse_query_param(url, "state")

      # Normal async path should work (no warning)
      token <- testthat::with_mocked_bindings(
        swap_code_for_token_set = function(client, code, code_verifier) {
          list(
            access_token = "t-async-ok",
            token_type = "Bearer",
            expires_in = 3600
          )
        },
        .package = "shinyOAuth",
        {
          values[[".process_query"]](paste0("?code=ok&state=", enc))
          poll_for_async(function() !is.null(values[["token"]]), session)
          values[["token"]]
        }
      )

      testthat::expect_false(is.null(token))
      testthat::expect_identical(token@access_token, "t-async-ok")
      testthat::expect_true(isTRUE(values[["last_login_async_used"]]))
    }
  )
})
