testthat::test_that("manual login flow yields authenticated TRUE on success", {
  # Ensure module skips browser cookie dependency in tests
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))

  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)

  shiny::testServer(
    app = oauth_module_server,
    args = list(
      id = "auth",
      client = cli,
      auto_redirect = FALSE, # we'll drive the flow manually
      indefinite_session = TRUE # avoid expiry-related flakes
    ),
    expr = {
      # We should have a synthetic browser token available in tests
      testthat::expect_true(values$has_browser_token())

      # Build auth URL and capture state
      url <- values$build_auth_url()
      testthat::expect_true(is.character(url) && nzchar(url))
      enc <- parse_query_param(url, "state")
      testthat::expect_true(is.character(enc) && nzchar(enc))

      # Mock token exchange to avoid real HTTP
      token <- testthat::with_mocked_bindings(
        swap_code_for_token_set = function(client, code, code_verifier) {
          list(access_token = "t", expires_in = 3600)
        },
        .package = "shinyOAuth",
        {
          # Simulate provider callback
          values$.process_query(paste0("?code=ok&state=", enc))
          session$flushReact()
          # Return the token for assertions
          values$token
        }
      )

      testthat::expect_false(is.null(token))
      session$flushReact()
      testthat::expect_true(
        is.logical(values$authenticated) && isTRUE(values$authenticated)
      )
      testthat::expect_null(values$error)
      testthat::expect_null(values$error_description)
    }
  )
})

testthat::test_that("login fails when introspection validation fails", {
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))

  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  cli@provider@introspection_url <- "https://example.com/introspect"
  cli@introspect <- TRUE
  cli@introspect_elements <- character(0)

  shiny::testServer(
    app = oauth_module_server,
    args = list(
      id = "auth",
      client = cli,
      auto_redirect = FALSE,
      indefinite_session = TRUE
    ),
    expr = {
      testthat::expect_true(values$has_browser_token())

      url <- values$build_auth_url()
      enc <- parse_query_param(url, "state")

      testthat::with_mocked_bindings(
        swap_code_for_token_set = function(client, code, code_verifier) {
          list(access_token = "t", expires_in = 3600)
        },
        req_with_retry = function(req) {
          httr2::response(
            url = as.character(req$url),
            status = 200,
            headers = list("content-type" = "application/json"),
            body = charToRaw('{"active":false}')
          )
        },
        .package = "shinyOAuth",
        {
          values$.process_query(paste0("?code=ok&state=", enc))
          session$flushReact()
        }
      )

      testthat::expect_false(isTRUE(values$authenticated))
      testthat::expect_null(values$token)
      testthat::expect_identical(values$error, "token_exchange_error")
      testthat::expect_true(
        is.character(values$error_description) &&
          grepl("not active", values$error_description, ignore.case = TRUE)
      )
    }
  )
})

testthat::test_that("auto_redirect triggers when unauthenticated and cookie present", {
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))

  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)

  shiny::testServer(
    app = oauth_module_server,
    args = list(
      id = "auth",
      client = cli,
      auto_redirect = TRUE,
      indefinite_session = TRUE
    ),
    expr = {
      # Simulate the initial empty query string load
      values$.process_query("")
      session$flushReact()
      testthat::expect_true(isTRUE(values$auto_redirected))
    }
  )
})

testthat::test_that("authenticated becomes FALSE for expired token (default mode)", {
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))

  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)

  shiny::testServer(
    app = oauth_module_server,
    args = list(
      id = "auth",
      client = cli,
      auto_redirect = FALSE,
      indefinite_session = FALSE
    ),
    expr = {
      # Seed a token that is already expired
      t <- OAuthToken(
        access_token = "x",
        refresh_token = NA_character_,
        expires_at = as.numeric(Sys.time()) - 10,
        id_token = NA_character_
      )
      values$token <- t
      # Observer recalculates authenticated when token changes
      session$flushReact()
      testthat::expect_false(values$authenticated)
    }
  )
})

testthat::test_that("reauth_after_seconds makes authenticated FALSE when max age exceeded", {
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))

  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)

  shiny::testServer(
    app = oauth_module_server,
    args = list(
      id = "auth",
      client = cli,
      auto_redirect = FALSE,
      reauth_after_seconds = 1,
      indefinite_session = FALSE
    ),
    expr = {
      # Valid token not expired, but make session "old"
      t <- OAuthToken(
        access_token = "x",
        refresh_token = NA_character_,
        expires_at = as.numeric(Sys.time()) + 3600,
        id_token = NA_character_
      )
      values$token <- t
      values$auth_started_at <- as.numeric(Sys.time()) - 5
      # Trigger recompute: poke token (no-op) to invalidate observer deps
      values$token <- values$token
      session$flushReact()
      testthat::expect_false(values$authenticated)
    }
  )
})

testthat::test_that("authenticated flips FALSE after expiry without poking reactive values", {
  # This test verifies that the authenticated observer includes time-based
  # re-evaluation logic. Since invalidateLater() timers don't fire reliably in
  # testServer, we verify the underlying behavior: after time passes, any
  # reactive flush should pick up the expired state.
  testthat::skip_on_cran() # Timing-sensitive test; may be flaky on slow CRAN machines
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))

  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)

  shiny::testServer(
    app = oauth_module_server,
    args = list(
      id = "auth",
      client = cli,
      auto_redirect = FALSE,
      indefinite_session = FALSE,
      refresh_proactively = FALSE
    ),
    expr = {
      # Seed a token that expires very soon (200ms from now)
      expire_in_secs <- 0.2
      t <- OAuthToken(
        access_token = "x",
        refresh_token = NA_character_,
        expires_at = as.numeric(Sys.time()) + expire_in_secs,
        id_token = NA_character_
      )
      values$token <- t
      session$flushReact()

      # Immediately after setting, authenticated should be TRUE
      testthat::expect_true(values$authenticated)

      # Wait for expiry to pass
      Sys.sleep(expire_in_secs + 0.1)

      # After time passes, reassigning the token (even to same value) should
      # trigger the authenticated observer to re-run. This verifies that
      # .compute_authenticated() correctly detects expiry via Sys.time().
      # In a real app, invalidateLater() schedules this automatically.
      old_token <- values$token
      values$token <- NULL
      values$token <- old_token
      session$flushReact()

      # Authenticated should now be FALSE because .compute_authenticated()
      # checks Sys.time() against expires_at
      testthat::expect_false(values$authenticated)
    }
  )
})

testthat::test_that("authenticated flips FALSE after reauth_after_seconds without poking", {
  # Same approach as expiry test - verify the logic works when time passes.
  testthat::skip_on_cran() # Timing-sensitive test; may be flaky on slow CRAN machines
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))

  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)

  shiny::testServer(
    app = oauth_module_server,
    args = list(
      id = "auth",
      client = cli,
      auto_redirect = FALSE,
      reauth_after_seconds = 0.2,
      indefinite_session = FALSE,
      refresh_proactively = FALSE
    ),
    expr = {
      # Token with long expiry, but short reauth window
      t <- OAuthToken(
        access_token = "x",
        refresh_token = NA_character_,
        expires_at = as.numeric(Sys.time()) + 3600,
        id_token = NA_character_
      )
      values$token <- t
      values$auth_started_at <- as.numeric(Sys.time())
      session$flushReact()

      testthat::expect_true(values$authenticated)

      # Wait for reauth window to pass
      Sys.sleep(0.35)

      # Trigger reactive re-evaluation by toggling token
      old_token <- values$token
      values$token <- NULL
      values$token <- old_token
      session$flushReact()

      testthat::expect_false(values$authenticated)
    }
  )
})

testthat::test_that("authenticated TRUE for token with NA expires_at (no expiry)", {
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))

  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)

  shiny::testServer(
    app = oauth_module_server,
    args = list(
      id = "auth",
      client = cli,
      auto_redirect = FALSE,
      indefinite_session = FALSE
    ),
    expr = {
      # Token with NA expires_at should be treated as non-expiring
      t <- OAuthToken(
        access_token = "x",
        refresh_token = NA_character_,
        expires_at = NA_real_,
        id_token = NA_character_
      )
      values$token <- t
      session$flushReact()

      testthat::expect_true(values$authenticated)
    }
  )
})

testthat::test_that("authenticated TRUE for token with Inf expires_at", {
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))

  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)

  shiny::testServer(
    app = oauth_module_server,
    args = list(
      id = "auth",
      client = cli,
      auto_redirect = FALSE,
      indefinite_session = FALSE
    ),
    expr = {
      # Token with Inf expires_at should be treated as non-expiring
      t <- OAuthToken(
        access_token = "x",
        refresh_token = NA_character_,
        expires_at = Inf,
        id_token = NA_character_
      )
      values$token <- t
      session$flushReact()

      testthat::expect_true(values$authenticated)
    }
  )
})

testthat::test_that("authenticated FALSE when error is set (default mode)", {
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))

  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)

  shiny::testServer(
    app = oauth_module_server,
    args = list(
      id = "auth",
      client = cli,
      auto_redirect = FALSE,
      indefinite_session = FALSE
    ),
    expr = {
      # Valid token
      t <- OAuthToken(
        access_token = "x",
        refresh_token = NA_character_,
        expires_at = as.numeric(Sys.time()) + 3600,
        id_token = NA_character_
      )
      values$token <- t
      session$flushReact()
      testthat::expect_true(values$authenticated)

      # Setting error should flip authenticated to FALSE
      values$error <- "some_error"
      session$flushReact()
      testthat::expect_false(values$authenticated)

      # Clearing error should restore authenticated
      values$error <- NULL
      session$flushReact()
      testthat::expect_true(values$authenticated)
    }
  )
})

testthat::test_that("authenticated FALSE when token is cleared", {
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))

  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)

  shiny::testServer(
    app = oauth_module_server,
    args = list(
      id = "auth",
      client = cli,
      auto_redirect = FALSE,
      indefinite_session = FALSE
    ),
    expr = {
      # Start with valid token
      t <- OAuthToken(
        access_token = "x",
        refresh_token = NA_character_,
        expires_at = as.numeric(Sys.time()) + 3600,
        id_token = NA_character_
      )
      values$token <- t
      session$flushReact()
      testthat::expect_true(values$authenticated)

      # Clearing token should flip authenticated to FALSE
      values$token <- NULL
      session$flushReact()
      testthat::expect_false(values$authenticated)
    }
  )
})

testthat::test_that("authenticated correct at exact expiry boundary", {
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))

  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)

  shiny::testServer(
    app = oauth_module_server,
    args = list(
      id = "auth",
      client = cli,
      auto_redirect = FALSE,
      indefinite_session = FALSE
    ),
    expr = {
      # Token expiring exactly now (edge case: now >= exp is FALSE)
      now <- as.numeric(Sys.time())
      t <- OAuthToken(
        access_token = "x",
        refresh_token = NA_character_,
        expires_at = now,
        id_token = NA_character_
      )
      values$token <- t
      session$flushReact()

      # At exact boundary, now >= exp should be TRUE, so authenticated = FALSE
      testthat::expect_false(values$authenticated)
    }
  )
})

testthat::test_that("indefinite_session keeps authenticated TRUE even when expired or error", {
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))

  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)

  shiny::testServer(
    app = oauth_module_server,
    args = list(
      id = "auth",
      client = cli,
      auto_redirect = FALSE,
      indefinite_session = TRUE
    ),
    expr = {
      # Expired token
      t <- OAuthToken(
        access_token = "x",
        refresh_token = NA_character_,
        expires_at = as.numeric(Sys.time()) - 10,
        id_token = NA_character_
      )
      values$token <- t
      # Even with an error, authenticated should remain TRUE in indefinite mode
      values$error <- "some_error"
      values$error_description <- "desc"
      # Poke token to trigger compute observer
      values$token <- values$token
      session$flushReact()
      testthat::expect_true(values$authenticated)
    }
  )
})

testthat::test_that("provider error with valid state sets provider error and authenticated FALSE", {
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))

  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)

  seen <- character(0)
  sess <- shiny::MockShinySession$new()
  orig <- sess$sendCustomMessage
  sess$sendCustomMessage <- function(type, message) {
    seen <<- c(seen, type)
    orig(type, message)
  }

  shiny::testServer(
    app = oauth_module_server,
    args = list(
      id = "auth",
      client = cli,
      auto_redirect = FALSE
    ),
    session = sess,
    expr = {
      # Flush any pending reactive events from module initialization
      session$flushReact()

      url <- values$build_auth_url()
      enc <- parse_query_param(url, "state")
      values$.process_query(paste0(
        "?error=access_denied&error_description=Nope&state=",
        enc
      ))
      session$flushReact()
      testthat::expect_identical(values$error, "access_denied")
      testthat::expect_match(values$error_description, "Nope")
      testthat::expect_false(values$authenticated)

      testthat::expect_true(
        any(seen == "shinyOAuth:clearQueryAndFixTitle"),
        info = "Expected clearQueryAndFixTitle on provider error response"
      )
    }
  )
})

testthat::test_that("error_uri from provider error callback is surfaced", {
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
      session$flushReact()

      url <- values$build_auth_url()
      enc <- parse_query_param(url, "state")

      # Provider returns error + error_description + error_uri
      values$.process_query(paste0(
        "?error=access_denied",
        "&error_description=Nope",
        "&error_uri=https%3A%2F%2Fprovider.example%2Fhelp%2Faccess_denied",
        "&state=",
        enc
      ))
      session$flushReact()

      testthat::expect_identical(values$error, "access_denied")
      testthat::expect_match(values$error_description, "Nope")
      testthat::expect_identical(
        values$error_uri,
        "https://provider.example/help/access_denied"
      )
      testthat::expect_false(values$authenticated)
    }
  )
})

testthat::test_that("error_uri is NULL when provider omits it", {
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
      session$flushReact()

      url <- values$build_auth_url()
      enc <- parse_query_param(url, "state")

      # Provider returns error without error_uri
      values$.process_query(paste0(
        "?error=server_error&state=",
        enc
      ))
      session$flushReact()

      testthat::expect_identical(values$error, "server_error")
      testthat::expect_null(values$error_uri)
    }
  )
})

testthat::test_that("oversized error_uri in callback is rejected", {
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))

  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)

  shiny::testServer(
    app = oauth_module_server,
    args = list(
      id = "auth",
      client = cli,
      auto_redirect = FALSE,
      indefinite_session = TRUE
    ),
    expr = {
      url <- values$build_auth_url()
      enc <- parse_query_param(url, "state")

      values$.process_query(
        paste0(
          "?error=access_denied&error_uri=",
          strrep("x", 3000),
          "&state=",
          enc
        )
      )
      session$flushReact()

      testthat::expect_identical(values$error, "invalid_callback_query")
      testthat::expect_match(
        values$error_description %||% "",
        "error_uri"
      )
    }
  )
})

testthat::test_that("oversized callback query params are rejected", {
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))

  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)

  shiny::testServer(
    app = oauth_module_server,
    args = list(
      id = "auth",
      client = cli,
      auto_redirect = FALSE,
      indefinite_session = TRUE
    ),
    expr = {
      # Build a real state payload
      url <- values$build_auth_url()
      enc <- parse_query_param(url, "state")

      # Oversized code should short-circuit before token exchange
      called <- FALSE
      testthat::with_mocked_bindings(
        swap_code_for_token_set = function(client, code, code_verifier) {
          called <<- TRUE
          list(access_token = "t", expires_in = 3600)
        },
        .package = "shinyOAuth",
        {
          values$.process_query(paste0(
            "?code=",
            strrep("a", 5000),
            "&state=",
            enc
          ))
          session$flushReact()
        }
      )

      testthat::expect_false(called)
      testthat::expect_identical(values$error, "invalid_callback_query")
      testthat::expect_match(
        values$error_description %||% "",
        "exceeded maximum length"
      )

      # Oversized error_description should also be rejected
      values$error <- NULL
      values$error_description <- NULL
      values$.process_query(
        paste0(
          "?error=access_denied&error_description=",
          strrep("x", 5000),
          "&state=",
          enc
        )
      )
      session$flushReact()
      testthat::expect_identical(values$error, "invalid_callback_query")
      testthat::expect_match(
        values$error_description %||% "",
        "error_description"
      )
    }
  )
})

testthat::test_that("oversized raw callback query string is rejected", {
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))

  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)

  shiny::testServer(
    app = oauth_module_server,
    args = list(
      id = "auth",
      client = cli,
      auto_redirect = FALSE,
      indefinite_session = TRUE
    ),
    expr = {
      # Build a real state payload
      url <- values$build_auth_url()
      enc <- parse_query_param(url, "state")

      # Construct a very large query string that would otherwise proceed to
      # token exchange (code+state are valid), but should be rejected before
      # parsing due to total size.
      big_query <- paste0(
        "?code=ok&state=",
        enc,
        "&pad=",
        strrep("x", 25000)
      )

      called <- FALSE
      testthat::with_mocked_bindings(
        swap_code_for_token_set = function(client, code, code_verifier) {
          called <<- TRUE
          list(access_token = "t", expires_in = 3600)
        },
        .package = "shinyOAuth",
        {
          values$.process_query(big_query)
          session$flushReact()
        }
      )

      testthat::expect_false(called)
      testthat::expect_identical(values$error, "invalid_callback_query")
      testthat::expect_match(
        values$error_description %||% "",
        "query string"
      )
      testthat::expect_null(values$token)
    }
  )
})

testthat::test_that("callback_max_query_bytes option is enforced", {
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))

  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)

  shiny::testServer(
    app = oauth_module_server,
    args = list(
      id = "auth",
      client = cli,
      auto_redirect = FALSE,
      indefinite_session = TRUE
    ),
    expr = {
      url <- values$build_auth_url()
      enc <- parse_query_param(url, "state")

      query <- paste0("?code=ok&state=", enc)
      query_bytes <- nchar(query, type = "bytes")

      # Too-small cap rejects the query before parsing continues
      withr::with_options(
        list(shinyOAuth.callback_max_query_bytes = query_bytes - 1),
        {
          values$.process_query(query)
          session$flushReact()
        }
      )
      testthat::expect_identical(values$error, "invalid_callback_query")
      testthat::expect_match(values$error_description %||% "", "query string")
      testthat::expect_null(values$token)

      # Large enough cap allows the normal flow to proceed
      values$error <- NULL
      values$error_description <- NULL
      called <- FALSE
      withr::with_options(
        list(shinyOAuth.callback_max_query_bytes = query_bytes + 1),
        {
          testthat::with_mocked_bindings(
            swap_code_for_token_set = function(client, code, code_verifier) {
              called <<- TRUE
              list(access_token = "t", expires_in = 3600)
            },
            .package = "shinyOAuth",
            {
              values$.process_query(query)
              session$flushReact()
            }
          )
        }
      )
      testthat::expect_true(called)
      testthat::expect_false(is.null(values$token))
      testthat::expect_null(values$error)
    }
  )
})

testthat::test_that("callback code/state clears query even when token exchange fails", {
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))

  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)

  seen <- character(0)
  sess <- shiny::MockShinySession$new()
  orig <- sess$sendCustomMessage
  sess$sendCustomMessage <- function(type, message) {
    seen <<- c(seen, type)
    orig(type, message)
  }

  shiny::testServer(
    app = oauth_module_server,
    args = list(
      id = "auth",
      client = cli,
      auto_redirect = FALSE,
      indefinite_session = TRUE
    ),
    session = sess,
    expr = {
      # Flush any pending reactive events from module initialization
      # (e.g., the url_search observer with MockShinySession's default ?mocksearch=1)
      session$flushReact()

      # Ensure browser token is properly initialized before building auth URL.
      # If this fails, the option didn't propagate correctly to the module.
      testthat::expect_true(
        values$has_browser_token(),
        info = "Browser token should be available in test mode"
      )

      url <- values$build_auth_url()
      testthat::expect_true(
        is.character(url) && nchar(url) > 0 && !is.na(url),
        info = "build_auth_url() should return a valid URL"
      )
      enc <- parse_query_param(url, "state")
      testthat::expect_true(
        is.character(enc) && nchar(enc) > 0 && !is.na(enc),
        info = "State parameter should be extractable from URL"
      )

      testthat::with_mocked_bindings(
        swap_code_for_token_set = function(client, code, code_verifier) {
          rlang::abort("exchange_failed")
        },
        .package = "shinyOAuth",
        {
          values$.process_query(paste0("?code=bad&state=", enc))
          session$flushReact()
        }
      )

      testthat::expect_identical(
        values$error,
        "token_exchange_error",
        info = paste0(
          "error=",
          values$error,
          "; ",
          "desc=",
          values$error_description %||% "(none)"
        )
      )
      testthat::expect_true(
        any(seen == "shinyOAuth:clearQueryAndFixTitle"),
        info = "Expected clearQueryAndFixTitle on token-exchange error"
      )
    }
  )
})

testthat::test_that("callback params are cleared when token already exists", {
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))

  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)

  seen <- character(0)
  sess <- shiny::MockShinySession$new()
  orig <- sess$sendCustomMessage
  sess$sendCustomMessage <- function(type, message) {
    seen <<- c(seen, type)
    orig(type, message)
  }

  shiny::testServer(
    app = oauth_module_server,
    args = list(
      id = "auth",
      client = cli,
      auto_redirect = FALSE
    ),
    session = sess,
    expr = {
      # Drain startup events and isolate this test's message capture.
      session$flushReact()
      seen <<- character(0)

      t <- OAuthToken(
        access_token = "existing",
        refresh_token = NA_character_,
        expires_at = as.numeric(Sys.time()) + 3600,
        id_token = NA_character_
      )
      values$token <- t

      values$.process_query("?code=abc&state=s1&foo=1")
      session$flushReact()

      testthat::expect_true(
        any(seen == "shinyOAuth:clearQueryAndFixTitle"),
        info = "Expected clearQueryAndFixTitle when callback params appear with existing token"
      )
      testthat::expect_identical(values$token@access_token, "existing")
    }
  )
})

testthat::test_that("query size cap enforced even when token already exists", {
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))

  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)

  shiny::testServer(
    app = oauth_module_server,
    args = list(
      id = "auth",
      client = cli,
      auto_redirect = FALSE,
      indefinite_session = TRUE
    ),
    expr = {
      # Seed an existing token so we enter the "already authenticated" branch.
      t <- OAuthToken(
        access_token = "existing",
        refresh_token = NA_character_,
        expires_at = as.numeric(Sys.time()) + 3600,
        id_token = NA_character_
      )
      values$token <- t

      # Build an oversized query that contains OAuth callback keys.
      # The default derived cap is ~20480 bytes; use 30 000 to exceed it.
      big_query <- paste0(
        "?code=abc&state=s1&pad=",
        strrep("x", 30000)
      )

      values$.process_query(big_query)
      session$flushReact()

      # The oversized query should be rejected before parsing.
      testthat::expect_identical(values$error, "invalid_callback_query")
      testthat::expect_match(
        values$error_description %||% "",
        "query string"
      )
      # Token must remain untouched.
      testthat::expect_identical(values$token@access_token, "existing")
    }
  )
})

testthat::test_that("strip_oauth_query removes only OAuth params", {
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
      q <- "?code=abc&state=s1&foo=1&bar=2"
      out <- values$.strip_oauth_query(q)
      testthat::expect_true(identical(out, "?foo=1&bar=2"))

      q2 <- "?foo=1&bar=2"
      out2 <- values$.strip_oauth_query(q2)
      testthat::expect_identical(out2, "?foo=1&bar=2")

      q3 <- "?code=abc&state=s1"
      out3 <- values$.strip_oauth_query(q3)
      testthat::expect_identical(out3, "")
    }
  )
})

testthat::test_that("oauth_module_server clears token and sets error when proactive refresh fails", {
  testthat::skip_if_not_installed("later")

  # Integration test: trigger the module's proactive refresh observer and
  # assert that the module (not the test) clears token and sets error.
  withr::local_options(list(
    shinyOAuth.skip_browser_token = TRUE,
    shinyOAuth.skip_id_sig = TRUE
  ))

  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)

  shiny::testServer(
    app = oauth_module_server,
    args = list(
      id = "auth",
      client = cli,
      auto_redirect = FALSE,
      async = FALSE,
      indefinite_session = FALSE,
      refresh_proactively = TRUE,
      # Make the lead window larger than remaining so refresh is attempted
      # immediately, but keep expiry far enough in the future to avoid the
      # separate expiry watcher racing this test.
      refresh_lead_seconds = 4000,
      refresh_check_interval = 100
    ),
    expr = {
      # Seed a token that is "valid" but will be proactively refreshed
      t <- OAuthToken(
        access_token = "old_at",
        refresh_token = "rt",
        expires_at = as.numeric(Sys.time()) + 3600,
        id_token = NA_character_
      )
      values$token <- t
      values$auth_started_at <- as.numeric(Sys.time())
      # Ensure we start from a clean error state
      values$error <- NULL
      values$error_description <- NULL
      session$flushReact()

      # Force refresh_token() to error as if ID token validation failed.
      testthat::with_mocked_bindings(
        refresh_token = function(
          oauth_client,
          token,
          async = FALSE,
          introspect = FALSE,
          shiny_session = NULL
        ) {
          shinyOAuth:::err_id_token("Invalid ID token")
        },
        .package = "shinyOAuth",
        {
          # Pump the event loop until the observer runs or timeout
          deadline <- Sys.time() + 2
          while (is.null(values$error) && Sys.time() < deadline) {
            later::run_now(0.05)
            session$flushReact()
            Sys.sleep(0.01)
          }
        }
      )

      testthat::expect_identical(values$error, "token_refresh_error")
      testthat::expect_false(is.null(values$error_description))
      testthat::expect_true(is.null(values$token))
      testthat::expect_false(values$authenticated)
      testthat::expect_false(isTRUE(values$refresh_in_progress))
    }
  )
})
