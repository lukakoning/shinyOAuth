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

testthat::test_that("provider error in query sets error and authenticated FALSE", {
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
      values$.process_query("?error=access_denied&error_description=Nope")
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
        strrep("x", 20000)
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
      withr::local_options(list(
        shinyOAuth.callback_max_query_bytes = query_bytes - 1
      ))
      values$.process_query(query)
      session$flushReact()
      testthat::expect_identical(values$error, "invalid_callback_query")
      testthat::expect_match(values$error_description %||% "", "query string")
      testthat::expect_null(values$token)

      # Large enough cap allows the normal flow to proceed
      values$error <- NULL
      values$error_description <- NULL
      called <- FALSE
      withr::local_options(list(
        shinyOAuth.callback_max_query_bytes = query_bytes + 1
      ))
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
      url <- values$build_auth_url()
      enc <- parse_query_param(url, "state")

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

      testthat::expect_identical(values$error, "token_exchange_error")
      testthat::expect_true(
        any(seen == "shinyOAuth:clearQueryAndFixTitle"),
        info = "Expected clearQueryAndFixTitle on token-exchange error"
      )
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
