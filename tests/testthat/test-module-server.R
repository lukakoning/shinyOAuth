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
