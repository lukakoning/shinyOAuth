testthat::test_that("revoke_on_session_end calls revoke_token when session ends", {
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))

  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  cli@provider@revocation_url <- "https://example.com/revoke"

  # Track revoke_token calls
  revoke_calls <- list()
  mock_revoke <- function(client, token, which, async = FALSE) {
    revoke_calls <<- c(revoke_calls, list(list(which = which, async = async)))
    list(supported = TRUE, revoked = TRUE, status = "ok")
  }

  testthat::with_mocked_bindings(
    revoke_token = mock_revoke,
    .package = "shinyOAuth",
    {
      shiny::testServer(
        app = oauth_module_server,
        args = list(
          id = "auth",
          client = cli,
          auto_redirect = FALSE,
          indefinite_session = TRUE,
          revoke_on_session_end = TRUE
        ),
        expr = {
          # Seed a valid token
          t <- OAuthToken(
            access_token = "access_tok",
            refresh_token = "refresh_tok",
            expires_at = as.numeric(Sys.time()) + 3600,
            id_token = NA_character_
          )
          values$token <- t
          session$flushReact()

          testthat::expect_true(values$authenticated)
        }
      )
    }
  )

  # After testServer exits, onSessionEnded callbacks are fired
  # Verify both refresh and access tokens were revoked
  testthat::expect_length(revoke_calls, 2)

  which_values <- vapply(revoke_calls, function(x) x$which, character(1))
  testthat::expect_true("refresh" %in% which_values)
  testthat::expect_true("access" %in% which_values)

  async_values <- vapply(revoke_calls, function(x) isTRUE(x$async), logical(1))
  testthat::expect_true(all(async_values == FALSE))
})

testthat::test_that("revoke_on_session_end uses async only when module async = TRUE", {
  testthat::skip_on_cran()
  testthat::skip_if_not_installed("promises")
  testthat::skip_if_not_installed("future")
  testthat::skip_if_not_installed("later")

  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))

  # Use in-process futures so mocks apply within future_promise
  old_plan <- NULL
  if (requireNamespace("future", quietly = TRUE)) {
    old_plan <- tryCatch(future::plan(), error = function(...) NULL)
    try(future::plan(future::sequential), silent = TRUE)
    withr::defer({
      if (!is.null(old_plan)) try(future::plan(old_plan), silent = TRUE)
    })
  }

  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  cli@provider@revocation_url <- "https://example.com/revoke"

  revoke_calls <- list()
  mock_revoke <- function(client, token, which, async = FALSE) {
    revoke_calls <<- c(revoke_calls, list(list(which = which, async = async)))
    list(supported = TRUE, revoked = TRUE, status = "ok")
  }

  testthat::with_mocked_bindings(
    revoke_token = mock_revoke,
    .package = "shinyOAuth",
    {
      shiny::testServer(
        app = oauth_module_server,
        args = list(
          id = "auth",
          client = cli,
          auto_redirect = FALSE,
          async = TRUE,
          indefinite_session = TRUE,
          revoke_on_session_end = TRUE
        ),
        expr = {
          t <- OAuthToken(
            access_token = "access_tok",
            refresh_token = "refresh_tok",
            expires_at = as.numeric(Sys.time()) + 3600,
            id_token = NA_character_
          )
          values$token <- t
          session$flushReact()

          testthat::expect_true(values$authenticated)
        }
      )
    }
  )

  testthat::expect_length(revoke_calls, 2)
  async_values <- vapply(revoke_calls, function(x) isTRUE(x$async), logical(1))
  testthat::expect_true(all(async_values == TRUE))
})

testthat::test_that("revoke_on_session_end does NOT call revoke_token when FALSE", {
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))

  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  cli@provider@revocation_url <- "https://example.com/revoke"

  # Track revoke_token calls
  revoke_calls <- list()
  mock_revoke <- function(client, token, which, async = FALSE) {
    revoke_calls <<- c(revoke_calls, list(list(which = which)))
    list(supported = TRUE, revoked = TRUE, status = "ok")
  }

  testthat::with_mocked_bindings(
    revoke_token = mock_revoke,
    .package = "shinyOAuth",
    {
      shiny::testServer(
        app = oauth_module_server,
        args = list(
          id = "auth",
          client = cli,
          auto_redirect = FALSE,
          indefinite_session = TRUE,
          revoke_on_session_end = FALSE # default
        ),
        expr = {
          # Seed a valid token
          t <- OAuthToken(
            access_token = "access_tok",
            refresh_token = "refresh_tok",
            expires_at = as.numeric(Sys.time()) + 3600,
            id_token = NA_character_
          )
          values$token <- t
          session$flushReact()

          testthat::expect_true(values$authenticated)
        }
      )
    }
  )

  # No revoke calls should have been made on session end

  testthat::expect_length(revoke_calls, 0)
})

testthat::test_that("revoke_on_session_end skips revoke if no token present", {
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))

  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  cli@provider@revocation_url <- "https://example.com/revoke"

  # Track revoke_token calls
  revoke_calls <- list()
  mock_revoke <- function(client, token, which, async = FALSE) {
    revoke_calls <<- c(revoke_calls, list(list(which = which)))
    list(supported = TRUE, revoked = TRUE, status = "ok")
  }

  testthat::with_mocked_bindings(
    revoke_token = mock_revoke,
    .package = "shinyOAuth",
    {
      shiny::testServer(
        app = oauth_module_server,
        args = list(
          id = "auth",
          client = cli,
          auto_redirect = FALSE,
          indefinite_session = TRUE,
          revoke_on_session_end = TRUE
        ),
        expr = {
          # No token set - user never authenticated
          testthat::expect_null(values$token)
          testthat::expect_false(values$authenticated)
        }
      )
    }
  )

  # No revoke calls since there was no token
  testthat::expect_length(revoke_calls, 0)
})

testthat::test_that("revoke_on_session_end emits audit event", {
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))

  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  cli@provider@revocation_url <- "https://example.com/revoke"

  # Capture audit events
  audit_events <- list()
  withr::local_options(list(
    shinyOAuth.audit_hook = function(event) {
      audit_events <<- c(audit_events, list(event))
    }
  ))

  mock_revoke <- function(client, token, which, async = FALSE) {
    list(supported = TRUE, revoked = TRUE, status = "ok")
  }

  testthat::with_mocked_bindings(
    revoke_token = mock_revoke,
    .package = "shinyOAuth",
    {
      shiny::testServer(
        app = oauth_module_server,
        args = list(
          id = "auth",
          client = cli,
          auto_redirect = FALSE,
          indefinite_session = TRUE,
          revoke_on_session_end = TRUE
        ),
        expr = {
          # Seed a valid token
          t <- OAuthToken(
            access_token = "access_tok",
            refresh_token = "refresh_tok",
            expires_at = as.numeric(Sys.time()) + 3600,
            id_token = NA_character_
          )
          values$token <- t
          session$flushReact()
        }
      )
    }
  )

  # Find the session_ended_revoke audit event
  types <- vapply(audit_events, function(e) e$type %||% "", character(1))
  testthat::expect_true("audit_session_ended_revoke" %in% types)
})
