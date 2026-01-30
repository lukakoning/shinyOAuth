testthat::test_that("revoke_on_session_end calls revoke_token when session ends", {
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))

  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  cli@provider@revocation_url <- "https://example.com/revoke"

  # Track revoke_token calls
  revoke_calls <- list()
  mock_revoke <- function(
    client,
    token,
    which,
    async = FALSE,
    shiny_session = NULL
  ) {
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
  testthat::expect_true(!any(async_values))
})

testthat::test_that("revoke_on_session_end uses async only when module async = TRUE", {
  testthat::skip_on_cran()
  testthat::skip_if_not_installed("promises")
  testthat::skip_if_not_installed("mirai")
  testthat::skip_if_not_installed("later")

  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))

  # Use mirai synchronous mode so mocks apply
  mirai::daemons(sync = TRUE)
  withr::defer(mirai::daemons(0))

  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  cli@provider@revocation_url <- "https://example.com/revoke"

  revoke_calls <- list()
  mock_revoke <- function(
    client,
    token,
    which,
    async = FALSE,
    shiny_session = NULL
  ) {
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
  testthat::expect_true(all(async_values))
})

testthat::test_that("revoke_on_session_end does NOT call revoke_token when FALSE", {
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))

  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  cli@provider@revocation_url <- "https://example.com/revoke"

  # Track revoke_token calls
  revoke_calls <- list()
  mock_revoke <- function(
    client,
    token,
    which,
    async = FALSE,
    shiny_session = NULL
  ) {
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
  mock_revoke <- function(
    client,
    token,
    which,
    async = FALSE,
    shiny_session = NULL
  ) {
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

  mock_revoke <- function(
    client,
    token,
    which,
    async = FALSE,
    shiny_session = NULL
  ) {
    list(supported = TRUE, revoked = TRUE, status = "ok")
  }

  session_token <- NULL

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
          session_token <<- .scalar_chr(session$token)

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

  testthat::expect_true(is.character(session_token) && nzchar(session_token))
  idx <- match("audit_session_ended_revoke", types)
  ev <- audit_events[[idx]]
  seen <- (ev$shiny_session %||% list())$token %||% NA_character_
  testthat::expect_identical(seen, session_token)
})

testthat::test_that("session_ended event is emitted even without revoke_on_session_end", {
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))

  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)

  # Capture audit events
  audit_events <- list()
  withr::local_options(list(
    shinyOAuth.audit_hook = function(event) {
      audit_events <<- c(audit_events, list(event))
    }
  ))

  shiny::testServer(
    app = oauth_module_server,
    args = list(
      id = "auth",
      client = cli,
      auto_redirect = FALSE,
      indefinite_session = TRUE,
      revoke_on_session_end = FALSE # default; no revocation
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

  # Find the session_ended audit event (should always be emitted)
  types <- vapply(audit_events, function(e) e$type %||% "", character(1))
  testthat::expect_true("audit_session_ended" %in% types)

  # Verify session_ended contains was_authenticated = TRUE
  idx <- match("audit_session_ended", types)
  ev <- audit_events[[idx]]
  testthat::expect_true(isTRUE(ev$was_authenticated))
})

testthat::test_that("authenticated_changed event is emitted on token set", {
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))

  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)

  # Capture audit events
  audit_events <- list()
  withr::local_options(list(
    shinyOAuth.audit_hook = function(event) {
      audit_events <<- c(audit_events, list(event))
    }
  ))

  shiny::testServer(
    app = oauth_module_server,
    args = list(
      id = "auth",
      client = cli,
      auto_redirect = FALSE,
      indefinite_session = TRUE
    ),
    expr = {
      # Initially not authenticated
      testthat::expect_false(values$authenticated)

      # Seed a valid token -> should trigger authenticated_changed
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

  # Find the authenticated_changed audit event
  types <- vapply(audit_events, function(e) e$type %||% "", character(1))
  testthat::expect_true("audit_authenticated_changed" %in% types)

  # Verify at least one change to TRUE was emitted
  auth_changed_events <- audit_events[types == "audit_authenticated_changed"]
  to_true <- vapply(
    auth_changed_events,
    function(e) {
      isTRUE(e$authenticated) && !isTRUE(e$previous_authenticated)
    },
    logical(1)
  )
  testthat::expect_true(any(to_true))
})
