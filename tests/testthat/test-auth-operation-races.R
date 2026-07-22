make_deferred_promise <- function() {
  control <- new.env(parent = emptyenv())
  control$promise <- promises::promise(function(resolve, reject) {
    control$resolve <- resolve
    control$reject <- reject
  })
  control
}

testthat::test_that("logout invalidates a pending async login", {
  testthat::skip_if_not_installed("promises")
  testthat::skip_if_not_installed("later")
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))

  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  login <- make_deferred_promise()
  revoked <- character()

  shiny::testServer(
    app = oauth_module_server,
    args = list(
      id = "auth",
      client = cli,
      auto_redirect = FALSE,
      async = TRUE
    ),
    expr = {
      url <- values$build_auth_url()
      state <- parse_query_param(url, "state")

      testthat::with_mocked_bindings(
        prepare_client_for_worker = function(client) client,
        async_dispatch = function(...) login$promise,
        revoke_token = function(oauth_client, token, which, ...) {
          revoked <<- c(revoked, which)
          invisible(NULL)
        },
        .package = "shinyOAuth",
        {
          values$.process_query(paste0("?code=old&state=", state))
          values$logout()

          login$resolve(OAuthToken(
            access_token = "stale-login",
            refresh_token = "stale-refresh"
          ))
          poll_for_async(function() length(revoked) == 2L, session)
        }
      )

      session$flushReact()
      testthat::expect_null(values$token)
      testthat::expect_identical(values$error, "logged_out")
      testthat::expect_false(isTRUE(values$authenticated))
      testthat::expect_setequal(revoked, c("refresh", "access"))
    }
  )
})

testthat::test_that("logout invalidates pending refresh and releases its flag", {
  testthat::skip_if_not_installed("promises")
  testthat::skip_if_not_installed("later")
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))

  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  refresh <- make_deferred_promise()
  revoked <- character()

  shiny::testServer(
    app = oauth_module_server,
    args = list(
      id = "auth",
      client = cli,
      auto_redirect = FALSE,
      async = TRUE,
      refresh_proactively = TRUE,
      refresh_lead_seconds = 4000,
      refresh_check_interval = 100
    ),
    expr = {
      testthat::with_mocked_bindings(
        refresh_token = function(...) refresh$promise,
        revoke_token = function(oauth_client, token, which, ...) {
          revoked <<- c(revoked, paste(token@access_token, which, sep = ":"))
          invisible(NULL)
        },
        .package = "shinyOAuth",
        {
          values$token <- OAuthToken(
            access_token = "old",
            refresh_token = "old-refresh",
            expires_at = as.numeric(Sys.time()) + 3600
          )
          values$error <- NULL
          poll_for_async(function() isTRUE(values$refresh_in_progress), session)

          values$logout()
          testthat::expect_false(isTRUE(values$refresh_in_progress))

          refresh$resolve(OAuthToken(
            access_token = "stale-refresh-result",
            refresh_token = "rotated-refresh",
            expires_at = as.numeric(Sys.time()) + 3600
          ))
          poll_for_async(
            function() sum(grepl("^stale-refresh-result:", revoked)) == 2L,
            session
          )
        }
      )

      session$flushReact()
      testthat::expect_null(values$token)
      testthat::expect_identical(values$error, "logged_out")
      testthat::expect_false(isTRUE(values$refresh_in_progress))
    }
  )
})

testthat::test_that("old refresh failure cannot clear a replacement login", {
  testthat::skip_if_not_installed("promises")
  testthat::skip_if_not_installed("later")
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))

  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  refresh <- make_deferred_promise()
  login <- make_deferred_promise()

  shiny::testServer(
    app = oauth_module_server,
    args = list(
      id = "auth",
      client = cli,
      auto_redirect = FALSE,
      async = TRUE,
      refresh_proactively = TRUE,
      refresh_lead_seconds = 4000,
      refresh_check_interval = 100
    ),
    expr = {
      url <- values$build_auth_url()
      state <- parse_query_param(url, "state")

      testthat::with_mocked_bindings(
        prepare_client_for_worker = function(client) client,
        async_dispatch = function(...) login$promise,
        refresh_token = function(...) refresh$promise,
        revoke_token = function(...) invisible(NULL),
        .package = "shinyOAuth",
        {
          values$token <- OAuthToken(
            access_token = "old",
            refresh_token = "old-refresh",
            expires_at = as.numeric(Sys.time()) + 3600
          )
          values$error <- NULL
          poll_for_async(function() isTRUE(values$refresh_in_progress), session)

          values$logout()
          values$browser_token <- "__SKIPPED__"
          values$.process_query(paste0("?code=new&state=", state))
          testthat::expect_false(isTRUE(values$refresh_in_progress))

          login$resolve(OAuthToken(
            access_token = "new-login",
            refresh_token = "new-refresh",
            expires_at = as.numeric(Sys.time()) + 10000
          ))
          poll_for_async(
            function() {
              !is.null(values$token) &&
                identical(values$token@access_token, "new-login")
            },
            session
          )

          refresh$reject(simpleError("old refresh failed"))
          deadline <- Sys.time() + 0.25
          while (Sys.time() < deadline) {
            later::run_now(0.02)
            session$flushReact()
          }
        }
      )

      testthat::expect_identical(values$token@access_token, "new-login")
      testthat::expect_null(values$error)
      testthat::expect_false(isTRUE(values$refresh_in_progress))
    }
  )
})

testthat::test_that("refresh completion requires the same source token", {
  testthat::skip_if_not_installed("promises")
  testthat::skip_if_not_installed("later")
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))

  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  refresh <- make_deferred_promise()

  shiny::testServer(
    app = oauth_module_server,
    args = list(
      id = "auth",
      client = cli,
      auto_redirect = FALSE,
      async = TRUE,
      refresh_proactively = TRUE,
      refresh_lead_seconds = 4000,
      refresh_check_interval = 100
    ),
    expr = {
      testthat::with_mocked_bindings(
        refresh_token = function(...) refresh$promise,
        revoke_token = function(...) invisible(NULL),
        .package = "shinyOAuth",
        {
          values$token <- OAuthToken(
            access_token = "source",
            refresh_token = "source-refresh",
            expires_at = as.numeric(Sys.time()) + 3600
          )
          poll_for_async(function() isTRUE(values$refresh_in_progress), session)

          values$token <- OAuthToken(
            access_token = "replacement",
            refresh_token = "replacement-refresh",
            expires_at = as.numeric(Sys.time()) + 10000
          )
          refresh$resolve(OAuthToken(
            access_token = "stale",
            refresh_token = "rotated",
            expires_at = as.numeric(Sys.time()) + 3600
          ))
          poll_for_async(
            function() !isTRUE(values$refresh_in_progress),
            session
          )
        }
      )

      testthat::expect_identical(values$token@access_token, "replacement")
      testthat::expect_false(isTRUE(values$refresh_in_progress))
    }
  )
})

testthat::test_that("reauthentication invalidates a pending refresh", {
  testthat::skip_if_not_installed("promises")
  testthat::skip_if_not_installed("later")
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))

  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  refresh <- make_deferred_promise()
  stale_revocations <- 0L

  shiny::testServer(
    app = oauth_module_server,
    args = list(
      id = "auth",
      client = cli,
      auto_redirect = FALSE,
      async = TRUE,
      reauth_after_seconds = 1,
      refresh_proactively = TRUE,
      refresh_lead_seconds = 4000,
      refresh_check_interval = 100
    ),
    expr = {
      testthat::with_mocked_bindings(
        refresh_token = function(...) refresh$promise,
        revoke_token = function(oauth_client, token, which, ...) {
          if (identical(token@access_token, "stale")) {
            stale_revocations <<- stale_revocations + 1L
          }
          invisible(NULL)
        },
        .package = "shinyOAuth",
        {
          values$auth_started_at <- as.numeric(Sys.time()) - 10
          values$token <- OAuthToken(
            access_token = "source",
            refresh_token = "source-refresh",
            expires_at = as.numeric(Sys.time()) + 3600
          )
          poll_for_async(
            function() identical(values$error, "reauth_required"),
            session
          )

          refresh$resolve(OAuthToken(
            access_token = "stale",
            refresh_token = "rotated",
            expires_at = as.numeric(Sys.time()) + 3600
          ))
          poll_for_async(function() stale_revocations == 2L, session)
        }
      )

      testthat::expect_null(values$token)
      testthat::expect_identical(values$error, "reauth_required")
      testthat::expect_false(isTRUE(values$refresh_in_progress))
    }
  )
})
