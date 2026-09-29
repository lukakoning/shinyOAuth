test_that("target acquisition can renew short-lived primary and secondary tokens", {
  local_options(shinyOAuth.skip_browser_token = TRUE)
  now <- Sys.time()
  local_mocked_bindings(Sys.time = function() now, .package = "base")
  client <- make_test_client(
    use_nonce = FALSE,
    scopes = c("read", "write", "contacts")
  )
  provider <- client@provider
  provider@token_target_mode <- "rfc8707"
  S7::props(client) <- list(
    provider = provider,
    token_targets = list(
      primary = list(resource = "urn:primary", scopes = c("read", "write")),
      secondary = list(resource = "urn:secondary", scopes = "contacts")
    ),
    default_token_target = "primary"
  )
  calls <- 0L
  lifetime <- 10
  local_mocked_bindings(
    revoke_token = function(...) invisible(NULL),
    req_with_retry = function(req, ...) {
      calls <<- calls + 1L
      httr2::response(
        req[["url"]],
        status = 200L,
        headers = list("content-type" = "application/json"),
        body = charToRaw(jsonlite::toJSON(
          list(
            access_token = paste0("access-", calls),
            refresh_token = paste0("refresh-", calls),
            token_type = "Bearer",
            expires_in = lifetime,
            scope = utils::URLdecode(as.character(
              req[["body"]][["data"]][["scope"]]
            ))
          ),
          auto_unbox = TRUE
        ))
      )
    }
  )
  for (target in c("primary", "secondary")) {
    for (proactive in c(FALSE, TRUE)) {
      calls <- 0L
      shiny::testServer(
        oauth_module_server,
        args = list(
          id = "auth",
          client = client,
          auto_redirect = FALSE,
          refresh_proactively = proactive
        ),
        {
          session[["flushReact"]]()
          .accept_login_token(manager_test_token(), NULL)
          current <- values[["connection"]]()
          expect_identical(
            current[["access_token"]](
              target = target,
              min_valid_for = 0,
              force_refresh = TRUE
            ),
            "access-1"
          )
          session[["flushReact"]]()
          expect_identical(calls, 1L)
          # Successful short-lived responses still have pacing, preventing a
          # tight refresh loop while the replacement is usable.
          early <- tryCatch(
            current[["access_token"]](
              target = target,
              min_valid_for = 0,
              force_refresh = TRUE
            ),
            error = identity
          )
          expect_identical(
            early[["context"]][["reason"]],
            "refresh_unavailable"
          )
          expect_identical(calls, 1L)
          now <<- now + 11
          session[["elapse"]](11000)
          expect_identical(
            current[["access_token"]](target = target, min_valid_for = 0),
            "access-2"
          )
          expect_identical(calls, 2L)
        }
      )
    }
  }

  # Renew before expiry when the caller needs a lifetime buffer. A fixed
  # success cooldown must not block otherwise useful 70-second replacements.
  lifetime <- 70
  calls <- 0L
  shiny::testServer(
    oauth_module_server,
    args = list(id = "auth", client = client, auto_redirect = FALSE),
    {
      .accept_login_token(manager_test_token(), NULL)
      current <- values[["connection"]]()
      expect_identical(
        current[["access_token"]](target = "secondary"),
        "access-1"
      )
      now <<- now + 11
      expect_identical(
        current[["access_token"]](target = "secondary"),
        "access-2"
      )
      expect_identical(calls, 2L)
    }
  )
})

test_that("managed target pacing follows lifetime with stable and rotating credentials", {
  local_options(shinyOAuth.skip_browser_token = TRUE)
  now <- Sys.time()
  local_mocked_bindings(Sys.time = function() now, .package = "base")
  client <- make_test_client(scopes = c("read", "write", "contacts"))
  provider <- client@provider
  provider@token_target_mode <- "rfc8707"
  S7::props(client) <- list(
    provider = provider,
    redirect_uri = "https://app.example/callback",
    token_targets = list(
      primary = list(resource = "urn:primary", scopes = c("read", "write")),
      secondary = list(resource = "urn:secondary", scopes = "contacts")
    ),
    default_token_target = "primary"
  )
  calls <- 0L
  lifetime <- 10
  dispatch <- refresh_token_dispatch
  local_mocked_bindings(
    revoke_token = function(...) invisible(NULL),
    refresh_token_dispatch = function(oauth_client, token, async = FALSE, ...) {
      result <- dispatch(oauth_client, token, async = FALSE, ...)
      if (async) promises::promise_resolve(result) else result
    },
    req_with_retry = function(req, ...) {
      calls <<- calls + 1L
      httr2::response(
        req[["url"]],
        status = 200L,
        headers = list("content-type" = "application/json"),
        body = charToRaw(jsonlite::toJSON(
          list(
            access_token = paste0("access-", calls),
            refresh_token = if (rotating) {
              paste0("refresh-", calls)
            } else {
              "synthetic-refresh"
            },
            token_type = "Bearer",
            expires_in = lifetime,
            scope = utils::URLdecode(as.character(req[["body"]][["data"]][[
              "scope"
            ]]))
          ),
          auto_unbox = TRUE
        ))
      )
    }
  )
  for (rotating in c(FALSE, TRUE)) {
    for (target in c("primary", "secondary")) {
      for (async in c(FALSE, TRUE)) {
        for (proactive in c(FALSE, TRUE)) {
          calls <- 0L
          lifetime <- 10
          manager <- oauth_connections(list(a = client), "https://app.example")
          oauth_connections_ui(shiny::fluidPage("Pacing"), "auth", manager)
          shiny::testServer(
            oauth_connections_server,
            args = list(
              id = "auth",
              manager = manager,
              async = async,
              refresh_proactively = proactive
            ),
            session = manager_test_session(),
            {
              current <- connection(manager_test_accept(controller))
              session[["flushReact"]]()
              acquire <- function(min_valid_for = 0, force_refresh = FALSE) {
                result <- current[["access_token"]](
                  target = target,
                  min_valid_for = min_valid_for,
                  force_refresh = force_refresh,
                  async = async
                )
                if (!inherits(result, "promise")) {
                  return(result)
                }
                value <- NULL
                promises::then(
                  result,
                  function(result) value <<- result,
                  function(error) value <<- error
                )
                poll_for_async(function() !is.null(value), session)
                if (inherits(value, "error")) {
                  stop(value)
                }
                value
              }
              expect_identical(acquire(force_refresh = TRUE), "access-1")
              session[["flushReact"]]()
              early <- tryCatch(acquire(force_refresh = TRUE), error = identity)
              expect_identical(
                early[["context"]][["reason"]],
                "refresh_unavailable"
              )
              expect_identical(calls, 1L)
              now <<- now + 11
              session[["elapse"]](11000)
              expect_identical(acquire(), "access-2")
              expect_identical(calls, 2L)

              # A lifetime buffer must trigger renewal before access-token expiry.
              lifetime <<- 70
              now <<- now + 11
              expect_identical(acquire(min_valid_for = 60), "access-3")
              now <<- now + 11
              expect_identical(acquire(min_valid_for = 60), "access-4")
              expect_identical(calls, 4L)

              # Rotating the shared credential for another target must not
              # erase a still-active cooldown and permit an alternating loop.
              lifetime <<- 10
              expect_identical(acquire(force_refresh = TRUE), "access-5")
              other <- if (target == "primary") "secondary" else "primary"
              expect_identical(
                current[["access_token"]](
                  target = other,
                  min_valid_for = 0,
                  force_refresh = TRUE
                ),
                "access-6"
              )
              early <- tryCatch(acquire(force_refresh = TRUE), error = identity)
              expect_identical(
                early[["context"]][["reason"]],
                "refresh_unavailable"
              )
              expect_identical(calls, 6L)
            }
          )
        }
      }
    }
  }
})

test_that("managed target success pacing uses the configured refresh lead", {
  now <- Sys.time()
  local_mocked_bindings(Sys.time = function() now, .package = "base")
  client <- make_test_client(scopes = c("read", "write"))
  provider <- client@provider
  provider@token_target_mode <- "rfc8707"
  S7::props(client) <- list(
    provider = provider,
    redirect_uri = "https://app.example/callback",
    token_targets = list(
      primary = list(resource = "urn:primary", scopes = c("read", "write"))
    ),
    default_token_target = "primary"
  )
  manager <- oauth_connections(list(a = client), "https://app.example")
  oauth_connections_ui(shiny::fluidPage("Pacing"), "health", manager)
  calls <- 0L
  local_mocked_bindings(refresh_token_impl = function(...) {
    calls <<- calls + 1L
    token <- manager_test_token(refresh = "synthetic-refresh")
    token@expires_at <- as.numeric(now) + 10
    token
  })
  shiny::testServer(
    oauth_connections_server,
    args = list(
      id = "health",
      manager = manager,
      refresh_lead_seconds = 5
    ),
    session = manager_test_session(),
    {
      current <- connection(manager_test_accept(controller))
      for (i in 1:2) {
        expect_identical(
          current[["access_token"]](min_valid_for = 0, force_refresh = TRUE),
          "synthetic-access"
        )
      }
      expect_identical(calls, 2L)
    }
  )
})
