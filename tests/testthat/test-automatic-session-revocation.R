test_that("automatic clearing revokes opted-in credentials before session end", {
  local_options(shinyOAuth.skip_browser_token = TRUE)
  for (mode in c("expiry", "reauth")) {
    for (enabled in c(FALSE, TRUE)) {
      now <- as.numeric(Sys.time())
      local_mocked_bindings(
        Sys.time = function() as.POSIXct(now, origin = "1970-01-01"),
        .package = "base"
      )
      client <- make_test_client()
      client@provider@revocation_url <- "https://example.com/revoke"
      token <- OAuthToken(
        access_token = "access", refresh_token = "refresh",
        expires_at = now + 3600
      )
      calls <- character()
      local_mocked_bindings(
        handle_callback = function(...) token,
        revoke_token = function(client, token, token_kind, ...) {
          calls <<- c(calls, token_kind)
          # A failed refresh-token attempt must not suppress access cleanup.
          if (token_kind == "refresh") stop("synthetic revocation failure")
          invisible(NULL)
        },
        .package = "shinyOAuth"
      )
      shiny::testServer(
        oauth_module_server,
        args = list(
          id = "auth", client = client, auto_redirect = FALSE,
          refresh_proactively = FALSE, revoke_on_session_end = enabled,
          reauth_after_seconds = if (mode == "reauth") 60 else NULL
        ),
        {
          state <- parse_query_param(values[["build_auth_url"]](), "state")
          values[[".process_query"]](paste0("?code=code&state=", state))
          session[["flushReact"]]()
          expect_true(values[["authenticated"]])
          now <<- now + if (mode == "reauth") 61 else 3601
          values[["auth_started_at"]] <- values[["auth_started_at"]] + 0.01
          values[["token"]] <- NULL
          values[["token"]] <- token
          session[["flushReact"]]()
          expect_null(values[["token"]])
          expect_identical(
            values[["error"]],
            if (mode == "reauth") "reauth_required" else "token_expired"
          )
          expect_identical(calls, if (enabled) c("refresh", "access") else character())
        }
      )
      # Ending the already-cleared session must not submit duplicate cleanup.
      expect_length(calls, if (enabled) 2L else 0L)
    }
  }
})

test_that("automatic cleanup follows the module async setting and clears access first", {
  local_options(shinyOAuth.skip_browser_token = TRUE)
  local_mocked_bindings(async_backend_available = function() "mirai", .package = "shinyOAuth")
  client <- make_test_client()
  client@provider@revocation_url <- "https://example.com/revoke"
  now <- as.numeric(Sys.time())
  local_mocked_bindings(
    Sys.time = function() as.POSIXct(now, origin = "1970-01-01"),
    .package = "base"
  )
  token <- OAuthToken(access_token = "access", refresh_token = "refresh", expires_at = now + 60)
  calls <- list()
  local_mocked_bindings(module_revoke_targets = function(
    client, token, secondary, async, shiny_session, ...
  ) {
    calls[[length(calls) + 1L]] <<- list(token = token, async = async, context = shiny_session)
  }, .package = "shinyOAuth")
  shiny::testServer(
    oauth_module_server,
    args = list(
      id = "auth", client = client, auto_redirect = FALSE, async = TRUE,
      refresh_proactively = FALSE, revoke_on_session_end = TRUE
    ),
    {
      values[["token"]] <- token
      values[["auth_started_at"]] <- now
      session[["flushReact"]]()
      now <<- now + 61
      values[["auth_started_at"]] <- values[["auth_started_at"]] + 0.01
      values[["token"]] <- NULL
      values[["token"]] <- token
      session[["flushReact"]]()
      expect_null(values[["token"]])
      expect_length(calls, 1L)
      expect_identical(calls[[1]][["token"]], token)
      expect_true(calls[[1]][["async"]])
      expect_true(calls[[1]][["context"]][["is_async"]])
    }
  )
  expect_length(calls, 1L)
})

test_that("automatic maximum-age clearing retains secondary tokens for cleanup", {
  local_options(shinyOAuth.skip_browser_token = TRUE)
  now <- as.numeric(Sys.time())
  local_mocked_bindings(
    Sys.time = function() as.POSIXct(now, origin = "1970-01-01"),
    .package = "base"
  )
  client <- make_test_client(scopes = c("read", "write"))
  provider <- client@provider
  S7::props(provider) <- list(
    token_target_mode = "rfc8707", revocation_url = "https://example.com/revoke"
  )
  S7::props(client) <- list(
    provider = provider,
    token_targets = list(
      first = list(resource = "urn:first", scopes = "read"),
      second = list(resource = "urn:second", scopes = "write")
    ),
    default_token_target = "first"
  )
  token <- OAuthToken(
    access_token = "first-access", refresh_token = "shared-refresh",
    expires_at = now + 3600, granted_scopes = "read"
  )
  bundle <- token_target_bundle(client, token)
  child <- token
  child@access_token <- "second-access"
  child@refresh_token <- NA_character_
  child@granted_scopes <- "write"
  bundle[["tokens"]][["second"]] <- child
  calls <- character()
  local_mocked_bindings(revoke_token = function(client, token, token_kind, ...) {
    value <- if (token_kind == "refresh") token@refresh_token else token@access_token
    calls <<- c(calls, paste(token_kind, value))
  }, .package = "shinyOAuth")
  shiny::testServer(
    oauth_module_server,
    args = list(
      id = "auth", client = client, auto_redirect = FALSE,
      refresh_proactively = FALSE, reauth_after_seconds = 60,
      revoke_on_session_end = TRUE
    ),
    {
      values[["token"]] <- token
      values[["auth_started_at"]] <- now
      session[["flushReact"]]()
      values[["targets"]] <- bundle
      now <<- now + 61
      values[["auth_started_at"]] <- values[["auth_started_at"]] + 0.01
      session[["flushReact"]]()
      expect_null(values[["token"]])
      expect_null(values[["targets"]])
      expect_identical(calls, c(
        "refresh shared-refresh", "access first-access", "access second-access"
      ))
    }
  )
  expect_length(calls, 3L)
})
