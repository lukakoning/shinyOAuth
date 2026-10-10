test_that("failed target refresh preserves every old credential until opted-in cleanup", {
  local_options(shinyOAuth.skip_browser_token = TRUE)
  provider <- make_test_provider()
  S7::props(provider) <- list(
    token_target_mode = "rfc8707",
    revocation_url = "https://example.com/revoke"
  )
  client <- oauth_client(
    provider,
    "app",
    client_secret = "",
    redirect_uri = "https://app.example/callback",
    scopes = c("read", "write"),
    token_targets = list(
      first = list(resource = "urn:first", scopes = "read"),
      second = list(resource = "urn:second", scopes = "write")
    ),
    default_token_target = "first"
  )
  primary <- manager_test_token(
    access = "first-access",
    refresh = "shared-refresh"
  )
  primary@granted_scopes <- "read"
  child <- manager_test_token(
    access = "second-access",
    refresh = "shared-refresh"
  )
  child@granted_scopes <- "write"
  bundle <- token_target_bundle(client, primary)
  bundle[["tokens"]][["second"]] <- child
  revoked <- character()
  local_mocked_bindings(
    refresh_token_dispatch = function(...) {
      stop(refresh_outcome_error(
        simpleError("transport ended after provider consumed renewal"),
        "possibly_consumed"
      ))
    },
    revoke_token = function(client, token, token_kind, ...) {
      revoked <<- c(
        revoked,
        if (token_kind == "refresh") token@refresh_token else token@access_token
      )
    }
  )
  shiny::testServer(
    oauth_module_server,
    args = list(
      id = "auth",
      client = client,
      auto_redirect = FALSE,
      revoke_on_session_end = TRUE
    ),
    {
      .accept_login_token(primary, NULL)
      values[["targets"]] <- bundle
      expect_error(.refresh_current_token(), "transport ended")
      expect_null(values[["token"]])
      expect_null(values[["targets"]])
      expect_identical(
        revoked,
        c("shared-refresh", "first-access", "second-access")
      )
      session[["close"]]()
      expect_length(revoked, 3L)
    }
  )
})
