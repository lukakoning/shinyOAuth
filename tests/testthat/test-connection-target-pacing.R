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
