independent_pacing_client <- function() {
  provider <- make_test_provider()
  provider@token_target_mode <- "rfc8707"
  oauth_client(
    provider,
    "app",
    client_secret = "",
    redirect_uri = "https://app.example/callback",
    scopes = c("read", "write", "contacts"),
    token_targets = list(
      primary = list(resource = "urn:primary", scopes = c("read", "write")),
      secondary = list(resource = "urn:secondary", scopes = "contacts")
    ),
    default_token_target = "primary"
  )
}

test_that("secondary acquisition cannot postpone primary proactive renewal", {
  now <- Sys.time()
  local_mocked_bindings(Sys.time = function() now, .package = "base")
  client <- independent_pacing_client()
  calls <- character()
  local_mocked_bindings(
    revoke_token = function(...) invisible(NULL),
    req_with_retry = function(req, ...) {
      data <- req[["body"]][["data"]]
      resource <- utils::URLdecode(as.character(data[["resource"]]))
      calls <<- c(calls, resource)
      httr2::response(
        req[["url"]],
        status = 200L,
        headers = list("content-type" = "application/json"),
        body = charToRaw(jsonlite::toJSON(
          list(
            access_token = paste0("access-", length(calls)),
            refresh_token = paste0("refresh-", length(calls)),
            token_type = "Bearer",
            expires_in = if (resource == "urn:primary") 3600 else 60,
            scope = utils::URLdecode(as.character(data[["scope"]]))
          ),
          auto_unbox = TRUE
        ))
      )
    }
  )
  shiny::testServer(
    oauth_module_server,
    args = list(
      id = "auth",
      client = client,
      auto_redirect = FALSE,
      refresh_proactively = TRUE,
      refresh_lead_seconds = 60
    ),
    {
      session[["flushReact"]]()
      token <- manager_test_token()
      token@expires_at <- as.numeric(now) + 10
      .accept_login_token(token, NULL)
      current <- values[["connection"]]()
      expect_identical(
        current[["access_token"]](target = "secondary", min_valid_for = 0),
        "access-1"
      )
      session[["flushReact"]]()
      expect_identical(calls, c("urn:secondary", "urn:primary"))
      expect_identical(current[["access_token"]](), "access-2")
      # Primary renewal must not erase the secondary target's cooldown.
      expect_error(
        current[["access_token"]](
          target = "secondary",
          min_valid_for = 0,
          force_refresh = TRUE
        ),
        class = "shinyOAuth_access_error"
      )
      now <<- now + 11
      session[["elapse"]](11000)
      session[["flushReact"]]()
      expect_identical(current[["summary"]]()[["status"]], "active")
      expect_identical(length(calls), 2L)
    }
  )
})

test_that("secondary success preserves primary cooldown and failure backoff", {
  now <- Sys.time()
  local_mocked_bindings(Sys.time = function() now, .package = "base")
  client <- independent_pacing_client()
  calls <- character()
  primary_calls <- 0L
  local_mocked_bindings(
    revoke_token = function(...) invisible(NULL),
    req_with_retry = function(req, ...) {
      data <- req[["body"]][["data"]]
      primary <- identical(
        utils::URLdecode(as.character(data[["resource"]])),
        "urn:primary"
      )
      calls <<- c(calls, if (primary) "primary" else "secondary")
      if (primary) {
        primary_calls <<- primary_calls + 1L
      }
      failed <- fail_primary && primary && primary_calls <= 2L
      httr2::response(
        req[["url"]],
        status = if (failed) 503L else 200L,
        headers = list("content-type" = "application/json"),
        body = charToRaw(jsonlite::toJSON(
          if (failed) {
            list(error = "temporarily_unavailable")
          } else {
            list(
              access_token = paste0("access-", length(calls)),
              refresh_token = paste0("refresh-", length(calls)),
              token_type = "Bearer",
              expires_in = if (primary) 10 else 3600,
              scope = utils::URLdecode(as.character(data[["scope"]]))
            )
          },
          auto_unbox = TRUE
        ))
      )
    }
  )
  for (fail_primary in c(FALSE, TRUE)) {
    calls <- character()
    primary_calls <- 0L
    shiny::testServer(
      oauth_module_server,
      args = list(
        id = "auth",
        client = client,
        auto_redirect = FALSE,
        refresh_proactively = TRUE,
        refresh_lead_seconds = 60
      ),
      {
        session[["flushReact"]]()
        token <- manager_test_token()
        token@expires_at <- as.numeric(now) + 10
        .accept_login_token(token, NULL)
        current <- values[["connection"]]()
        session[["flushReact"]]()
        expect_identical(primary_calls, 1L)
        current[["access_token"]](target = "secondary", min_valid_for = 0)
        session[["flushReact"]]()
        expect_identical(primary_calls, 1L)
        now <<- now + if (fail_primary) 1.5 else 6
        session[["elapse"]](if (fail_primary) 1500 else 6000)
        session[["flushReact"]]()
        expect_identical(primary_calls, 2L)
        if (fail_primary) {
          # Repeated primary failures retain exponential backoff even across
          # successful acquisitions with a rotating shared refresh credential.
          current[["access_token"]](target = "secondary", force_refresh = TRUE)
          now <<- now + 1.5
          session[["elapse"]](1500)
          session[["flushReact"]]()
          expect_identical(primary_calls, 2L)
          now <<- now + 1
          session[["elapse"]](1000)
          session[["flushReact"]]()
          expect_identical(primary_calls, 3L)
        }
        expect_identical(current[["summary"]]()[["status"]], "active")
        expect_identical(
          current[["access_token"]](min_valid_for = 0),
          paste0("access-", length(calls))
        )
      }
    )
  }
})
