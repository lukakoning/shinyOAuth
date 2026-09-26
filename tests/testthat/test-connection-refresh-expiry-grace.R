test_that("on-demand refresh survives ordinary expiry only within its owned grace period", {
  local_options(shinyOAuth.skip_browser_token = TRUE)
  client <- make_test_client(use_nonce = FALSE, scopes = c("read", "write"))
  now <- Sys.time()
  local_mocked_bindings(Sys.time = function() now, .package = "base")
  resolve <- NULL
  revoked <- character()
  local_mocked_bindings(
    refresh_token = function(...) {
      promises::promise(function(resolve_, reject_) {
        resolve <<- resolve_
      })
    },
    revoke_token = function(client, token, token_kind, ...) {
      revoked <<- c(revoked, token_kind)
      invisible(NULL)
    }
  )
  for (scenario in c(
    "complete",
    "deadline",
    "logout",
    "reauth_age",
    "no_refresh"
  )) {
    resolve <- NULL
    revoked <- character()
    shiny::testServer(
      oauth_module_server,
      args = list(
        id = "auth",
        client = client,
        auto_redirect = FALSE,
        refresh_proactively = FALSE,
        refresh_lead_seconds = 1,
        reauth_after_seconds = if (scenario == "reauth_age") 2 else NULL
      ),
      {
        token <- manager_test_token()
        token@expires_at <- as.numeric(now) + 1
        .accept_login_token(token, NULL)
        session[["flushReact"]]()
        current <- values[["connection"]]()
        result <- NULL
        if (scenario != "no_refresh") {
          promises::then(
            current[["access_token"]](async = TRUE),
            function(x) result <<- x,
            function(x) result <<- x
          )
          expect_true(is.function(resolve))
        }
        elapsed <- if (scenario == "deadline") 7 else 2
        now <<- now + elapsed
        session[["elapse"]](elapsed * 1000)
        session[["flushReact"]]()
        if (scenario == "logout") {
          values[["logout"]]()
        }
        if (scenario == "complete") {
          expect_false(is.null(values[["token"]]))
          expect_true(values[["refresh_in_progress"]])
        } else {
          expect_null(values[["token"]])
        }
        if (scenario != "no_refresh") {
          fresh <- manager_test_token(access = "fresh")
          resolve(fresh)
          poll_for_async(function() !is.null(result), session)
          if (scenario == "complete") {
            expect_identical(result, "fresh")
            expect_identical(current[["access_token"]](), "fresh")
            expect_length(revoked, 0L)
          } else {
            expect_s3_class(result, "shinyOAuth_access_error")
            expect_identical(
              result[["context"]][["reason"]],
              if (scenario == "reauth_age") {
                "interaction_required"
              } else {
                "authorization_unavailable"
              }
            )
            expect_false(current[["is_usable"]]())
            expect_true(all(c("refresh", "access") %in% revoked))
          }
        }
      }
    )
  }
})
