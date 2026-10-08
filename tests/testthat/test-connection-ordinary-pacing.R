test_that("ordinary managed refresh pacing follows token lifetime after success", {
  now <- Sys.time()
  local_mocked_bindings(Sys.time = function() now, .package = "base")
  calls <- 0L
  lifetime <- 10
  refresh <- refresh_token
  local_mocked_bindings(
    revoke_token = function(...) invisible(NULL),
    refresh_token = function(oauth_client, token, async = FALSE, ...) {
      result <- refresh(oauth_client, token, async = FALSE, ...)
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
            scope = "read write"
          ),
          auto_unbox = TRUE
        ))
      )
    }
  )
  for (rotating in c(FALSE, TRUE)) {
    for (async in c(FALSE, TRUE)) {
      for (proactive in c(FALSE, TRUE)) {
        calls <- 0L
        lifetime <- 10
        fixture <- manager_test_fixture()
        shiny::testServer(
          oauth_connections_server,
          args = list(
            id = "health",
            manager = fixture[["manager"]],
            async = async,
            refresh_proactively = proactive
          ),
          session = manager_test_session(manager_test_cookie(fixture)),
          {
            current <- connection(manager_test_accept(controller))
            session[["flushReact"]]()
            acquire <- function(min_valid_for = 0, force_refresh = FALSE) {
              result <- current[["access_token"]](
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
                function(result) {
                  value <<- result
                },
                function(error) {
                  value <<- error
                }
              )
              poll_for_async(function() !is.null(value), session)
              if (inherits(value, "error")) {
                stop(value)
              }
              value
            }
            expect_identical(acquire(force_refresh = TRUE), "access-1")
            session[["flushReact"]]()
            # Stable and rotated credentials both resist tight refresh loops.
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

            # Refresh before expiry to satisfy the default lifetime buffer.
            lifetime <<- 70
            now <<- now + 11
            expect_identical(acquire(min_valid_for = 60), "access-3")
            now <<- now + 11
            expect_identical(acquire(min_valid_for = 60), "access-4")
            expect_identical(calls, 4L)
          }
        )
      }
    }
  }
})

test_that("ordinary managed success pacing respects the configured refresh lead", {
  now <- Sys.time()
  local_mocked_bindings(Sys.time = function() now, .package = "base")
  fixture <- manager_test_fixture()
  calls <- 0L
  local_mocked_bindings(refresh_token_impl = function(...) {
    calls <<- calls + 1L
    token <- manager_test_token()
    token@expires_at <- as.numeric(now) + 10
    token
  })
  shiny::testServer(
    oauth_connections_server,
    args = list(
      id = "health",
      manager = fixture[["manager"]],
      refresh_lead_seconds = 5
    ),
    session = manager_test_session(manager_test_cookie(fixture)),
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
