test_that("cached async token snapshots cannot bypass documented SDK ownership guards", {
  local_options(shinyOAuth.skip_browser_token = TRUE)
  local_mocked_bindings(
    revoke_token = function(...) invisible(NULL),
    refresh_token_dispatch = function(client, token, scope_request, ...) {
      token@granted_scopes <- scope_request[["scopes"]]
      token@access_token <- "narrowed-access"
      token
    }
  )
  exercise <- function(current, factory, change, session, scenario) {
    pending <- current[["access_token"]](
      required_scopes = "write",
      async = TRUE
    )
    change()
    snapshot <- NULL
    finished <- FALSE
    sdk_calls <- character()
    promises::then(pending, function(token) {
      snapshot <<- token
      # Equivalent to the vignette's req(factory()), ID and scope checks.
      # A failed factory also stops the SDK call (e.g. an ended owner).
      latest <- tryCatch(factory(), error = function(...) NULL)
      if (
        !is.null(latest) &&
          identical(latest[["id"]], current[["id"]]) &&
          latest[["has_scopes"]]("write")
      ) {
        sdk_calls <<- c(sdk_calls, token)
      }
      finished <<- TRUE
    })
    poll_for_async(function() finished, session)
    expect_identical(snapshot, "synthetic-access")
    if (scenario == "unchanged") {
      expect_identical(sdk_calls, snapshot)
    } else {
      expect_length(sdk_calls, 0L)
      expect_false(current[["has_scopes"]]("write"))
    }
    if (scenario == "narrow") {
      expect_identical(factory()[["id"]], current[["id"]])
      expect_true(factory()[["has_scopes"]]("read"))
    }
    if (scenario == "replace") {
      expect_false(identical(factory()[["id"]], current[["id"]]))
      expect_true(factory()[["has_scopes"]]("write"))
    }
  }
  for (scenario in c("unchanged", "logout", "narrow", "replace")) {
    client <- make_test_client(use_nonce = FALSE, scopes = c("read", "write"))
    shiny::testServer(
      oauth_module_server,
      args = list(id = "auth", client = client, auto_redirect = FALSE),
      {
        .accept_login_token(manager_test_token(), NULL)
        current <- values[["connection"]]()
        exercise(
          current,
          values[["connection"]],
          function() {
            if (scenario %in% c("logout", "replace")) {
              values[["logout"]]()
            }
            if (scenario == "narrow") {
              expect_true(current[["refresh"]](scopes = "read"))
            }
            if (scenario == "replace") {
              .accept_login_token(
                manager_test_token(access = "new-login"),
                NULL
              )
            }
          },
          session,
          scenario
        )
      }
    )
    client@redirect_uri <- "https://app.example/callback"
    fixture <- ordinary_manager_fixture(client)
    shiny::testServer(
      oauth_connections_server,
      args = list(id = "health", manager = fixture[["manager"]]),
      session = manager_test_session(manager_test_cookie(fixture)),
      {
        stored_id <- manager_test_accept(controller)
        current <- connection(stored_id)
        exercise(
          current,
          connection,
          function() {
            if (scenario == "logout") {
              controller[["logout"]](revoke = FALSE)
            }
            if (scenario == "narrow") {
              expect_true(current[["refresh"]](scopes = "read"))
            }
            if (scenario == "replace") {
              controller[["disconnect"]](stored_id, revoke = FALSE)
              manager_test_accept(
                controller,
                token = manager_test_token(access = "new-login")
              )
            }
          },
          session,
          scenario
        )
      }
    )
  }
})
