revocation_target_fixture <- function() {
  scopes <- paste0("s", seq_len(16L))
  client <- make_test_client(use_nonce = FALSE, scopes = scopes)
  provider <- client@provider
  S7::props(provider) <- list(
    token_target_mode = "rfc8707",
    revocation_url = "https://example.com/revoke"
  )
  targets <- stats::setNames(
    lapply(seq_len(16L), function(i) {
      list(resource = paste0("urn:", i), scopes = scopes[[i]])
    }),
    paste0("t", seq_len(16L))
  )
  S7::props(client) <- list(
    provider = provider,
    token_targets = targets,
    default_token_target = "t1"
  )
  token <- OAuthToken(
    access_token = "primary",
    refresh_token = "shared",
    token_type = "Bearer",
    expires_at = as.numeric(Sys.time()) + 3600,
    granted_scopes = scopes[[1L]],
    granted_scopes_verified = TRUE
  )
  bundle <- token_target_bundle(client, token)
  for (i in 2:16) {
    child <- token
    child@access_token <- paste0("access-", i)
    child@refresh_token <- NA_character_
    child@granted_scopes <- scopes[[i]]
    bundle[["tokens"]][[paste0("t", i)]] <- child
  }
  list(client = client, token = token, bundle = bundle)
}

test_that("logout and session end clear access before one bounded revocation batch", {
  local_options(
    shinyOAuth.skip_browser_token = TRUE,
    shinyOAuth.timeout = 30,
    shinyOAuth.retry_max_tries = 100L
  )
  for (async in c(FALSE, TRUE)) {
    for (ending in c(FALSE, TRUE)) {
      f <- revocation_target_fixture()
      attempts <- list()
      dispatches <- 0L
      active_values <- NULL
      old_connection <- NULL
      local_mocked_bindings(
        async_dispatch = function(expr, args, ...) {
          dispatches <<- dispatches + 1L
          promises::promise_resolve(eval(
            expr,
            list2env(args, parent = baseenv())
          ))
        },
        req_perform_bounded = function(req, ...) {
          attempts[[length(attempts) + 1L]] <<- list(
            timeout = req[["options"]][["timeout_ms"]],
            has_token = shiny::isolate(!is.null(active_values[["token"]])),
            has_targets = shiny::isolate(
              length(active_values[["targets"]][["tokens"]]) > 0L
            ),
            hint = req[["body"]][["data"]][["token_type_hint"]]
          )
          expect_error(
            shiny::isolate(old_connection[["access_token"]]()),
            class = "shinyOAuth_access_error"
          )
          httr2::response(
            req[["url"]],
            status = 503L,
            headers = list("Retry-After" = "60"),
            body = raw()
          )
        }
      )
      shiny::testServer(
        oauth_module_server,
        args = list(
          id = "auth",
          client = f[["client"]],
          auto_redirect = FALSE,
          async = async,
          revoke_on_session_end = ending
        ),
        {
          session[["flushReact"]]()
          .accept_login_token(f[["token"]], NULL)
          values[["targets"]] <- f[["bundle"]]
          active_values <<- values
          old_connection <<- values[["connection"]]()
          if (ending) {
            session[["close"]]()
          } else {
            values[["logout"]]()
          }
          expect_null(values[["token"]])
        }
      )
      expect_length(attempts, 17L)
      expect_identical(dispatches, if (async) 1L else 0L)
      expect_identical(as.character(attempts[[1L]][["hint"]]), "refresh_token")
      expect_true(all(vapply(
        attempts,
        function(x) x[["timeout"]] <= 2000,
        logical(1)
      )))
      expect_false(any(vapply(
        attempts,
        function(x) x[["has_token"]] || x[["has_targets"]],
        logical(1)
      )))
      expect_identical(getOption("shinyOAuth.timeout"), 30)
      expect_identical(getOption("shinyOAuth.retry_max_tries"), 100L)
    }
  }
})

test_that("the cleanup deadline stops remaining targets and expired queued batches", {
  f <- revocation_target_fixture()
  now <- Sys.time()
  local_mocked_bindings(Sys.time = function() now, .package = "base")
  calls <- 0L
  local_mocked_bindings(req_perform_bounded = function(req, ...) {
    calls <<- calls + 1L
    now <<- now + req[["options"]][["timeout_ms"]] / 1000
    httr2::response(req[["url"]], status = 503L, headers = list(), body = raw())
  })
  module_revoke_targets(f[["client"]], f[["token"]], f[["bundle"]][["tokens"]])
  expect_identical(calls, 5L)
  queued <- NULL
  local_mocked_bindings(async_dispatch = function(expr, args, ...) {
    queued <<- list(expr = expr, args = args)
    promises::promise_resolve(NULL)
  })
  module_revoke_targets(
    f[["client"]],
    f[["token"]],
    f[["bundle"]][["tokens"]],
    async = TRUE
  )
  now <- now + 11
  eval(queued[["expr"]], list2env(queued[["args"]], parent = baseenv()))
  expect_identical(calls, 5L)
  module_revoke_targets(
    f[["client"]],
    f[["token"]],
    f[["bundle"]][["tokens"]],
    deadline = as.numeric(now) + 0.0005
  )
  expect_identical(calls, 5L)
})

test_that("duplicate module credentials leave time for distinct target tokens", {
  for (fails in c(FALSE, TRUE)) {
    f <- revocation_target_fixture()
    token <- f[["token"]]
    token@access_token <- token@refresh_token
    secondary <- f[["bundle"]][["tokens"]]
    for (target in names(secondary)) {
      secondary[[target]]@access_token <- if (target == "t16") {
        "distinct"
      } else {
        token@access_token
      }
    }
    now <- Sys.time()
    attempted <- character()
    local_mocked_bindings(Sys.time = function() now, .package = "base")
    local_mocked_bindings(revoke_token = function(
      client,
      token,
      token_kind,
      ...
    ) {
      value <- if (token_kind == "refresh") {
        token@refresh_token
      } else {
        token@access_token
      }
      attempted <<- c(attempted, paste(token_kind, value))
      now <<- now + 2
      if (fails) {
        stop("remote failure")
      }
      list(revoked = TRUE)
    })
    module_revoke_targets(f[["client"]], token, secondary)
    expect_identical(
      attempted,
      c("refresh shared", "access shared", "access distinct")
    )
  }
})

test_that("manager batches reuse duplicate outcomes across targets and records", {
  for (fails in c(FALSE, TRUE)) {
    f <- revocation_target_fixture()
    token <- f[["token"]]
    token@access_token <- token@refresh_token
    f[["client"]]@redirect_uri <- "https://app.example/callback"
    manager <- ordinary_manager_fixture(f[["client"]])
    now <- Sys.time()
    attempted <- character()
    events <- list()
    local_options(shinyOAuth.audit_hook = function(event) {
      events[[length(events) + 1L]] <<- event
    })
    local_mocked_bindings(Sys.time = function() now, .package = "base")
    local_mocked_bindings(
      refresh_token_dispatch = function(client, token, target_request, ...) {
        token@access_token <- if (
          identical(target_request[["scopes"]], "s16")
        ) {
          "distinct"
        } else {
          "shared"
        }
        token@granted_scopes <- target_request[["scopes"]]
        token
      },
      revoke_token = function(client, token, token_kind, ...) {
        value <- if (token_kind == "refresh") {
          token@refresh_token
        } else {
          token@access_token
        }
        attempted <<- c(attempted, paste(token_kind, value))
        # Finish the budget on the last unique credential. Later aliases must
        # retain their original outcomes, including failed attempts.
        now <<- now + if (value == "distinct") 6 else 2
        if (fails) {
          stop("remote failure")
        }
        list(revoked = TRUE)
      }
    )
    shiny::testServer(
      oauth_connections_server,
      args = list(id = "health", manager = manager[["manager"]]),
      session = manager_test_session(manager_test_cookie(manager)),
      {
        for (i in 1:2) {
          current <- connection(manager_test_accept(controller, token = token))
          for (target in paste0("t", 2:16)) {
            current[["refresh"]](target = target)
          }
        }
        events <<- list()
        results <- session[["getReturned"]]()[["disconnect_all"]]()
        expect_length(results, 2L)
        outcome <- if (fails) "failed" else "accepted"
        for (result in results) {
          expect_identical(result[["local"]], "disconnected")
          expect_identical(
            result[["remote"]],
            list(refresh = outcome, access = outcome)
          )
        }
        removed <- Filter(
          function(event) {
            event[["type"]] == "audit_connection_disconnected"
          },
          events
        )
        expect_length(removed, 2L)
        for (event in removed) {
          expect_identical(event[["remote_access_outcome"]], outcome)
          expect_identical(event[["remote_refresh_outcome"]], outcome)
        }
        expect_false(current[["is_usable"]]())
      }
    )
    expect_identical(
      attempted,
      c("refresh shared", "access shared", "access distinct")
    )
  }
})

test_that("batch revocation keeps identical values in different clients separate", {
  f <- manager_test_fixture()
  attempted <- character()
  local_mocked_bindings(revoke_token = function(
    client,
    token,
    token_kind,
    ...
  ) {
    attempted <<- c(attempted, paste(client@client_id, token_kind))
    list(revoked = TRUE)
  })
  shiny::testServer(
    oauth_connections_server,
    args = list(id = "health", manager = f[["manager"]]),
    session = manager_test_session(manager_test_cookie(f)),
    {
      manager_test_accept(controller, "a")
      manager_test_accept(controller, "b")
      results <- session[["getReturned"]]()[["disconnect_all"]]()
      expect_length(results, 2L)
      expect_setequal(
        attempted,
        c(
          "client-a refresh",
          "client-a access",
          "client-b refresh",
          "client-b access"
        )
      )
    }
  )
})

test_that("a real cleanup worker applies one attempt per credential", {
  skip_if_not_installed("webfakes")
  skip_if_not_installed("mirai")
  mirai::daemons(1)
  withr::defer(mirai::daemons(0))
  assert_shinyoauth_available_in_daemon()
  local_options(shinyOAuth.retry_max_tries = 100L)
  app <- webfakes::new_app()
  app[["locals"]][["calls"]] <- 0L
  app[["post"]]("/revoke", function(req, res) {
    req[["app"]][["locals"]][["calls"]] <- req[["app"]][["locals"]][["calls"]] +
      1L
    res[["set_status"]](503L)
    res[["set_header"]]("Retry-After", "60")
    res[["send"]]("")
  })
  app[["get"]]("/calls", function(req, res) {
    res[["send_json"]](
      list(calls = req[["app"]][["locals"]][["calls"]]),
      auto_unbox = TRUE
    )
  })
  server <- webfakes::local_app_process(app)
  f <- revocation_target_fixture()
  client <- f[["client"]]
  client@provider@revocation_url <- server[["url"]]("/revoke")
  done <- FALSE
  pending <- module_revoke_targets(
    client,
    f[["token"]],
    f[["bundle"]][["tokens"]],
    async = TRUE
  )
  promises::then(pending, function(...) done <<- TRUE)
  poll_for_async(function() done, timeout = 30)
  expect_true(done)
  metrics <- httr2::resp_body_json(httr2::req_perform(httr2::request(server[[
    "url"
  ]]("/calls"))))
  expect_identical(metrics[["calls"]], 17L)
})
