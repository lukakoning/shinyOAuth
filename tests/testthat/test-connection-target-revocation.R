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
