test_that("replacement state limits are checked before ending either authorization", {
  local_options(shinyOAuth.skip_browser_token = TRUE)
  limits <- c(
    "shinyOAuth.callback_max_state_bytes",
    "shinyOAuth.state_max_token_chars",
    "shinyOAuth.state_max_wrapper_bytes",
    "shinyOAuth.state_max_ct_b64_chars",
    "shinyOAuth.state_max_ct_bytes"
  )
  provider_calls <- 0L
  local_mocked_bindings(
    build_prepared_authorization = function(...) {
      provider_calls <<- provider_calls + 1L
      stop("Preflight must not build or publish an authorization request")
    },
    revoke_token = function(...) {
      stop("Preflight must not revoke credentials")
    }
  )
  for (managed in c(FALSE, TRUE)) {
    for (budget in c("defaults", limits)) {
      options <- stats::setNames(as.list(rep(65536, length(limits))), limits)
      if (budget == "defaults") {
        options[] <- list(8192)
      } else {
        options[[budget]] <- 4096
      }
      withr::local_options(options)
      scopes <- sprintf("api.permission.%02d", 1:50)
      provider <- make_test_provider()
      provider@token_target_mode <- "rfc8707"
      client <- oauth_client(
        provider,
        "app",
        client_secret = "",
        redirect_uri = "https://app.example/callback",
        scopes = scopes,
        token_targets = stats::setNames(
          lapply(1:3, function(i) {
            list(resource = paste0("urn:api:", i), scopes = scopes)
          }),
          c("a", "b", "c")
        ),
        default_token_target = "a"
      )
      # Initial login fits these same limits; only replacement carries the
      # configured scopes and per-target limits that exceed the selected cap.
      prepared <- prepare_call_internal(
        client,
        valid_browser_token(),
        .defer_build = TRUE
      )
      expect_type(prepared, "list")
      keys <- client@state_store[["keys"]]()
      f <- ordinary_manager_fixture(client)
      token <- manager_test_token()
      token@granted_scopes <- scopes
      shiny::testServer(
        if (managed) oauth_connections_server else oauth_module_server,
        args = if (managed) {
          list(id = "health", manager = f[["manager"]])
        } else {
          list(id = "auth", client = client, auto_redirect = FALSE)
        },
        session = manager_test_session(
          if (managed) manager_test_cookie(f) else NULL
        ),
        {
          session[["flushReact"]]()
          if (managed) {
            id <- manager_test_accept(controller, token = token)
            current <- connection(id)
          } else {
            .accept_login_token(token, NULL)
            current <- values[["connection"]]()
            before <- as.list(auth_operations)
          }
          expect_error(
            if (managed) {
              session[["getReturned"]]()[["reauthorize"]](id)
            } else {
              values[["reauthorize"]]()
            },
            class = "shinyOAuth_error"
          )
          expect_true(current[["is_usable"]]())
          expect_identical(current[["access_token"]](), "synthetic-access")
          expect_setequal(client@state_store[["keys"]](), keys)
          if (managed) {
            expect_null(controller[["hooks"]]("a")[["prepare"]]()[[
              "replaces_connection_id"
            ]])
          } else {
            expect_identical(as.list(auth_operations), before)
            expect_identical(values[["connection"]](), current)
            expect_null(values[["error"]])
          }
        }
      )
    }
  }
  expect_identical(provider_calls, 0L)
})

test_that("successful preflight does not persist a login or contact the provider", {
  client <- make_test_client(use_nonce = FALSE, scopes = "read")
  provider <- client@provider
  provider@par_url <- "https://example.com/par"
  client@provider <- provider
  local_mocked_bindings(build_prepared_authorization = function(...) {
    stop("Preflight must not send PAR or publish a Request Object")
  })
  keys <- client@state_store[["keys"]]()
  expect_null(preflight_reauthorization(client, scopes = client@scopes))
  expect_setequal(client@state_store[["keys"]](), keys)
})
