test_that("managed replacement supports complete scope budgets in external state", {
  local_options(
    shinyOAuth.skip_browser_token = TRUE,
    shinyOAuth.callback_max_state_bytes = 1048576,
    shinyOAuth.state_max_token_chars = 1048576,
    shinyOAuth.state_max_wrapper_bytes = 1048576,
    shinyOAuth.state_max_ct_b64_chars = 1048576,
    shinyOAuth.state_max_ct_bytes = 1048576
  )
  cases <- list(
    list(
      scopes = sprintf("permission.%03d.%s", 1:35, strrep("x", 40)),
      targets = 1L
    ),
    list(scopes = c(strrep("a", 4096), strrep("b", 4096)), targets = 1L),
    list(scopes = sprintf("%03d%s", 1:128, strrep("x", 61)), targets = 16L)
  )
  for (case in cases) {
    scopes <- case[["scopes"]]
    provider <- make_test_provider()
    provider@token_target_mode <- "rfc8707"
    client <- oauth_client(
      provider,
      "app",
      client_secret = "",
      redirect_uri = "https://app.example/callback",
      scopes = scopes,
      token_targets = stats::setNames(
        lapply(seq_len(case[["targets"]]), function(i) {
          list(resource = paste0("urn:api:", i), scopes = scopes)
        }),
        paste0("api", seq_len(case[["targets"]]))
      ),
      default_token_target = "api1"
    )
    memory <- cachem::cache_mem()
    client@state_store <- custom_cache(
      get = function(key, missing = NULL) {
        memory[["get"]](key, missing = missing)
      },
      set = function(key, value) memory[["set"]](key, value),
      remove = function(key) memory[["remove"]](key),
      info = function() list(max_age = 300),
      take = function(key, missing = NULL) {
        value <- memory[["get"]](key, missing = missing)
        memory[["remove"]](key)
        value
      }
    )
    calls <- 0L
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
              access_token = "replacement-access",
              refresh_token = "replacement-refresh",
              token_type = "Bearer",
              expires_in = 3600,
              scope = paste(scopes, collapse = " ")
            ),
            auto_unbox = TRUE
          ))
        )
      }
    )
    fixture <- ordinary_manager_fixture(client)
    shiny::testServer(
      oauth_connections_server,
      args = list(id = "health", manager = fixture[["manager"]]),
      session = manager_test_session(manager_test_cookie(fixture)),
      {
        token <- manager_test_token()
        token@granted_scopes <- scopes
        id <- manager_test_accept(controller, token = token)
        current <- connection(id)
        expect_true(current[["is_usable"]]())
        session[["getReturned"]]()[["reauthorize"]](id)
        modules[["a"]][["browser_token"]] <- "__SKIPPED__"
        url <- modules[["a"]][["build_auth_url"]]()
        expect_true(is_valid_string(url))
        expect_null(modules[["a"]][["error"]])
        state <- parse_query_param(url, "state")
        payload <- state_payload_decrypt_validate(client, state)
        record <- state_store_get(client, payload[["state"]])
        expect_gt(nchar(record[["transaction_context"]], type = "bytes"), 4096)
        hooks <- controller[["hooks"]]("a")
        context <- oauth_module_managed_context(
          hooks,
          client,
          state,
          "__SKIPPED__"
        )
        altered <- context[["data"]]
        altered[["requested_scopes"]] <- "injected-permission"
        expect_false(hooks[["validate"]](altered))
        fresh <- handle_callback_internal(
          client,
          "code",
          state,
          "__SKIPPED__",
          .transaction_context = context[["json"]]
        )
        hooks[["accept"]](fresh, context[["data"]], as.numeric(Sys.time()))
        expect_identical(calls, 1L)
        expect_false(current[["is_usable"]]())
        rows <- Filter(
          function(row) !is.null(row[["token"]]),
          controller[["records"]]()
        )
        expect_length(rows, 1L)
        expect_setequal(rows[[1L]][["token"]]@granted_scopes, scopes)
        expect_identical(
          rows[[1L]][["targets"]][["limits"]],
          token_target_limits(client)
        )
        expect_error(handle_callback_internal(
          client,
          "replay",
          state,
          "__SKIPPED__",
          .transaction_context = context[["json"]]
        ))
        expect_identical(calls, 1L)
      }
    )
  }
})

test_that("replacement context rejection leaves the current connection usable", {
  fixture <- manager_test_fixture()
  encode <- authorization_context_json
  local_mocked_bindings(authorization_context_json = function(context) {
    if (!is.null(context[["replaces_connection_id"]])) {
      err_config("synthetic context serialization failure")
    }
    encode(context)
  })
  shiny::testServer(
    oauth_connections_server,
    args = list(id = "health", manager = fixture[["manager"]]),
    session = manager_test_session(manager_test_cookie(fixture)),
    {
      id <- manager_test_accept(controller)
      current <- connection(id)
      expect_error(
        session[["getReturned"]]()[["reauthorize"]](id),
        "serialization failure"
      )
      expect_true(current[["is_usable"]]())
      expect_identical(current[["access_token"]](), "synthetic-access")
      expect_identical(
        controller[["hooks"]]("a")[["prepare"]]()[["replaces_connection_id"]],
        NULL
      )
    }
  )
})
