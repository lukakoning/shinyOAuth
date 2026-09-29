default_scope_reauthorization_fixture <- function(oidc) {
  f <- if (oidc) ordinary_oidc_fixture() else NULL
  client <- if (oidc) {
    f[["client"]]
  } else {
    make_test_client(use_nonce = FALSE, scopes = character())
  }
  client@redirect_uri <- "https://app.example/callback"
  if (oidc) {
    client@scopes <- "openid"
  }
  state <- new.env(parent = emptyenv())
  state[["scopes"]] <- "provider.default"
  state[["fail"]] <- FALSE
  state[["requests"]] <- list()
  list(
    client = client,
    state = state,
    jwk = f[["jwk"]],
    authorize = function(url) {
      if (oidc) {
        f[["authorize"]](url)
      }
      invisible(url)
    },
    request = function(req, ...) {
      if (state[["fail"]]) {
        stop("synthetic refresh interruption")
      }
      state[["requests"]][[length(state[["requests"]]) + 1L]] <- req[[
        "body"
      ]][["data"]]
      response <- if (oidc) {
        jsonlite::fromJSON(rawToChar(f[["request"]](req)[["body"]]))
      } else {
        list(token_type = "Bearer", expires_in = 3600)
      }
      response[["access_token"]] <- paste0(
        "default-access-",
        length(state[["requests"]])
      )
      response[["refresh_token"]] <- paste0(
        "default-refresh-",
        length(state[["requests"]])
      )
      response[["scope"]] <- paste(state[["scopes"]], collapse = " ")
      httr2::response(
        req[["url"]],
        status = 200L,
        headers = list("content-type" = "application/json"),
        body = charToRaw(jsonlite::toJSON(response, auto_unbox = TRUE))
      )
    }
  )
}

test_that("provider-default replacement survives failed callbacks in new sessions", {
  local_options(shinyOAuth.skip_browser_token = FALSE)
  for (oidc in c(FALSE, TRUE)) {
    for (async in c(FALSE, TRUE)) {
      f <- default_scope_reauthorization_fixture(oidc)
      client <- f[["client"]]
      local_mocked_bindings(
        fetch_jwks = function(...) list(keys = list(f[["jwk"]])),
        req_with_retry = f[["request"]],
        revoke_token = function(...) invisible(NULL),
        async_dispatch = function(expr, args, ...) {
          promises::promise_resolve(eval(
            expr,
            list2env(args, parent = globalenv())
          ))
        }
      )
      browser <- valid_browser_token()
      initial <- f[["authorize"]](prepare_call(client, browser))
      token <- handle_callback(
        client,
        "initial",
        parse_query_param(initial, "state"),
        browser
      )
      expect_identical(token@granted_scopes, "provider.default")
      if (oidc) {
        expect_true(token@id_token_validated)
      }
      replacement <- NULL
      shiny::testServer(
        oauth_module_server,
        args = list(id = "auth", client = client, auto_redirect = FALSE),
        {
          session[["flushReact"]]()
          .accept_login_token(token, NULL)
          previous <- values[["connection"]]()
          expect_true(previous[["is_usable"]]())
          values[["reauthorize"]]()
          expect_false(previous[["is_usable"]]())
          values[["browser_token"]] <- browser
          replacement <<- .build_auth_url()
        }
      )
      f[["state"]][["scopes"]] <- c("provider.default", "new.admin")
      shiny::testServer(
        oauth_module_server,
        args = list(
          id = "auth",
          client = client,
          auto_redirect = FALSE,
          async = async
        ),
        {
          session[["flushReact"]]()
          callback <- function(url) {
            f[["authorize"]](url)
            values[["browser_token"]] <- browser
            state <- parse_query_param(url, "state")
            payload <- state_payload_decrypt_validate(client, state)
            expect_setequal(
              as_scope_tokens(payload[["scopes"]]),
              if (oidc) "openid" else character()
            )
            expect_identical(
              connection_data_decode(payload[["accepted_extra_scopes"]]),
              "provider.default"
            )
            values[[".process_query"]](paste0("?code=next&state=", state))
            poll_for_async(
              function() is.null(auth_operations[["active_login_id"]]),
              session
            )
          }
          callback(replacement)
          expect_null(values[["token"]])
          expect_false(is.null(values[["error"]]))
          expect_identical(
            auth_operations[["reauth_extra_scopes"]],
            "provider.default"
          )
          values[["reauthorize"]]()
          values[["browser_token"]] <- browser
          f[["state"]][["scopes"]] <- "provider.default"
          callback(.build_auth_url())
          expect_null(values[["error"]])
          expect_identical(values[["token"]]@granted_scopes, "provider.default")
          if (oidc) {
            expect_true(values[["token"]]@id_token_validated)
          }
          current <- values[["connection"]]()
          expect_true(current[["is_usable"]]())
          expect_false(current[["has_scopes"]]("provider.default"))
          expect_true(auth_operations[["refresh_scope_narrowed"]])
          count <- length(f[["state"]][["requests"]])
          expect_error(current[["refresh"]](scopes = character()), "non-empty")
          expect_length(f[["state"]][["requests"]], count)
          expect_true(.refresh_current_token())
          f[["state"]][["scopes"]] <- c("provider.default", "new.admin")
          expect_error(.refresh_current_token(), "exceeds")
          expect_null(values[["token"]])
        }
      )
      expect_true(all(vapply(
        f[["state"]][["requests"]],
        function(request) {
          !"provider.default" %in% normalize_scope_tokens(request[["scope"]])
        },
        logical(1)
      )))
    }
  }
})

test_that("managed provider-default replacement retains evidence after restoration", {
  local_options(shinyOAuth.skip_browser_token = FALSE)
  for (oidc in c(FALSE, TRUE)) {
    for (uncertain in c(FALSE, TRUE)) {
      f <- default_scope_reauthorization_fixture(oidc)
      client <- f[["client"]]
      local_mocked_bindings(
        fetch_jwks = function(...) list(keys = list(f[["jwk"]])),
        req_with_retry = f[["request"]],
        revoke_token = function(...) invisible(NULL)
      )
      browser <- valid_browser_token()
      initial <- f[["authorize"]](prepare_call(client, browser))
      token <- handle_callback(
        client,
        "initial",
        parse_query_param(initial, "state"),
        browser
      )
      fixture <- ordinary_manager_fixture(client)
      cookie <- manager_test_cookie(fixture)
      connection_id <- NULL
      shiny::testServer(
        oauth_connections_server,
        args = list(id = "health", manager = fixture[["manager"]]),
        session = manager_test_session(cookie),
        {
          connection_id <<- manager_test_accept(controller, token = token)
        }
      )
      metadata <- fixture[["manager"]][["state"]][["authorization_metadata"]]
      rm(list = ls(metadata), envir = metadata)
      shiny::testServer(
        oauth_connections_server,
        args = list(id = "health", manager = fixture[["manager"]]),
        session = manager_test_session(cookie),
        {
          previous <- connection(connection_id)
          expect_true(previous[["is_usable"]]())
          if (uncertain) {
            f[["state"]][["fail"]] <- TRUE
            expect_error(previous[["refresh"]]())
            f[["state"]][["fail"]] <- FALSE
            expect_identical(previous[["summary"]]()[["status"]], "uncertain")
          }
          expect_identical(controller[["reauthorize"]](connection_id), "a")
          expect_false(previous[["is_usable"]]())
          hooks <- controller[["hooks"]]("a")
          context <- hooks[["prepare"]]()
          expect_identical(
            context[["requested_scopes"]],
            if (oidc) "openid" else NULL
          )
          expect_identical(
            context[["accepted_extra_scopes"]],
            "provider.default"
          )
          forged <- context
          forged[["accepted_extra_scopes"]] <- "new.admin"
          expect_false(hooks[["validate"]](forged))
          forged_token <- token
          forged_token@granted_scopes <- c("provider.default", "new.admin")
          expect_error(
            hooks[["accept"]](forged_token, context, as.numeric(Sys.time())),
            "exceeds"
          )
          url <- f[["authorize"]](prepare_call_internal(
            client,
            browser,
            .transaction_context = context,
            .requested_scopes = context[["requested_scopes"]],
            .accepted_extra_scopes = context[["accepted_extra_scopes"]]
          ))
          state <- parse_query_param(url, "state")
          restored <- oauth_module_managed_context(
            hooks,
            client,
            state,
            browser
          )
          fresh <- handle_callback_internal(
            client,
            "replacement",
            state,
            browser,
            .transaction_context = restored[["json"]]
          )
          hooks[["accept"]](fresh, restored[["data"]], as.numeric(Sys.time()))
          row <- Filter(
            function(row) {
              identical(row[["replaces_connection_id"]], connection_id)
            },
            controller[["records"]]()
          )[[1L]]
          expect_true(row[["refresh_scope_narrowed"]])
          current <- connection(row[["stored"]][["id"]])
          expect_true(current[["is_usable"]]())
          expect_false(current[["has_scopes"]]("provider.default"))
          if (oidc) {
            expect_true(row[["token"]]@id_token_validated)
          }
          count <- length(f[["state"]][["requests"]])
          expect_error(current[["refresh"]](scopes = character()), "non-empty")
          expect_length(f[["state"]][["requests"]], count)
          expect_true(current[["refresh"]]())
          f[["state"]][["scopes"]] <- c("provider.default", "new.admin")
          expect_error(current[["refresh"]]())
          expect_false(current[["is_usable"]]())
          expect_true(all(vapply(
            f[["state"]][["requests"]],
            function(request) {
              !"provider.default" %in%
                normalize_scope_tokens(request[["scope"]])
            },
            logical(1)
          )))
        }
      )
    }
  }
})

test_that("an empty replacement grant does not restore provider-default permissions", {
  local_options(shinyOAuth.skip_browser_token = FALSE)
  f <- default_scope_reauthorization_fixture(FALSE)
  client <- f[["client"]]
  local_mocked_bindings(
    req_with_retry = f[["request"]],
    revoke_token = function(...) invisible(NULL)
  )
  browser <- valid_browser_token()
  initial <- prepare_call(client, browser)
  token <- handle_callback(
    client,
    "initial",
    parse_query_param(initial, "state"),
    browser
  )
  shiny::testServer(
    oauth_module_server,
    args = list(id = "auth", client = client, auto_redirect = FALSE),
    {
      session[["flushReact"]]()
      .accept_login_token(token, NULL)
      values[["reauthorize"]]()
      values[["browser_token"]] <- browser
      url <- .build_auth_url()
      f[["state"]][["scopes"]] <- character()
      values[[".process_query"]](paste0(
        "?code=replacement&state=",
        parse_query_param(url, "state")
      ))
      expect_null(values[["error"]])
      expect_length(values[["token"]]@granted_scopes, 0L)
      expect_true(.refresh_current_token())
      expect_length(values[["token"]]@granted_scopes, 0L)
      values[["reauthorize"]]()
      values[["browser_token"]] <- browser
      url <- .build_auth_url()
      f[["state"]][["scopes"]] <- "provider.default"
      values[[".process_query"]](paste0(
        "?code=too-broad&state=",
        parse_query_param(url, "state")
      ))
      expect_null(values[["token"]])
      expect_false(is.null(values[["error"]]))
      values[["reauthorize"]]()
      values[["browser_token"]] <- browser
      url <- .build_auth_url()
      f[["state"]][["scopes"]] <- character()
      values[[".process_query"]](paste0(
        "?code=empty-retry&state=",
        parse_query_param(url, "state")
      ))
      expect_null(values[["error"]])
      expect_length(values[["token"]]@granted_scopes, 0L)
      expect_true(auth_operations[["refresh_scope_narrowed"]])
      f[["state"]][["scopes"]] <- "provider.default"
      expect_error(.refresh_current_token(), "exceeds")
      expect_null(values[["token"]])
      values[["reauthorize"]]()
      values[["browser_token"]] <- browser
      url <- .build_auth_url()
      values[[".process_query"]](paste0(
        "?code=after-failed-refresh&state=",
        parse_query_param(url, "state")
      ))
      expect_null(values[["token"]])
      expect_false(is.null(values[["error"]]))
      expect_true(all(vapply(
        tail(f[["state"]][["requests"]], 3L),
        function(req) {
          is.null(req[["scope"]])
        },
        logical(1)
      )))
    }
  )
})

test_that("managed empty evidence limits survive restoration and uncertain refresh", {
  local_options(shinyOAuth.skip_browser_token = FALSE)
  for (uncertain in c(FALSE, TRUE)) {
    client <- make_test_client(use_nonce = FALSE, scopes = character())
    client@redirect_uri <- "https://app.example/callback"
    fixture <- ordinary_manager_fixture(client)
    cookie <- manager_test_cookie(fixture)
    token <- manager_test_token()
    token@granted_scopes <- "provider.default"
    connection_id <- NULL
    local_mocked_bindings(revoke_token = function(...) invisible(NULL))
    shiny::testServer(
      oauth_connections_server,
      args = list(id = "health", manager = fixture[["manager"]]),
      session = manager_test_session(cookie),
      {
        initial <- manager_test_accept(controller, token = token)
        controller[["reauthorize"]](initial)
        hooks <- controller[["hooks"]]("a")
        context <- hooks[["prepare"]]()
        empty <- token
        empty@granted_scopes <- character()
        empty@access_token <- "empty-replacement"
        empty@refresh_token <- "empty-refresh"
        hooks[["accept"]](empty, context, as.numeric(Sys.time()))
        row <- Filter(
          function(row) identical(row[["replaces_connection_id"]], initial),
          controller[["records"]]()
        )[[1L]]
        connection_id <<- row[["stored"]][["id"]]
      }
    )
    metadata <- fixture[["manager"]][["state"]][["authorization_metadata"]]
    rm(list = ls(metadata), envir = metadata)
    local_mocked_bindings(req_with_retry = function(...) {
      stop("synthetic refresh interruption")
    })
    shiny::testServer(
      oauth_connections_server,
      args = list(id = "health", manager = fixture[["manager"]]),
      session = manager_test_session(cookie),
      {
        current <- connection(connection_id)
        expect_true(current[["is_usable"]]())
        if (uncertain) {
          expect_error(current[["refresh"]]())
          expect_identical(current[["summary"]]()[["status"]], "uncertain")
        }
        controller[["reauthorize"]](connection_id)
        hooks <- controller[["hooks"]]("a")
        context <- hooks[["prepare"]]()
        expect_identical(context[["accepted_extra_scopes"]], character())
        browser <- valid_browser_token()
        url <- prepare_call_internal(
          client,
          browser,
          .transaction_context = context,
          .requested_scopes = context[["requested_scopes"]],
          .accepted_extra_scopes = context[["accepted_extra_scopes"]]
        )
        state <- parse_query_param(url, "state")
        payload <- state_payload_decrypt_validate(client, state)
        expect_identical(
          connection_data_decode(payload[["accepted_extra_scopes"]]),
          character()
        )
        restored <- oauth_module_managed_context(hooks, client, state, browser)
        expect_error(
          hooks[["accept"]](token, restored[["data"]], as.numeric(Sys.time())),
          "exceeds"
        )
        empty <- token
        empty@granted_scopes <- character()
        empty@access_token <- "empty-retry"
        empty@refresh_token <- "empty-retry-refresh"
        expect_true(hooks[["accept"]](
          empty,
          restored[["data"]],
          as.numeric(Sys.time())
        ))
        row <- Filter(
          function(row) {
            identical(row[["replaces_connection_id"]], connection_id)
          },
          controller[["records"]]()
        )[[1L]]
        expect_true(row[["refresh_scope_narrowed"]])
      }
    )
  }
})
