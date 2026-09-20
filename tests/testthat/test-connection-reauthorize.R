test_that("single-module reauthorization preserves its accepted scope limit", {
  local_options(shinyOAuth.skip_browser_token = FALSE)
  redirects <- list()
  revoked <- 0L
  local_mocked_bindings(
    send_oauth_module_redirect = function(session, url) {
      redirects[[length(redirects) + 1L]] <<- url
    },
    revoke_token = function(...) {
      revoked <<- revoked + 1L
    },
    refresh_token_dispatch = function(client, token, scope_request, ...) {
      expect_identical(scope_request[["scopes"]], "read")
      manager_test_token()
    }
  )
  client <- make_test_client(use_nonce = FALSE)
  client@scopes <- c("read", "write")
  shiny::testServer(
    oauth_module_server,
    args = list(id = "auth", client = client, auto_redirect = FALSE),
    {
      session[["flushReact"]]()
      token <- manager_test_token()
      token@granted_scopes <- "read"
      values[["token"]] <- token
      previous <- values[["connection"]]()
      values[["reauthorize"]]()
      session[["setInputs"]](
        shinyOAuth_sid = browser_ack[["token"]],
        shinyOAuth_cookie_ack = list(requestId = browser_ack[["id"]])
      )
      poll_for_async(function() length(redirects) > 0L, session)
      expect_null(values[["connection"]]())
      expect_identical(previous[["has_scopes"]]("read"), FALSE)
      expect_identical(revoked, 0L)
      expect_length(redirects, 1L)
      expect_identical(
        httr2::url_parse(redirects[[1L]])[["query"]][["scope"]],
        "read"
      )
      prepared <- prepare_call_internal(
        client,
        valid_browser_token(),
        .defer_build = TRUE,
        .requested_scopes = auth_operations[["reauth_scopes"]]
      )
      payload <- state_payload_decrypt_validate(
        client,
        prepared[["build_args"]][["payload"]]
      )
      expect_identical(payload[["scopes"]], "read")
      expect_setequal(payload[["configured_scopes"]], c("read", "write"))
      operation <- .begin_auth_operation("login", NULL, new_epoch = TRUE)
      .accept_login_token(token, NULL)
      .finish_auth_operation(operation, "login")
      current <- values[["connection"]]()
      expect_identical(current[["has_scopes"]]("write"), FALSE)
      expect_identical(identical(current[["id"]], previous[["id"]]), FALSE)
      error <- tryCatch(current[["refresh"]](), error = identity)
      expect_s3_class(error, "shinyOAuth_access_error")
      expect_null(values[["token"]])
    }
  )
})

test_that("managed replacement preserves restrictions after uncertain refresh", {
  f <- manager_test_fixture()
  cookie <- manager_test_cookie(f)
  local_mocked_bindings(
    refresh_token = function(...) stop("synthetic transport interruption"),
    revoke_token = function(...) stop("reauthorization must not revoke")
  )
  shiny::testServer(
    oauth_connections_server,
    args = list(id = "health", manager = f[["manager"]]),
    session = manager_test_session(cookie),
    {
      token <- manager_test_token()
      token@granted_scopes <- "read"
      id <- manager_test_accept(controller, token = token)
      other <- manager_test_accept(
        controller,
        client = "b",
        token = manager_test_token(refresh = "independent-refresh")
      )
      previous <- connection(id)
      tryCatch(
        previous[["access_token"]](force_refresh = TRUE),
        error = function(e) NULL
      )
      expect_identical(previous[["summary"]]()[["status"]], "uncertain")
      expect_identical(controller[["reauthorize"]](id), "a")
      hooks <- controller[["hooks"]]("a")
      context <- hooks[["prepare"]]()
      expect_identical(
        hooks[["parameters"]](context)[["requested_scopes"]],
        "read"
      )
      token@refresh_token <- "replacement-refresh"
      hooks[["accept"]](token, context, as.numeric(Sys.time()))
      rows <- controller[["records"]]()
      replacement <- Filter(
        function(row) identical(row[["replaces_connection_id"]], id),
        rows
      )[[1L]]
      expect_identical(replacement[["token"]]@granted_scopes, "read")
      expect_identical(replacement[["refresh_scope_narrowed"]], TRUE)
      expect_identical(
        connection_record_summary(
          replacement,
          replacement[["stored"]][["id"]]
        )[["replaces_connection_id"]],
        id
      )
      expect_identical(connection(other)[["is_usable"]](), TRUE)
      expect_identical(previous[["is_usable"]](), FALSE)
    }
  )
})

test_that("reauthorization scope overrides are authenticated and bounded", {
  local_options(shinyOAuth.skip_browser_token = TRUE)
  client <- make_test_client(use_nonce = FALSE)
  client@scopes <- c("read", "write")
  prepared <- prepare_call_internal(
    client,
    "__SKIPPED__",
    .defer_build = TRUE,
    .requested_scopes = "read"
  )
  payload <- state_payload_decrypt_validate(
    client,
    prepared[["build_args"]][["payload"]]
  )
  expect_identical(payload[["scopes"]], "read")
  payload[["scopes"]] <- "admin"
  error <- tryCatch(
    payload_verify_client_binding(client, payload),
    error = identity
  )
  expect_s3_class(error, "shinyOAuth_state_error")
  error <- tryCatch(
    prepare_call_internal(client, "__SKIPPED__", .requested_scopes = "admin"),
    error = identity
  )
  expect_s3_class(error, "shinyOAuth_input_error")
})

test_that("Microsoft UserInfo can be disabled without weakening OIDC", {
  provider <- oauth_provider_microsoft(userinfo_required = FALSE)
  expect_identical(provider@userinfo_required, FALSE)
  expect_identical(provider@userinfo_id_token_match, FALSE)
  expect_identical(provider@id_token_validation, TRUE)
  expect_identical(provider@id_token_required, TRUE)
  expect_identical(provider@use_nonce, TRUE)
  expect_identical(oauth_provider_microsoft()@userinfo_required, TRUE)
})

test_that("replacement code exchange enforces the sealed scope limit", {
  local_options(shinyOAuth.skip_browser_token = FALSE)
  client <- make_test_client(use_nonce = FALSE, scopes = c("read", "write"))
  scope <- NULL
  local_mocked_bindings(swap_code_for_token_set = function(...) {
    result <- list(
      access_token = "replacement-access",
      token_type = "Bearer",
      expires_in = 3600
    )
    if (!is.null(scope)) {
      result[["scope"]] <- scope
    }
    result
  })
  exchange <- function() {
    browser <- valid_browser_token()
    url <- prepare_call_internal(client, browser, .requested_scopes = "read")
    handle_callback(
      client,
      code = "synthetic-code",
      state = parse_query_param(url, "state"),
      browser_token = browser
    )
  }
  token <- exchange()
  expect_identical(token@granted_scopes, "read")
  expect_identical(token@granted_scopes_verified, FALSE)
  scope <- "read write"
  error <- tryCatch(exchange(), error = identity)
  expect_s3_class(error, "shinyOAuth_token_error")
})

test_that("explicit replacement retains the maximum authentication age policy", {
  local_options(shinyOAuth.skip_browser_token = TRUE)
  client <- make_test_client(use_nonce = TRUE)
  shiny::testServer(
    oauth_module_server,
    args = list(
      id = "auth",
      client = client,
      auto_redirect = FALSE,
      reauth_after_seconds = 60
    ),
    {
      token <- manager_test_token()
      token@granted_scopes <- "openid"
      values[["token"]] <- token
      values[["auth_started_at"]] <- as.numeric(Sys.time()) - 120
      values[["reauthorize"]]()
      expect_identical(auth_operations[["force_oidc_reauth"]], TRUE)
    }
  )
})

test_that("reauthorization discards late refresh without upstream revocation", {
  local_options(shinyOAuth.skip_browser_token = TRUE)
  client <- make_test_client(use_nonce = FALSE)
  client@scopes <- c("read", "write")
  resolve <- NULL
  revoked <- 0L
  local_mocked_bindings(
    refresh_token = function(...) {
      promises::promise(function(resolve_, reject_) resolve <<- resolve_)
    },
    revoke_token = function(...) {
      revoked <<- revoked + 1L
    }
  )
  shiny::testServer(
    oauth_module_server,
    args = list(id = "auth", client = client, auto_redirect = FALSE),
    {
      values[["token"]] <- manager_test_token()
      previous <- values[["connection"]]()
      result <- NULL
      promises::catch(
        previous[["access_token"]](force_refresh = TRUE, async = TRUE),
        function(error) result <<- error
      )
      values[["reauthorize"]]()
      resolve(manager_test_token(access = "obsolete-refresh"))
      poll_for_async(function() !is.null(result), session)
      expect_identical(
        result[["context"]][["reason"]],
        "authorization_unavailable"
      )
      expect_null(values[["connection"]]())
      expect_identical(revoked, 0L)
    }
  )
})

test_that("managed reauthorization routes the selected connection's scope limit", {
  local_options(shinyOAuth.skip_browser_token = TRUE)
  f <- manager_test_fixture()
  cookie <- manager_test_cookie(f)
  resolve <- NULL
  revoked <- 0L
  local_mocked_bindings(
    refresh_token = function(...) {
      promises::promise(function(resolve_, reject_) resolve <<- resolve_)
    },
    revoke_token = function(...) {
      revoked <<- revoked + 1L
    }
  )
  shiny::testServer(
    oauth_connections_server,
    args = list(id = "health", manager = f[["manager"]]),
    session = manager_test_session(cookie),
    {
      token <- manager_test_token()
      token@granted_scopes <- "read"
      id <- manager_test_accept(controller, token = token)
      auth <- session[["getReturned"]]()
      previous <- auth[["connection"]](id)
      result <- NULL
      promises::catch(
        previous[["access_token"]](force_refresh = TRUE, async = TRUE),
        function(error) result <<- error
      )
      auth[["reauthorize"]](id)
      expect_identical(previous[["has_scopes"]]("read"), FALSE)
      expect_identical(modules[["a"]][["pending_login"]], TRUE)
      resolve(manager_test_token(access = "obsolete-managed-refresh"))
      poll_for_async(function() !is.null(result), session)
      expect_identical(
        result[["context"]][["reason"]],
        "authorization_unavailable"
      )
      expect_identical(revoked, 0L)
      context <- controller[["hooks"]]("a")[["prepare"]]()
      expect_identical(context[["requested_scopes"]], "read")
      expect_identical(context[["replaces_connection_id"]], id)
      broad <- manager_test_token(refresh = "new-refresh")
      error <- tryCatch(
        controller[["hooks"]]("a")[["accept"]](
          broad,
          context,
          as.numeric(Sys.time())
        ),
        error = identity
      )
      expect_s3_class(error, "shinyOAuth_token_error")
    }
  )
})

test_that("reauthorization does not expand an explicitly empty grant", {
  local_options(shinyOAuth.skip_browser_token = TRUE)
  client <- make_test_client(use_nonce = FALSE, scopes = c("read", "write"))
  shiny::testServer(
    oauth_module_server,
    args = list(id = "auth", client = client, auto_redirect = FALSE),
    {
      token <- manager_test_token()
      token@granted_scopes <- character()
      values[["token"]] <- token
      error <- tryCatch(values[["reauthorize"]](), error = identity)
      expect_identical(error[["context"]][["reason"]], "interaction_required")
      expect_identical(values[["pending_login"]], FALSE)
    }
  )
})
