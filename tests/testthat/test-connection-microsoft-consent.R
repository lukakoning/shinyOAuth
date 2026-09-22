microsoft_consent_client <- function(scopes = c("read", "write")) {
  provider <- oauth_provider(
    "microsoft-consent",
    "https://issuer.example/auth",
    "https://issuer.example/token",
    token_target_mode = "microsoft",
    use_nonce = FALSE,
    token_auth_style = "public"
  )
  oauth_client(
    provider,
    "app",
    redirect_uri = "https://app.example/callback",
    scopes = paste0("https://api.example/", scopes),
    scope_validation = "strict",
    resource_bases = c(api = "https://api.example/v1"),
    token_targets = list(
      api = list(
        resource = "https://api.example",
        scopes = paste0("https://api.example/", scopes),
        required_scopes = "https://api.example/read",
        resource_ids = "api"
      )
    )
  )
}

microsoft_consent_fixture <- function(client) {
  manager <- oauth_connections(
    list(a = client),
    "https://app.example",
    retention = "browser",
    store = oauth_connection_store_memory(),
    owner_policy = oauth_browser_owner(),
    keys = list(
      credentials = openssl::rand_bytes(32),
      owner = openssl::rand_bytes(32)
    )
  )
  list(
    manager = manager,
    ui = oauth_connections_ui(shiny::fluidPage("Consent"), "auth", manager)
  )
}

test_that("Microsoft prior consent remains honest evidence without widening operations", {
  local_options(shinyOAuth.skip_browser_token = FALSE)
  dispatch <- refresh_token_dispatch
  for (managed in c(FALSE, TRUE)) {
    for (partial in c(FALSE, TRUE)) {
      client <- microsoft_consent_client(
        if (partial) c("read", "write") else "read"
      )
      f <- microsoft_consent_fixture(client)
      requests <- list()
      resource_calls <- 0L
      hold_refresh <- FALSE
      finish <- NULL
      returned <- if (partial) "read" else "read write"
      local_mocked_bindings(
        refresh_token_dispatch = function(...) {
          if (hold_refresh) {
            promises::promise(function(resolve, reject) finish <<- resolve)
          } else {
            dispatch(...)
          }
        },
        req_with_retry = function(req, ...) {
          requests[[length(requests) + 1L]] <<- lapply(
            req[["body"]][["data"]],
            function(value) {
              utils::URLdecode(gsub(
                "+",
                " ",
                as.character(value),
                fixed = TRUE
              ))
            }
          )
          httr2::response(
            req[["url"]],
            status = 200L,
            headers = list("content-type" = "application/json"),
            body = charToRaw(jsonlite::toJSON(
              list(
                access_token = paste0("access-", length(requests)),
                refresh_token = paste0("refresh-", length(requests)),
                token_type = "Bearer",
                expires_in = 3600,
                scope = returned
              ),
              auto_unbox = TRUE
            ))
          )
        },
        perform_resource_req = function(...) {
          resource_calls <<- resource_calls + 1L
          "resource-response"
        },
        revoke_token = function(...) invisible(NULL)
      )
      # The configured API permission can be a subset of previous consent. A
      # partial response is also a permanent local ceiling for later responses.
      if (partial) {
        client@scope_validation <- "none"
      }
      browser <- valid_browser_token()
      url <- prepare_call(client, browser)
      token <- handle_callback(
        client,
        "code",
        parse_query_param(url, "state"),
        browser
      )
      shiny::testServer(
        if (managed) oauth_connections_server else oauth_module_server,
        args = if (managed) {
          list(id = "auth", manager = f[["manager"]])
        } else {
          list(id = "auth", client = client, auto_redirect = FALSE)
        },
        session = manager_test_session(
          if (managed) manager_test_cookie(f) else NULL
        ),
        {
          current <- if (managed) {
            connection(manager_test_accept(controller, token = token))
          } else {
            .accept_login_token(token, NULL)
            values[["connection"]]()
          }
          expect_true(current[["has_scopes"]]("https://api.example/read"))
          expect_false(current[["has_scopes"]]("https://api.example/write"))
          expect_error(current[["access_token"]]("https://api.example/write"))
          expect_error(current[["request"]](
            "api",
            required_scopes = "https://api.example/write"
          ))
          expect_identical(resource_calls, 0L)
          expect_identical(
            current[["request"]](
              "api",
              required_scopes = "https://api.example/read"
            ),
            "resource-response"
          )
          returned <<- "read write"
          expect_identical(
            current[["access_token"]](force_refresh = TRUE),
            "access-2"
          )
          expect_setequal(
            current[["targets"]]()[["api"]][["granted_scopes"]],
            paste0("https://api.example/", c("read", "write"))
          )
          expect_false(current[["has_scopes"]]("https://api.example/write"))
          expect_identical(
            tail(requests, 1L)[[1L]][["scope"]],
            "https://api.example/read"
          )
          expect_identical(
            current[["targets"]]()[["api"]][["status"]],
            if (partial) "limited" else "active"
          )
          record <- if (managed) {
            controller[["read"]](current[["id"]])
          } else {
            list(
              client = client,
              token = values[["token"]],
              targets = values[["targets"]]
            )
          }
          expect_identical(
            record[["targets"]][["limits"]][["api"]],
            "https://api.example/read"
          )
          # Restored credentials retain the full evidence and the smaller policy.
          key <- openssl::rand_bytes(32)
          sealed <- connection_credentials_seal(
            record[["token"]],
            "synthetic-owner-id",
            "synthetic-connection",
            client,
            key,
            as.numeric(Sys.time()),
            targets = record[["targets"]]
          )
          restored <- connection_credentials_open(
            sealed,
            "synthetic-owner-id",
            "synthetic-connection",
            client,
            key
          )
          selected <- token_target_select(c(list(client = client), restored))
          expect_false(connection_record_has_scopes(
            selected,
            "https://api.example/write"
          ))

          # A refresh claim hides the bundle in a manager. Its reactive permission
          # snapshot must not briefly expose the broader physical grant.
          session[["flushReact"]]()
          hold_refresh <<- TRUE
          pending <- current[["access_token"]](
            force_refresh = TRUE,
            async = TRUE
          )
          session[["flushReact"]]()
          expect_false(current[["has_scopes"]]("https://api.example/write"))
          expect_true(current[["has_scopes"]]("https://api.example/read"))
          completed <- NULL
          promises::then(pending, function(value) completed <<- value)
          finish(record[["token"]])
          poll_for_async(function() !is.null(completed), session)
          expect_identical(completed, "access-2")
          expect_false(current[["has_scopes"]]("https://api.example/write"))
        }
      )
    }
  }
})

test_that("direct default-target refresh accepts the full Microsoft grant", {
  client <- microsoft_consent_client("read")
  granted <- paste0("https://api.example/", c("read", "write"))
  token <- OAuthToken(
    access_token = "access",
    refresh_token = "refresh",
    token_type = "Bearer",
    expires_at = as.numeric(Sys.time()) + 3600,
    granted_scopes = granted,
    granted_scopes_verified = TRUE
  )
  sent <- NULL
  local_mocked_bindings(req_with_retry = function(req, ...) {
    sent <<- utils::URLdecode(as.character(req[["body"]][["data"]][["scope"]]))
    httr2::response(
      req[["url"]],
      status = 200L,
      headers = list("content-type" = "application/json"),
      body = charToRaw(jsonlite::toJSON(
        list(
          access_token = "fresh",
          refresh_token = "rotated",
          token_type = "Bearer",
          expires_in = 3600,
          scope = paste(granted, collapse = " ")
        ),
        auto_unbox = TRUE
      ))
    )
  })
  fresh <- refresh_token(client, token)
  expect_identical(sent, "https://api.example/read")
  expect_setequal(fresh@granted_scopes, granted)
})

test_that("Microsoft API narrowing fails before using refresh credentials", {
  local_options(shinyOAuth.skip_browser_token = TRUE)
  for (managed in c(FALSE, TRUE)) {
    client <- microsoft_consent_client()
    f <- microsoft_consent_fixture(client)
    calls <- 0L
    local_mocked_bindings(refresh_token_dispatch = function(...) {
      calls <<- calls + 1L
      stop("must not send")
    })
    token <- OAuthToken(
      access_token = "access",
      refresh_token = "refresh",
      token_type = "Bearer",
      expires_at = as.numeric(Sys.time()) + 3600,
      granted_scopes = client@scopes,
      granted_scopes_verified = TRUE
    )
    shiny::testServer(
      if (managed) oauth_connections_server else oauth_module_server,
      args = if (managed) {
        list(id = "auth", manager = f[["manager"]])
      } else {
        list(id = "auth", client = client, auto_redirect = FALSE)
      },
      session = manager_test_session(
        if (managed) manager_test_cookie(f) else NULL
      ),
      {
        current <- if (managed) {
          connection(manager_test_accept(controller, token = token))
        } else {
          .accept_login_token(token, NULL)
          values[["connection"]]()
        }
        error <- tryCatch(
          current[["refresh"]](scopes = "https://api.example/read"),
          error = identity
        )
        expect_s3_class(error, "shinyOAuth_access_error")
        expect_identical(
          error[["context"]][["reason"]],
          "unsupported_scope_narrowing"
        )
        expect_identical(calls, 0L)
        expect_identical(current[["access_token"]](), "access")
      }
    )
  }
})

test_that("Microsoft consent expansion stays resource bounded and aggregate bounded", {
  client <- microsoft_consent_client("read")
  request <- token_target_request(client)
  for (extra in c(
    "https://other.example/read",
    "https://api.example.evil/read",
    "https://api.example/.default",
    "https://api.example/",
    "email"
  )) {
    expect_error(
      validate_token_target_grant(
        client,
        c("https://api.example/read", extra),
        request
      ),
      class = "shinyOAuth_token_error"
    )
  }
  expect_error(
    validate_token_target_grant(client, "https://api.example/write", request),
    class = "shinyOAuth_token_error"
  )
  targets <- client@token_targets
  targets[["second"]] <- list(
    resource = "https://second.example",
    scopes = "https://second.example/read"
  )
  S7::props(client) <- list(
    token_targets = targets,
    scopes = c(client@scopes, "https://second.example/read")
  )
  token <- function(resource) {
    OAuthToken(
      access_token = "access",
      refresh_token = "refresh",
      token_type = "Bearer",
      expires_at = as.numeric(Sys.time()) + 3600,
      granted_scopes = paste0(resource, c("/read", paste0("/p", 1:69))),
      granted_scopes_verified = TRUE
    )
  }
  primary <- token("https://api.example")
  bundle <- token_target_bundle(client, primary)
  fresh <- token("https://second.example")
  expect_error(
    token_target_commit(
      client,
      primary,
      bundle,
      fresh,
      token_target_request(client, "second", bundle[["limits"]])
    ),
    "grants exceed"
  )
  fresh@refresh_token <- NA_character_
  bundle[["tokens"]][["second"]] <- fresh
  key <- openssl::rand_bytes(32)
  sealed <- connection_credentials_seal(
    primary,
    "synthetic-owner-id",
    "synthetic-connection",
    client,
    key,
    as.numeric(Sys.time()),
    targets = bundle
  )
  expect_error(
    connection_credentials_open(
      sealed,
      "synthetic-owner-id",
      "synthetic-connection",
      client,
      key
    ),
    class = "shinyOAuth_token_error"
  )
})
