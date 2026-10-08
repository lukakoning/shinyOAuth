test_that("Microsoft API-empty grants cannot acquire a token for another resource", {
  local_options(shinyOAuth.skip_browser_token = FALSE)
  f <- ordinary_oidc_fixture()
  client <- f[["client"]]
  provider <- client@provider
  provider@token_target_mode <- "microsoft"
  S7::props(client) <- list(
    provider = provider,
    scopes = c(
      "openid",
      "offline_access",
      "api://custom/read",
      "api://other/contacts"
    ),
    resource_bases = c(api = "https://custom-api.example/v1"),
    token_targets = list(
      api = list(
        resource = "api://custom",
        scopes = "api://custom/read",
        resource_ids = "api"
      ),
      other = list(resource = "api://other", scopes = "api://other/contacts")
    ),
    default_token_target = "api"
  )
  response_scope <- "openid"
  resource_calls <- 0L
  local_mocked_bindings(
    fetch_jwks = function(...) list(keys = list(f[["jwk"]])),
    req_with_retry = function(req, ...) {
      response <- f[["request"]](req, ...)
      body <- httr2::resp_body_json(response)
      body[["scope"]] <- response_scope
      httr2::response(
        req[["url"]],
        status = 200L,
        headers = list("content-type" = "application/json"),
        body = charToRaw(jsonlite::toJSON(body, auto_unbox = TRUE))
      )
    },
    perform_resource_req = function(...) {
      resource_calls <<- resource_calls + 1L
      "resource-response"
    },
    revoke_token = function(...) invisible(NULL)
  )
  for (managed in c(FALSE, TRUE)) {
    for (partial_at in c("login", "refresh")) {
      for (async in c(FALSE, TRUE)) {
        response_scope <- if (partial_at == "login") "openid" else "openid read"
        browser <- valid_browser_token()
        url <- f[["authorize"]](prepare_call(client, browser))
        token <- handle_callback(
          client,
          "code",
          parse_query_param(url, "state"),
          browser
        )
        expect_true(token@id_token_validated)
        fixture <- ordinary_manager_fixture(client)
        shiny::testServer(
          if (managed) oauth_connections_server else oauth_module_server,
          args = if (managed) {
            list(id = "health", manager = fixture[["manager"]])
          } else {
            list(id = "health", client = client, auto_redirect = FALSE)
          },
          session = manager_test_session(
            if (managed) manager_test_cookie(fixture) else NULL
          ),
          {
            current <- if (managed) {
              connection(manager_test_accept(controller, token = token))
            } else {
              .accept_login_token(token, NULL)
              values[["connection"]]()
            }
            if (partial_at == "refresh") {
              response_scope <<- "openid"
              expect_true(current[["refresh"]]())
            }
            expect_identical(
              current[["targets"]]()[["api"]][["granted_scopes"]],
              "openid"
            )
            if (managed) {
              # Exercise authenticated storage restoration, including its limits.
              record <- controller[["read"]](current[["id"]])
              expect_setequal(
                record[["targets"]][["limits"]][["api"]],
                c("openid", "offline_access")
              )
            }
            before <- length(f[["state"]][["requests"]])
            resource_calls <<- 0L
            error <- tryCatch(
              current[["access_token"]](
                target = "api",
                force_refresh = TRUE,
                async = async
              ),
              error = identity
            )
            if (inherits(error, "promise")) {
              settled <- NULL
              promises::then(
                error,
                function(x) {
                  settled <<- x
                },
                function(x) {
                  settled <<- x
                }
              )
              poll_for_async(function() !is.null(settled), session)
              error <- settled
            }
            expect_s3_class(error, "shinyOAuth_access_error")
            expect_identical(
              error[["context"]][["reason"]],
              "insufficient_scope"
            )
            expect_error(
              current[["refresh"]](),
              class = "shinyOAuth_access_error"
            )
            expect_error(
              current[["request"]]("api", refresh = TRUE, min_valid_for = 7200),
              class = "shinyOAuth_access_error"
            )
            expect_identical(length(f[["state"]][["requests"]]), before)
            expect_identical(resource_calls, 0L)

            # Invalid replacement fails before disconnect and cannot add .default
            # or restore the removed API permission from configuration.
            if (managed) {
              expect_error(
                controller[["reauthorize"]](current[["id"]]),
                class = "shinyOAuth_access_error"
              )
            } else {
              expect_error(
                values[["reauthorize"]](),
                class = "shinyOAuth_access_error"
              )
            }
            expect_identical(length(f[["state"]][["requests"]]), before)
            expect_type(
              current[["access_token"]](min_valid_for = 0),
              "character"
            )
            expect_identical(
              current[["identity"]]()[["id_token_claims"]][["sub"]],
              "alice"
            )
            expect_false(current[["has_scopes"]]("api://custom/read"))

            # Another target still has its resource selector and can be acquired.
            response_scope <<- "openid contacts"
            expect_type(
              current[["access_token"]](target = "other"),
              "character"
            )
            sent <- tail(f[["state"]][["requests"]], 1L)[[1L]]
            expect_true(
              "api://other/contacts" %in%
                normalize_scope_tokens(sent[["scope"]])
            )
          }
        )
      }
    }
  }
})

test_that("code redemption rejects a restored Microsoft OIDC-only target limit", {
  local_options(shinyOAuth.skip_browser_token = FALSE)
  provider <- make_test_provider()
  provider@token_target_mode <- "microsoft"
  client <- oauth_client(
    provider,
    "app",
    client_secret = "",
    redirect_uri = "https://app.example/callback",
    scopes = c("openid", "api://custom/read"),
    token_targets = list(
      api = list(resource = "api://custom", scopes = "api://custom/read")
    )
  )
  calls <- 0L
  local_mocked_bindings(req_with_retry = function(...) {
    calls <<- calls + 1L
    stop("Token endpoint must not be called")
  })
  browser <- valid_browser_token()
  prepared <- prepare_call_internal(
    client,
    browser,
    .requested_scopes = "openid",
    .target_limits = list(api = "openid")
  )
  expect_error(
    handle_callback(
      client,
      "code",
      parse_query_param(prepared, "state"),
      browser
    ),
    class = "shinyOAuth_access_error"
  )
  expect_identical(calls, 0L)
})
