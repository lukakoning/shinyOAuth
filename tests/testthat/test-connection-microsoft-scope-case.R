test_that("Microsoft casing is consistent through callbacks, refresh and restoration", {
  local_options(shinyOAuth.skip_browser_token = FALSE)
  provider <- make_test_provider()
  provider@token_target_mode <- "microsoft"
  prefix <- "https://graph.microsoft.com/"
  client <- oauth_client(
    provider,
    "app",
    client_secret = "",
    redirect_uri = "https://app.example/callback",
    scopes = paste0(prefix, "user.read"),
    scope_validation = "strict",
    resource_bases = c(graph = "https://graph.microsoft.com/v1.0"),
    token_targets = list(
      graph = list(
        resource = "https://graph.microsoft.com",
        scopes = paste0(prefix, "USER.READ"),
        required_scopes = paste0(prefix, "User.Read"),
        resource_ids = "graph"
      )
    )
  )
  returned <- "User.Read Mail.Read"
  calls <- 0L
  local_mocked_bindings(
    req_with_retry = function(req, ...) {
      calls <<- calls + 1L
      httr2::response(
        req[["url"]],
        status = 200L,
        headers = list("content-type" = "application/json"),
        body = charToRaw(jsonlite::toJSON(
          list(
            access_token = paste0("access-", calls),
            refresh_token = paste0("refresh-", calls),
            token_type = "Bearer",
            expires_in = 3600,
            scope = returned
          ),
          auto_unbox = TRUE
        ))
      )
    },
    perform_resource_req = function(...) "resource-response",
    revoke_token = function(...) invisible(NULL)
  )
  for (managed in c(FALSE, TRUE)) {
    returned <- "User.Read Mail.Read"
    browser <- valid_browser_token()
    url <- prepare_call(client, browser)
    token <- handle_callback(
      client,
      "code",
      parse_query_param(url, "state"),
      browser
    )
    expect_setequal(
      token@granted_scopes,
      paste0(prefix, c("User.Read", "Mail.Read"))
    )
    bundle <- token_target_bundle(client, token)
    expect_identical(bundle[["limits"]][["graph"]], paste0(prefix, "User.Read"))
    key <- openssl::rand_bytes(32L)
    owner <- strrep("a", 32L)
    id <- strrep("b", 32L)
    sealed <- connection_credentials_seal(
      token,
      owner,
      id,
      client,
      key,
      1000,
      targets = bundle
    )
    restored <- connection_credentials_open(sealed, owner, id, client, key)
    expect_identical(restored[["targets"]], bundle)
    exercise <- function(current) {
      for (scope in c("user.read", "User.Read", "USER.READ")) {
        expect_true(current[["has_scopes"]](paste0(prefix, scope)))
        expect_type(
          current[["access_token"]](paste0(prefix, scope)),
          "character"
        )
      }
      expect_false(current[["has_scopes"]](paste0(prefix, "mail.read")))
      expect_identical(current[["summary"]]()[["status"]], "active")
      expect_identical(
        current[["request"]](
          "graph",
          required_scopes = paste0(prefix, "user.read")
        ),
        "resource-response"
      )
      returned <<- "USER.READ MAIL.READ"
      expect_true(current[["refresh"]](scopes = paste0(prefix, "user.read")))
      expect_true(current[["has_scopes"]](paste0(prefix, "User.Read")))
      expect_false(current[["has_scopes"]](paste0(prefix, "Mail.Read")))
    }
    if (managed) {
      f <- ordinary_manager_fixture(client)
      shiny::testServer(
        oauth_connections_server,
        args = list(id = "health", manager = f[["manager"]]),
        session = manager_test_session(manager_test_cookie(f)),
        {
          id <- manager_test_accept(controller, token = token)
          exercise(session[["getReturned"]]()[["connection"]](id))
        }
      )
    } else {
      shiny::testServer(
        oauth_module_server,
        args = list(id = "auth", client = client, auto_redirect = FALSE),
        {
          session[["flushReact"]]()
          .accept_login_token(token, NULL)
          exercise(values[["connection"]]())
        }
      )
    }
  }
})

test_that("scope case equivalence never changes resource identifiers or RFC scopes", {
  for (mode in c("microsoft", "rfc8707")) {
    provider <- make_test_provider()
    provider@token_target_mode <- mode
    client <- oauth_client(
      provider,
      "app",
      client_secret = "",
      redirect_uri = "https://app.example/callback",
      scopes = "api://Resource/user.read",
      token_targets = list(
        api = list(
          resource = "api://Resource",
          scopes = "api://Resource/user.read"
        )
      )
    )
    expect_identical(
      token_target_scopes_allowed(client, "api", "api://Resource/USER.READ"),
      mode == "microsoft"
    )
    for (other in c("api://resource/user.read", "api://Resource2/user.read")) {
      expect_false(token_target_scopes_allowed(client, "api", other))
      expect_error(validate_token_target_grant(
        client,
        other,
        token_target_request(client)
      ))
    }
    expect_false(connection_scope_covered(client, "openid", "OPENID"))
  }
})
