test_that("broader SMART grants survive complete replacement authorization", {
  local_options(shinyOAuth.skip_browser_token = TRUE)
  client <- smart_client(
    smart_client_fixture(),
    "example",
    "https://app.example/callback",
    scopes = "user/Patient.r",
    required_scopes = "user/Patient.r"
  )
  local_mocked_bindings(req_with_retry = function(req, ...) {
    httr2::response(
      req[["url"]],
      status = 200L,
      headers = list("content-type" = "application/json"),
      body = charToRaw(
        '{"access_token":"smart-access","refresh_token":"smart-refresh","token_type":"Bearer","expires_in":3600,"scope":"user/*.rs"}'
      )
    )
  })
  exchange <- function(url) {
    handle_callback(
      client,
      "code",
      parse_query_param(url, "state"),
      "__SKIPPED__"
    )
  }
  token <- exchange(prepare_call(client, "__SKIPPED__"))
  expect_identical(token@granted_scopes, "user/*.rs")
  expect_identical(
    authorization_retained_scopes(client, token, client@scopes),
    client@scopes
  )
  expect_identical(authorization_extra_scopes(client, token), "user/*.rs")

  shiny::testServer(
    oauth_module_server,
    args = list(id = "auth", client = client, auto_redirect = FALSE),
    {
      session[["flushReact"]]()
      operation <- .begin_auth_operation("login", NULL, new_epoch = TRUE)
      .accept_login_token(token, NULL)
      .finish_auth_operation(operation, "login")
      values[["reauthorize"]]()
      values[["browser_token"]] <- "__SKIPPED__"
      url <- values[["build_auth_url"]]()
      expect_identical(
        parse_query_param(url, "scope", decode = TRUE),
        "user/Patient.r"
      )
      replacement <- exchange(url)
      expect_identical(replacement@granted_scopes, "user/*.rs")
      .accept_login_token(replacement, NULL)
      expect_true(values[["connection"]]()[["has_scopes"]]("user/Patient.r"))
      expect_false(values[["connection"]]()[["has_scopes"]](
        "user/Observation.r"
      ))
    }
  )
  manager <- oauth_connections(
    list(a = client),
    "https://app.example",
    retention = "browser",
    store = oauth_connection_store_memory(),
    owner_policy = oauth_browser_owner(),
    keys = list(
      credentials = openssl::rand_bytes(32L),
      owner = openssl::rand_bytes(32L)
    )
  )
  fixture <- list(
    ui = oauth_connections_ui(shiny::fluidPage(), "health", manager)
  )
  shiny::testServer(
    oauth_connections_server,
    args = list(id = "health", manager = manager),
    session = manager_test_session(manager_test_cookie(fixture)),
    {
      id <- manager_test_accept(controller, token = token)
      controller[["reauthorize"]](id)
      hooks <- controller[["hooks"]]("a")
      context <- hooks[["prepare"]]()
      expect_identical(context[["requested_scopes"]], "user/Patient.r")
      url <- prepare_call_internal(
        client,
        "__SKIPPED__",
        .requested_scopes = context[["requested_scopes"]],
        .accepted_extra_scopes = context[["accepted_extra_scopes"]]
      )
      replacement <- exchange(url)
      hooks[["accept"]](replacement, context, as.numeric(Sys.time()))
      row <- Filter(
        function(row) identical(row[["replaces_connection_id"]], id),
        controller[["records"]]()
      )[[1L]]
      expect_identical(row[["token"]]@granted_scopes, "user/*.rs")
      expect_identical(row[["authorization_scopes"]], "user/Patient.r")
    }
  )
  request <- refresh_scope_request(
    client,
    token,
    "user/Patient.r",
    accepted_extra_scopes = "user/*.rs"
  )
  expect_no_error(validate_refresh_scope_grant(client, "user/*.rs", request))
  expect_error(
    validate_refresh_scope_grant(client, "user/*.cruds", request),
    "exceeds"
  )
  expect_error(
    smart_verify_scope_grant(
      client,
      "user/*.cruds",
      TRUE,
      token@granted_scopes
    ),
    "prior grant"
  )
})

test_that("SMART retained requests preserve reductions and never widen a ceiling", {
  client <- smart_client(
    smart_client_fixture(),
    "example",
    "https://app.example/callback",
    scopes = c("user/Patient.rs", "user/Observation.rs"),
    required_scopes = character()
  )
  expect_identical(
    smart_authorization_retained_scopes(client, "user/*.rs", "user/Patient.r"),
    "user/Patient.r"
  )
  expect_setequal(
    smart_authorization_retained_scopes(client, "user/*.r", client@scopes),
    c("user/Patient.r", "user/Observation.r")
  )
  expect_identical(
    smart_authorization_retained_scopes(
      client,
      "user/Patient.r",
      client@scopes
    ),
    "user/Patient.r"
  )
})
