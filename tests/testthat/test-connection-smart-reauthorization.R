test_that("standalone replacement obtains patient context with narrowed permissions", {
  local_options(shinyOAuth.skip_browser_token = TRUE)
  site <- smart_client_fixture()
  site[["metadata"]][["capabilities"]] <- c(
    site[["metadata"]][["capabilities"]], "permission-offline"
  )
  client <- smart_client(
    site, "example", "https://app.example/callback",
    scopes = c("launch/patient", "patient/Patient.rs", "offline_access"),
    required_scopes = "patient/Patient.r"
  )
  local_mocked_bindings(req_with_retry = function(req, ...) {
    httr2::response(
      req[["url"]], status = 200L,
      headers = list("content-type" = "application/json"),
      body = charToRaw(jsonlite::toJSON(list(
        access_token = "smart-access", refresh_token = "smart-refresh",
        token_type = "Bearer", expires_in = 3600,
        scope = "patient/Patient.r offline_access", patient = "123"
      ), auto_unbox = TRUE))
    )
  })
  browser <- "__SKIPPED__"
  exchange <- function(url) {
    handle_callback(
      client, "code", parse_query_param(url, "state"), browser
    )
  }
  token <- exchange(prepare_call(client, browser))
  expect_identical(token@smart_context[["patient"]], "123")
  expect_false("launch/patient" %in% token@granted_scopes)
  expected <- c("launch/patient", "patient/Patient.r", "offline_access")

  shiny::testServer(
    oauth_module_server,
    args = list(id = "auth", client = client, auto_redirect = FALSE),
    {
      session[["flushReact"]]()
      operation <- .begin_auth_operation("login", NULL, new_epoch = TRUE)
      .accept_login_token(token, NULL)
      .finish_auth_operation(operation, "login")
      previous <- values[["connection"]]()
      values[["reauthorize"]]()
      values[["browser_token"]] <- browser
      url <- values[["build_auth_url"]]()
      expect_setequal(
        normalize_scope_tokens(parse_query_param(url, "scope", decode = TRUE)),
        expected
      )
      replacement <- exchange(url)
      expect_identical(replacement@smart_context[["patient"]], "123")
      expect_setequal(replacement@granted_scopes, token@granted_scopes)
      expect_false(previous[["is_usable"]]())
    }
  )

  manager <- oauth_connections(
    list(a = client), "https://app.example",
    retention = "browser", store = oauth_connection_store_memory(),
    owner_policy = oauth_browser_owner(),
    keys = list(
      credentials = openssl::rand_bytes(32L), owner = openssl::rand_bytes(32L)
    )
  )
  f <- list(ui = oauth_connections_ui(shiny::fluidPage(), "health", manager))
  shiny::testServer(
    oauth_connections_server,
    args = list(id = "health", manager = manager),
    session = manager_test_session(manager_test_cookie(f)),
    {
      id <- manager_test_accept(controller, token = token)
      controller[["reauthorize"]](id)
      hooks <- controller[["hooks"]]("a")
      context <- hooks[["prepare"]]()
      expect_setequal(context[["requested_scopes"]], expected)
      url <- prepare_call_internal(
        client, browser, .requested_scopes = context[["requested_scopes"]]
      )
      replacement <- exchange(url)
      hooks[["accept"]](replacement, context, as.numeric(Sys.time()))
      row <- Filter(
        function(row) identical(row[["replaces_connection_id"]], id),
        controller[["records"]]()
      )[[1L]]
      expect_identical(row[["token"]]@smart_context[["patient"]], "123")
      expect_setequal(row[["token"]]@granted_scopes, token@granted_scopes)
    }
  )
})

test_that("standalone launch repair does not restore removed patient permissions", {
  client <- smart_client(
    smart_client_fixture(), "example", "https://app.example/callback",
    scopes = c("launch/patient", "patient/Patient.rs", "user/Observation.r"),
    required_scopes = character()
  )
  expect_identical(
    authorization_scope_limit(client, "user/Observation.r"),
    "user/Observation.r"
  )
  expect_setequal(
    authorization_scope_limit(client, "patient/Patient.r"),
    c("patient/Patient.r", "launch/patient")
  )
  expect_error(
    authorization_scope_limit(client, "patient/Patient.cruds"),
    "within the client configuration"
  )
})
