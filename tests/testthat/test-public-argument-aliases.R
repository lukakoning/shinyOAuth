test_that("polling intervals accept both spellings and released positions", {
  local_mocked_bindings(
    oauth_module_server_impl = function(...) list(...),
    .package = "shinyOAuth"
  )
  current <- oauth_module_server(
    "auth",
    "client",
    refresh_check_interval_ms = 4321
  )
  legacy <- oauth_module_server("auth", "client", refresh_check_interval = 4321)
  positional <- oauth_module_server(
    "auth",
    "client",
    TRUE,
    FALSE,
    FALSE,
    NULL,
    FALSE,
    60,
    4321
  )
  expect_identical(current, legacy)
  expect_identical(current, positional)
  expect_identical(current[["refresh_check_interval"]], 4321)
  expect_identical(
    oauth_module_server("auth", "client")[["refresh_check_interval"]],
    10000
  )
  expect_error(
    oauth_module_server(
      "auth",
      "client",
      refresh_check_interval_ms = 100,
      refresh_check_interval = 200
    ),
    "Cannot supply both"
  )
})

test_that("resource and refresh helpers preserve released named arguments", {
  client <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  token <- OAuthToken(access_token = "synthetic-access", token_type = "Bearer")
  preferred <- resource_req(token, "https://api.example/data", client = client)
  legacy <- resource_req(
    token,
    "https://api.example/data",
    oauth_client = client
  )
  expect_identical(preferred[["url"]], legacy[["url"]])
  expect_identical(preferred[["headers"]], legacy[["headers"]])
  expect_identical(preferred[["options"]], legacy[["options"]])
  local_mocked_bindings(
    refresh_token_dispatch = function(...) list(...),
    .package = "shinyOAuth"
  )
  expect_identical(
    refresh_token(client = client, token = token),
    refresh_token(oauth_client = client, token = token)
  )
  expect_error(
    resource_req(
      token,
      "https://api.example",
      client = client,
      oauth_client = client
    ),
    "Cannot supply both"
  )
})

test_that("token operation aliases select identical tokens and preserve defaults", {
  client <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  client@provider@introspection_url <- "https://example.com/introspect"
  client@provider@revocation_url <- "https://example.com/revoke"
  token <- OAuthToken(
    access_token = "synthetic-access",
    refresh_token = "synthetic-refresh",
    token_type = "Bearer"
  )
  requests <- list()
  local_mocked_bindings(
    req_with_retry = function(req, ...) {
      requests[[length(requests) + 1L]] <<- req
      httr2::response(
        url = req[["url"]],
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw('{"active":true}')
      )
    },
    .package = "shinyOAuth"
  )
  for (operation in list(introspect_token, revoke_token)) {
    current <- operation(client = client, token = token, token_kind = "access")
    legacy <- operation(
      oauth_client = client,
      oauth_token = token,
      which = "access"
    )
    expect_identical(current, legacy)
    n <- length(requests)
    expect_identical(requests[[n]][["body"]], requests[[n - 1L]][["body"]])
    expect_error(
      operation(client, token, token_kind = "access", which = "refresh"),
      "Cannot supply both"
    )
  }
  introspect_token(client, token)
  access_body <- requests[[length(requests)]][["body"]]
  revoke_token(client, token)
  refresh_body <- requests[[length(requests)]][["body"]]
  expect_identical(
    as.character(access_body[["data"]][["token"]]),
    "synthetic-access"
  )
  expect_identical(
    as.character(refresh_body[["data"]][["token"]]),
    "synthetic-refresh"
  )
})

test_that("callback aliases forward the same state and browser binding", {
  client <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  local_mocked_bindings(
    handle_callback_internal = function(...) list(...),
    .package = "shinyOAuth"
  )
  preferred <- handle_callback(
    client = client,
    code = "code",
    state = "sealed-state",
    browser_token = "browser"
  )
  legacy <- handle_callback(
    oauth_client = client,
    code = "code",
    payload = "sealed-state",
    browser_token = "browser"
  )
  expect_identical(preferred, legacy)
  expect_error(
    handle_callback(
      client,
      "code",
      state = "one",
      payload = "two",
      browser_token = "browser"
    ),
    "Cannot supply both"
  )
})

test_that("preferred constructor names preserve released settings and properties", {
  provider <- make_test_provider()
  provider@introspection_url <- "https://example.com/introspect"
  preferred <- oauth_client(
    provider,
    "registered",
    "secret",
    redirect_uri = "https://app.example/callback",
    introspect = TRUE,
    introspection_checks = "client_id"
  )
  legacy <- oauth_client(
    provider,
    "registered",
    "secret",
    redirect_uri = "https://app.example/callback",
    introspect = TRUE,
    introspect_elements = "client_id"
  )
  expect_identical(preferred@introspection_checks, legacy@introspect_elements)
  preferred@introspection_checks <- "scope"
  expect_identical(preferred@introspect_elements, "scope")
  preferred@introspect_elements <- "sub"
  expect_identical(preferred@introspection_checks, "sub")
})
