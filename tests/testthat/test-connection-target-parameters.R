test_that("provider resource overrides cannot replace declared targets", {
  # Unblocking generic parameters must not bypass the target routing policy.
  local_options(
    shinyOAuth.unblock_auth_params = "resource",
    shinyOAuth.unblock_token_params = "resource"
  )
  for (mode in c("rfc8707", "microsoft")) {
    for (field in c("extra_auth_params", "extra_token_params")) {
      for (name in c("resource", "RESOURCE", " resource ")) {
        for (value in list("urn:other", NULL)) {
          provider <- make_test_provider()
          provider@token_target_mode <- mode
          S7::prop(provider, field) <- stats::setNames(list(value), name)
          expect_error(
            oauth_client(
              provider,
              "app",
              client_secret = "",
              redirect_uri = "https://app.example/callback",
              scopes = "https://api.example/read",
              token_targets = list(
                api = list(
                  resource = "https://api.example",
                  scopes = "https://api.example/read"
                )
              )
            ),
            "resource.*conflicts with token_targets"
          )
        }
      }
    }
  }
})

test_that("unrelated provider parameters preserve target routing on the wire", {
  local_options(shinyOAuth.skip_browser_token = FALSE)
  provider <- make_test_provider()
  S7::props(provider) <- list(
    token_target_mode = "rfc8707",
    extra_auth_params = list(prompt = "consent"),
    extra_token_params = list(custom = "retained")
  )
  client <- oauth_client(
    provider,
    "app",
    client_secret = "",
    redirect_uri = "https://app.example/callback",
    scopes = "read",
    token_targets = list(api = list(resource = "urn:api", scopes = "read"))
  )
  requests <- list()
  local_mocked_bindings(req_with_retry = function(req, ...) {
    requests[[length(requests) + 1L]] <<- lapply(
      req[["body"]][["data"]],
      function(value) {
        utils::URLdecode(as.character(value))
      }
    )
    httr2::response(
      req[["url"]],
      status = 200L,
      headers = list("content-type" = "application/json"),
      body = charToRaw(
        '{"access_token":"access","refresh_token":"refresh","token_type":"Bearer","expires_in":3600,"scope":"read"}'
      )
    )
  })
  browser <- valid_browser_token()
  url <- prepare_call(client, browser)
  expect_identical(parse_query_param(url, "resource", decode = TRUE), "urn:api")
  expect_identical(parse_query_param(url, "prompt", decode = TRUE), "consent")
  token <- handle_callback(
    client,
    "code",
    parse_query_param(url, "state"),
    browser
  )
  refresh_token(client, token)
  expect_length(requests, 2L)
  for (request in requests) {
    expect_identical(request[["resource"]], "urn:api")
    expect_identical(request[["custom"]], "retained")
  }
})
