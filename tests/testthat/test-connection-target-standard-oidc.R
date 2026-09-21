test_that("RFC 8707 carries and validates phone and address as OIDC scopes", {
  local_options(shinyOAuth.skip_browser_token = FALSE)
  for (identity_scope in c("phone", "address")) {
    provider <- make_test_provider()
    provider@token_target_mode <- "rfc8707"
    client <- oauth_client(
      provider,
      "app",
      client_secret = "",
      redirect_uri = "https://app.example/callback",
      scopes = c("read", "openid", identity_scope),
      required_scopes = identity_scope,
      token_targets = list(api = list(resource = "urn:api", scopes = "read"))
    )
    sent <- list()
    response_scopes <- paste(client@scopes, collapse = " ")
    local_mocked_bindings(req_with_retry = function(req, ...) {
      sent[[length(sent) + 1L]] <<- lapply(
        req[["body"]][["data"]],
        function(value) {
          utils::URLdecode(gsub("+", " ", as.character(value), fixed = TRUE))
        }
      )
      httr2::response(
        req[["url"]],
        status = 200L,
        headers = list("content-type" = "application/json"),
        body = charToRaw(jsonlite::toJSON(
          list(
            access_token = "access",
            refresh_token = "refresh",
            token_type = "Bearer",
            expires_in = 3600,
            scope = response_scopes
          ),
          auto_unbox = TRUE
        ))
      )
    })
    browser <- valid_browser_token()
    url <- prepare_call(client, browser)
    expect_setequal(
      normalize_scope_tokens(parse_query_param(url, "scope", decode = TRUE)),
      client@scopes
    )
    token <- handle_callback(
      client,
      "code",
      parse_query_param(url, "state"),
      browser
    )
    fresh <- refresh_token(client, token)
    expect_setequal(fresh@granted_scopes, client@scopes)
    expect_length(sent, 2L)
    for (request in sent) {
      expect_identical(request[["resource"]], "urn:api")
      expect_setequal(normalize_scope_tokens(request[["scope"]]), client@scopes)
    }
    bundle <- token_target_bundle_decode(
      client,
      token_target_bundle_encode(token_target_bundle(client, fresh))
    )
    expect_setequal(bundle[["limits"]][["api"]], client@scopes)
    expect_error(
      token_target_request(client, scopes = c("read", "openid")),
      class = "shinyOAuth_access_error"
    )
    # OIDC classification does not authorize an undeclared identity scope.
    response_scopes <- "read openid phone address"
    expect_error(refresh_token(client, fresh), class = "shinyOAuth_token_error")
    client@required_scopes <- character()
    request <- token_target_request(client, scopes = "read")
    expect_identical(request[["scopes"]], "read")
    expect_error(
      validate_token_target_grant(client, c("read", identity_scope), request),
      class = "shinyOAuth_token_error"
    )
  }
})

test_that("Microsoft keeps its supported OIDC set separate from API permission names", {
  provider <- make_test_provider()
  provider@token_target_mode <- "microsoft"
  client <- oauth_client(
    provider,
    "app",
    client_secret = "",
    redirect_uri = "https://app.example/callback",
    scopes = c("openid", "email", "api://example/.default"),
    token_targets = list(
      api = list(resource = "api://example", scopes = "api://example/.default")
    )
  )
  request <- token_target_request(client)
  response <- token_target_response(
    client,
    list(scope = "openid email phone address"),
    request
  )
  expected <- c(
    "openid",
    "email",
    "api://example/phone",
    "api://example/address"
  )
  expect_setequal(normalize_scope_tokens(response[["scope"]]), expected)
  expect_no_error(validate_token_target_grant(client, expected, request))
  expect_error(
    validate_token_target_grant(client, c("openid", "phone"), request),
    class = "shinyOAuth_token_error"
  )
})
