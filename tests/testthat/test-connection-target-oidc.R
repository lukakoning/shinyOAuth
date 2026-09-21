oidc_target_client <- function(required = character()) {
  provider <- make_test_provider()
  provider@token_target_mode <- "rfc8707"
  oauth_client(
    provider,
    "app",
    client_secret = "",
    redirect_uri = "https://app.example/callback",
    scopes = c("read", "write", "openid", "profile", "email", "offline_access"),
    required_scopes = required,
    token_targets = list(
      api = list(resource = "urn:api", scopes = c("read", "write"))
    )
  )
}

test_that("optional OIDC permissions remain narrowed on the wire and in stored policy", {
  local_options(shinyOAuth.skip_browser_token = FALSE)
  client <- oidc_target_client()
  initial <- OAuthToken(
    access_token = "initial",
    refresh_token = "refresh",
    token_type = "Bearer",
    expires_at = as.numeric(Sys.time()) + 3600,
    granted_scopes = client@scopes,
    granted_scopes_verified = TRUE
  )
  bundle <- token_target_bundle(client, initial)
  scopes <- c("read", "openid")
  request <- token_target_request(
    client,
    limits = bundle[["limits"]],
    scopes = scopes
  )
  requests <- list()
  response_scopes <- paste(scopes, collapse = " ")
  local_mocked_bindings(req_with_retry = function(req, ...) {
    requests[[length(requests) + 1L]] <<- utils::URLdecode(req[["body"]][[
      "data"
    ]][["scope"]])
    body <- list(
      access_token = "fresh",
      refresh_token = "rotated",
      token_type = "Bearer",
      expires_in = 3600
    )
    if (!is.null(response_scopes)) {
      body[["scope"]] <- response_scopes
    }
    httr2::response(
      req[["url"]],
      status = 200L,
      headers = list("content-type" = "application/json"),
      body = charToRaw(jsonlite::toJSON(body, auto_unbox = TRUE))
    )
  })
  fresh <- refresh_token_dispatch(client, initial, target_request = request)
  expect_setequal(fresh@granted_scopes, scopes)
  committed <- token_target_commit(client, initial, bundle, fresh, request)
  restored <- token_target_bundle_decode(
    client,
    token_target_bundle_encode(committed[["targets"]])
  )
  expect_setequal(restored[["limits"]][["api"]], scopes)
  expect_setequal(
    token_target_request(client, limits = restored[["limits"]])[["scopes"]],
    scopes
  )
  for (removed in c("profile", "email", "offline_access")) {
    expect_error(
      token_target_request(
        client,
        limits = restored[["limits"]],
        scopes = c(scopes, removed)
      ),
      class = "shinyOAuth_access_error"
    )
    response_scopes <- paste(c(scopes, removed), collapse = " ")
    expect_error(refresh_token(client, fresh), class = "shinyOAuth_token_error")
  }
  # Missing response scope inherits only the reduced request, never configuration.
  response_scopes <- NULL
  again <- refresh_token(client, fresh)
  expect_setequal(again@granted_scopes, scopes)
  for (sent in requests) {
    expect_setequal(
      normalize_scope_tokens(gsub("+", " ", sent, fixed = TRUE)),
      scopes
    )
  }
  browser <- valid_browser_token()
  url <- prepare_call_internal(
    client,
    browser,
    .requested_scopes = token_target_authorization_scopes(
      client,
      restored[["limits"]]
    ),
    .target_limits = restored[["limits"]]
  )
  expect_setequal(
    normalize_scope_tokens(parse_query_param(url, "scope", decode = TRUE)),
    scopes
  )
  payload <- state_payload_decrypt_validate(
    client,
    parse_query_param(url, "state")
  )
  expect_setequal(
    connection_data_decode(payload[["target_limits"]])[["api"]],
    scopes
  )
})

test_that("required OIDC scopes cannot be removed and ungranted optional scopes stay absent", {
  client <- oidc_target_client("email")
  expect_error(
    token_target_request(client, scopes = c("read", "openid")),
    class = "shinyOAuth_access_error"
  )
  expect_setequal(
    token_target_request(client, scopes = c("read", "email"))[["scopes"]],
    c("read", "email")
  )
  initial <- OAuthToken(
    access_token = "initial",
    refresh_token = "refresh",
    token_type = "Bearer",
    expires_at = as.numeric(Sys.time()) + 3600,
    granted_scopes = c("read", "email"),
    granted_scopes_verified = TRUE
  )
  bundle <- token_target_bundle(client, initial)
  expect_setequal(
    token_target_request(client, limits = bundle[["limits"]])[["scopes"]],
    c("read", "email")
  )
})
