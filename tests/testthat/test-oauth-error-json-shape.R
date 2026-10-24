test_that("only unambiguous scalar OAuth errors affect refresh outcomes", {
  client <- make_test_client(use_nonce = FALSE)
  previous <- OAuthToken(
    access_token = "previous",
    refresh_token = "previous-refresh"
  )
  body <- NULL
  local_mocked_bindings(
    req_with_retry = function(...) {
      httr2::response(
        url = client@provider@token_url,
        status = 400L,
        headers = list("content-type" = "application/json"),
        body = charToRaw(body)
      )
    },
    .package = "shinyOAuth"
  )
  malformed <- c(
    '{"error":["invalid_scope"]}',
    '{"error":["invalid_grant"]}',
    '{"error":{"value":"invalid_scope"}}',
    '{"error":123}',
    '{"error":true}',
    '{"error":null}',
    '{"error":""}',
    '{"error":"invalid_scope","error":"invalid_grant"}',
    '{"error":"invalid_grant","error":"invalid_scope"}',
    '{"error":"invalid_scope","err\\u006fr":"invalid_grant"}',
    '{"error":"invalid_scope","extension":{"a":1,"a":2}}',
    '[{"error":"invalid_scope"}]',
    '"invalid_scope"',
    'null',
    '{"error":"invalid_scope"',
    paste0(
      '{"error":"invalid_scope","extension":',
      strrep('[', 65L),
      '0',
      strrep(']', 65L),
      '}'
    )
  )
  for (body in malformed) {
    error <- tryCatch(refresh_token(client, previous), error = identity)
    expect_s3_class(error, "shinyOAuth_http_error")
    expect_identical(error[["status"]], 400L, info = body)
    expect_null(error[["oauth_error"]])
    expect_identical(
      error[["refresh_credential_outcome"]],
      "possibly_consumed",
      info = body
    )
  }
  for (code in c("invalid_scope", "invalid_grant", "temporarily_unavailable")) {
    # Unrelated extension arrays remain legal and must not obscure a valid code.
    body <- paste0('{"error":"', code, '","extension":[1,2]}')
    error <- tryCatch(refresh_token(client, previous), error = identity)
    expect_identical(error[["oauth_error"]], code)
    expect_identical(
      error[["refresh_credential_outcome"]],
      if (code == "invalid_grant") "rejected" else "not_consumed"
    )
  }
})

test_that("array-shaped optional error fields are not exposed as scalar diagnostics", {
  local_options(shinyOAuth.expose_error_body = TRUE)
  response <- httr2::response(
    status = 400L,
    headers = list("content-type" = "application/json"),
    body = charToRaw(paste0(
      '{"error":"invalid_scope","error_description":["description"],',
      '"error_uri":["https://example.com/help"]}'
    ))
  )
  error <- tryCatch(
    err_http("Token request failed", response),
    error = identity
  )
  expect_identical(error[["oauth_error"]], "invalid_scope")
  expect_null(error[["oauth_error_description"]])
  expect_null(error[["oauth_error_uri"]])
})

test_that("module retires refresh credentials after malformed endpoint errors", {
  local_options(shinyOAuth.skip_browser_token = TRUE)
  client <- make_test_client(use_nonce = FALSE)
  body <- NULL
  local_mocked_bindings(
    req_with_retry = function(...) {
      httr2::response(
        url = client@provider@token_url,
        status = 400L,
        headers = list("content-type" = "application/json"),
        body = charToRaw(body)
      )
    },
    .package = "shinyOAuth"
  )
  for (body in c(
    '{"error":["invalid_scope"]}',
    '{"error":"invalid_scope","error":"invalid_grant"}'
  )) {
    shiny::testServer(
      oauth_module_server,
      args = list(
        id = "auth",
        client = client,
        auto_redirect = FALSE,
        indefinite_session = TRUE,
        refresh_proactively = TRUE
      ),
      {
        values[["token"]] <- OAuthToken(
          access_token = "previous",
          refresh_token = "previous-refresh",
          expires_at = as.numeric(Sys.time()) + 30
        )
        session[["flushReact"]]()
        expect_identical(values[["token"]]@access_token, "previous")
        expect_identical(values[["token"]]@refresh_token, NA_character_)
        expect_true(values[["token_stale"]])
      }
    )
  }
})
