# Tests for RFC 6749 §5.2 structured error extraction in err_http()

test_that("err_http extracts RFC 6749 §5.2 error fields from JSON response", {
  resp <- httr2::response(
    url = "https://example.com/token",
    status = 400,
    headers = list("content-type" = "application/json"),
    body = charToRaw(
      '{"error":"invalid_grant","error_description":"The authorization code has expired","error_uri":"https://example.com/docs/errors#invalid_grant"}'
    )
  )

  cond <- tryCatch(
    shinyOAuth:::err_http(
      "Token exchange failed",
      resp,
      context = list(phase = "exchange_code")
    ),
    error = identity
  )

  expect_s3_class(cond, "shinyOAuth_http_error")
  expect_identical(cond$oauth_error, "invalid_grant")
  expect_identical(
    cond$oauth_error_description,
    "The authorization code has expired"
  )
  expect_identical(
    cond$oauth_error_uri,
    "https://example.com/docs/errors#invalid_grant"
  )
  # Message should contain the structured error

  expect_match(conditionMessage(cond), "invalid_grant", fixed = TRUE)
  expect_match(
    conditionMessage(cond),
    "The authorization code has expired",
    fixed = TRUE
  )
  expect_match(
    conditionMessage(cond),
    "https://example.com/docs/errors#invalid_grant",
    fixed = TRUE
  )
})

test_that("err_http extracts error + error_description without error_uri", {
  resp <- httr2::response(
    url = "https://example.com/token",
    status = 401,
    headers = list("content-type" = "application/json"),
    body = charToRaw(
      '{"error":"invalid_client","error_description":"Client authentication failed"}'
    )
  )

  cond <- tryCatch(
    shinyOAuth:::err_http("Token refresh failed", resp),
    error = identity
  )

  expect_identical(cond$oauth_error, "invalid_client")
  expect_identical(
    cond$oauth_error_description,
    "Client authentication failed"
  )
  expect_null(cond$oauth_error_uri)
  expect_match(conditionMessage(cond), "invalid_client", fixed = TRUE)
  expect_match(
    conditionMessage(cond),
    "Client authentication failed",
    fixed = TRUE
  )
})

test_that("err_http extracts error field alone", {
  resp <- httr2::response(
    url = "https://example.com/token",
    status = 400,
    headers = list("content-type" = "application/json"),
    body = charToRaw('{"error":"unsupported_grant_type"}')
  )

  cond <- tryCatch(
    shinyOAuth:::err_http("Token request failed", resp),
    error = identity
  )

  expect_identical(cond$oauth_error, "unsupported_grant_type")
  expect_null(cond$oauth_error_description)
  expect_null(cond$oauth_error_uri)
  expect_match(conditionMessage(cond), "unsupported_grant_type", fixed = TRUE)
})

test_that("err_http does not extract fields from non-JSON error response", {
  resp <- httr2::response(
    url = "https://example.com/token",
    status = 500,
    headers = list("content-type" = "text/html"),
    body = charToRaw("<html><body>Internal Server Error</body></html>")
  )

  cond <- tryCatch(
    shinyOAuth:::err_http("Server error", resp),
    error = identity
  )

  expect_null(cond$oauth_error)
  expect_null(cond$oauth_error_description)
  expect_null(cond$oauth_error_uri)
})

test_that("err_http does not extract fields when JSON has no error field", {
  resp <- httr2::response(
    url = "https://example.com/token",
    status = 400,
    headers = list("content-type" = "application/json"),
    body = charToRaw('{"message":"something went wrong"}')
  )

  cond <- tryCatch(
    shinyOAuth:::err_http("Bad request", resp),
    error = identity
  )

  expect_null(cond$oauth_error)
  expect_null(cond$oauth_error_description)
  expect_null(cond$oauth_error_uri)
})

test_that("err_http propagates RFC 6749 §5.2 fields to trace event", {
  events <- list()
  withr::local_options(list(
    shinyOAuth.trace_hook = function(ev) {
      events[[length(events) + 1]] <<- ev
    }
  ))

  resp <- httr2::response(
    url = "https://example.com/token",
    status = 400,
    headers = list("content-type" = "application/json"),
    body = charToRaw(
      '{"error":"invalid_grant","error_description":"Code expired"}'
    )
  )

  tryCatch(
    shinyOAuth:::err_http(
      "Token exchange failed",
      resp,
      context = list(phase = "exchange_code")
    ),
    error = function(e) NULL
  )

  expect_true(length(events) >= 1)
  ev <- events[[1]]
  expect_identical(ev$oauth_error, "invalid_grant")
  expect_identical(ev$oauth_error_description, "Code expired")
  expect_null(ev$oauth_error_uri)
})

test_that("swap_code_for_token_set surfaces structured error on 400", {
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)

  testthat::local_mocked_bindings(
    req_with_retry = function(req) {
      httr2::response(
        url = as.character(req$url),
        status = 400,
        headers = list("content-type" = "application/json"),
        body = charToRaw(
          '{"error":"invalid_grant","error_description":"Authorization code is invalid or expired"}'
        )
      )
    },
    .package = "shinyOAuth"
  )

  cond <- tryCatch(
    shinyOAuth:::swap_code_for_token_set(cli, "bad_code", "verifier123"),
    error = identity
  )

  expect_s3_class(cond, "shinyOAuth_http_error")
  expect_identical(cond$oauth_error, "invalid_grant")
  expect_identical(
    cond$oauth_error_description,
    "Authorization code is invalid or expired"
  )
})

test_that("refresh_token surfaces structured error on 400", {
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)

  testthat::local_mocked_bindings(
    req_with_retry = function(req) {
      httr2::response(
        url = as.character(req$url),
        status = 400,
        headers = list("content-type" = "application/json"),
        body = charToRaw(
          '{"error":"invalid_grant","error_description":"Refresh token has been revoked"}'
        )
      )
    },
    .package = "shinyOAuth"
  )

  tok <- OAuthToken(
    access_token = "old_at",
    refresh_token = "old_rt",
    expires_at = as.numeric(Sys.time()) + 10,
    id_token = NA_character_
  )

  cond <- tryCatch(
    refresh_token(cli, tok, async = FALSE),
    error = identity
  )

  expect_s3_class(cond, "shinyOAuth_http_error")
  expect_identical(cond$oauth_error, "invalid_grant")
  expect_identical(
    cond$oauth_error_description,
    "Refresh token has been revoked"
  )
})

test_that("err_http ignores non-string error/error_description values", {
  # Some edge cases: error field is a number or array
  resp <- httr2::response(
    url = "https://example.com/token",
    status = 400,
    headers = list("content-type" = "application/json"),
    body = charToRaw('{"error":123,"error_description":["a","b"]}')
  )

  cond <- tryCatch(
    shinyOAuth:::err_http("Bad request", resp),
    error = identity
  )

  # Non-string values should not be extracted
  expect_null(cond$oauth_error)
  expect_null(cond$oauth_error_description)
})
