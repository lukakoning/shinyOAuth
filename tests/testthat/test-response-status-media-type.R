for (form in c(FALSE, TRUE)) {
  test_that(paste("token exchange and refresh require HTTP 200", form), {
    client <- make_test_client(scopes = character(), use_nonce = FALSE)
    previous <- OAuthToken(
      access_token = "previous",
      refresh_token = "previous-refresh"
    )
    status <- 200L
    attempts <- 0L
    parse_calls <- 0L
    original_parser <- parse_token_response
    local_mocked_bindings(
      req_with_dpop_retry = function(req, ..., idempotent = TRUE) {
        expect_false(idempotent)
        attempts <<- attempts + 1L
        httr2::response(
          url = req[["url"]],
          status = status,
          headers = list(
            "content-type" = if (form) {
              "application/x-www-form-urlencoded"
            } else {
              "application/json"
            }
          ),
          body = charToRaw(
            if (form) {
              "access_token=replacement&token_type=Bearer&refresh_token=replacement-refresh&expires_in=3600"
            } else {
              '{"access_token":"replacement","token_type":"Bearer","refresh_token":"replacement-refresh","expires_in":3600}'
            }
          )
        )
      },
      parse_token_response = function(...) {
        parse_calls <<- parse_calls + 1L
        original_parser(...)
      }
    )
    for (status in c(200L, 201L, 202L, 204L, 299L, 304L)) {
      attempts <- 0L
      parse_calls <- 0L
      exchange <- tryCatch(
        swap_code_for_token_set(client, "synthetic-code", strrep("x", 43)),
        error = identity
      )
      refreshed <- tryCatch(refresh_token(client, previous), error = identity)
      expect_identical(attempts, 2L)
      if (status == 200L) {
        expect_identical(exchange[["access_token"]], "replacement")
        expect_identical(refreshed@access_token, "replacement")
        expect_identical(parse_calls, 2L)
      } else {
        expect_s3_class(exchange, "shinyOAuth_http_error")
        expect_s3_class(refreshed, "shinyOAuth_http_error")
        expect_identical(
          refreshed[["refresh_credential_outcome"]],
          "possibly_consumed"
        )
        expect_identical(parse_calls, 0L)
      }
      expect_identical(previous@access_token, "previous")
      expect_identical(previous@refresh_token, "previous-refresh")
    }
  })
}

test_that("revocation requires 200 and never claims another status revoked a token", {
  client <- make_test_client()
  client@provider@revocation_url <- "https://example.com/revoke"
  token <- OAuthToken(access_token = "opaque")
  for (status in c(200L, 201L, 202L, 204L, 299L)) {
    local_mocked_bindings(req_with_retry = function(...) {
      httr2::response(status = status, body = raw())
    })
    result <- revoke_token(client, token, token_kind = "access")
    if (status == 200L) {
      expect_true(result[["revoked"]])
    } else {
      expect_true(is.na(result[["revoked"]]))
      expect_identical(result[["status"]], paste0("http_", status))
    }
  }
})

test_that("UserInfo and introspection reject JSON under unrelated media types", {
  client <- make_test_client()
  client@provider@introspection_url <- "https://example.com/introspect"
  client@provider@userinfo_url <- "https://example.com/userinfo"
  token <- OAuthToken(access_token = "opaque")
  for (type in c(
    "text/plain",
    "text/html",
    "application/octet-stream",
    "application/jwtx"
  )) {
    response <- httr2::response(
      status = 200,
      headers = list("content-type" = type),
      body = charToRaw('{"active":true,"sub":"test"}')
    )
    local_mocked_bindings(req_with_retry = function(...) response)
    result <- introspect_token(client, token, token_kind = "access")
    expect_true(is.na(result[["active"]]))
    expect_identical(result[["status"]], "invalid_json")
    expect_error(get_userinfo(client, "opaque"))
  }
  for (type in c(
    "application/json",
    "application/json; charset=utf-8",
    "application/vnd.github+json"
  )) {
    expect_true(response_has_json_media_type(httr2::response(
      status = 200,
      headers = list("content-type" = type),
      body = raw()
    )))
  }
})
