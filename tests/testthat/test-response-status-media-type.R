test_that("revocation requires 200 and never claims another status revoked a token", {
  client <- make_test_client()
  client@provider@revocation_url <- "https://example.com/revoke"
  token <- OAuthToken(access_token = "opaque")
  for (status in c(200L, 201L, 202L, 204L, 299L)) {
    local_mocked_bindings(req_with_retry = function(...) {
      httr2::response(status = status, body = raw())
    })
    result <- revoke_token(client, token, which = "access")
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
    result <- introspect_token(client, token, which = "access")
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
