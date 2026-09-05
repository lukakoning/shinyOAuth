test_that("token JSON preserves singleton arrays until scalar validation", {
  for (field in c("access_token", "refresh_token", "id_token", "token_type", "expires_in", "scope")) {
    body <- paste0('{"', field, '":[', if (field == "expires_in") "60" else '"value"', ']}')
    for (content_type in c("application/json", "text/plain")) {
      resp <- httr2::response(status_code = 200L,
        headers = list("Content-Type" = content_type), body = charToRaw(body))
      expect_error(shinyOAuth:::parse_token_response(resp), "JSON scalar")
    }
  }
})

test_that("OIDC UserInfo validates JSON scalars before normalizing profile arrays", {
  cli <- make_test_client(use_nonce = FALSE)
  cli@provider@issuer <- "https://example.com"
  cli@provider@userinfo_url <- "https://example.com/userinfo"
  body <- '{}'
  testthat::local_mocked_bindings(
    req_with_retry = function(...) httr2::response(status_code = 200L,
      headers = list("Content-Type" = "application/json"), body = charToRaw(body)),
    .package = "shinyOAuth"
  )
  for (body in c('{"sub":["user"]}', '{"sub":"user","email_verified":[true]}',
                 '{"sub":"user","phone_number_verified":[true]}')) {
    expect_error(get_userinfo(cli, "token"), class = "shinyOAuth_userinfo_error")
  }
  body <- '{"sub":"user","email_verified":true,"groups":["staff","reviewers"]}'
  ui <- get_userinfo(cli, "token")
  expect_identical(ui$sub, "user")
  expect_true(ui$email_verified)
  expect_identical(ui$groups, c("staff", "reviewers"))
})
test_that("malformed wire scopes never become verified grants", {
  cli <- make_test_client(use_nonce = FALSE)
  cli@provider@introspection_url <- "https://example.com/introspect"
  cli@introspect <- TRUE
  cli@introspect_elements <- "scope"
  cli@scope_validation <- "strict"
  cli@scopes <- c("read", "write")
  for (wire in c('"read\\twrite"', '"read\\nwrite"', '"read  write"',
      '" read"', '"read "', '"read\\\\write"', '"read\\\"write"',
      '"r\\u00e9ad"', '{"a":"read","b":"write"}', '["read"]',
      'true', '123', 'null')) {
    resp <- httr2::response(status_code = 200L,
      headers = list("Content-Type" = "application/json"),
      body = charToRaw(paste0('{"scope":', wire, '}')))
    expect_error(shinyOAuth:::parse_token_response(resp), "scope")
    intro <- list(supported = TRUE, active = TRUE, status = "ok",
      raw = jsonlite::fromJSON(paste0('{"active":true,"scope":', wire, '}'),
        simplifyVector = FALSE))
    token <- OAuthToken(access_token = "synthetic", token_type = "Bearer")
    expect_error(shinyOAuth:::enforce_token_introspection_policy(cli, token, intro),
      "scope")
    expect_false(token@granted_scopes_verified)
  }
  expect_identical(shinyOAuth:::resolve_granted_scope_state("read write",
    c("read", "write"))$granted_scopes, c("read", "write"))
  expect_identical(shinyOAuth:::as_scope_tokens(list("read\twrite")), c("read", "write"))
})
