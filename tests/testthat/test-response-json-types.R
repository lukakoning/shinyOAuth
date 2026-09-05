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
