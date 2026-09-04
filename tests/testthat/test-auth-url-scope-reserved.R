test_that("OAuthProvider rejects scope in extra_auth_params (prevents scope desync)", {
  expect_error(
    oauth_provider(
      name = "test",
      auth_url = "https://example.com/authorize",
      token_url = "https://example.com/token",
      extra_auth_params = list(scope = "user-read-email")
    ),
    regexp = "extra_auth_params must not contain reserved keys|scope"
  )
})

test_that("authorization parameters encode percent escapes as literal data", {
  client <- make_test_client()
  client@provider@extra_auth_params <- list(
    login_hint = "victim%40example.com&prompt=none&state=attacker"
  )

  auth_url <- shinyOAuth:::prepare_call(client, valid_browser_token())
  query <- sub("^[^?]*\\?", "", auth_url)
  fields <- strsplit(query, "&", fixed = TRUE)[[1]]
  names <- vapply(strsplit(fields, "=", fixed = TRUE), `[[`, "", 1L)
  login_hint <- fields[startsWith(fields, "login_hint=")]

  expect_identical(sum(names == "login_hint"), 1L)
  expect_identical(sum(names == "prompt"), 0L)
  expect_identical(sum(names == "state"), 1L)
  expect_identical(
    utils::URLdecode(sub("^[^=]*=", "", login_hint)),
    "victim%40example.com&prompt=none&state=attacker"
  )
})
