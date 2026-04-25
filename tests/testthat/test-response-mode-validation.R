test_that("OAuthProvider only allows query response_mode", {
  expect_error(
    OAuthProvider(
      name = "test",
      auth_url = "https://example.com/authorize",
      token_url = "https://example.com/token",
      extra_auth_params = list(response_mode = "form_post")
    ),
    regexp = "response_mode.*query.*POST form callbacks"
  )

  expect_error(
    OAuthProvider(
      name = "test",
      auth_url = "https://example.com/authorize",
      token_url = "https://example.com/token",
      extra_auth_params = list(response_mode = "fragment")
    ),
    regexp = "response_mode"
  )

  expect_no_error(OAuthProvider(
    name = "test",
    auth_url = "https://example.com/authorize",
    token_url = "https://example.com/token",
    extra_auth_params = list(response_mode = "query")
  ))

  expect_no_error(OAuthProvider(
    name = "test",
    auth_url = "https://example.com/authorize",
    token_url = "https://example.com/token",
    extra_auth_params = list(response_mode = " Query ")
  ))
})

test_that("prepare_call normalizes explicit query response_mode", {
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  cli@provider@extra_auth_params <- list(
    response_mode = " Query ",
    prompt = "login"
  )

  url <- shinyOAuth:::prepare_call(cli, browser_token = valid_browser_token())

  expect_identical(
    parse_query_param(url, "response_mode", decode = TRUE),
    "query"
  )
  expect_identical(parse_query_param(url, "prompt", decode = TRUE), "login")
})
