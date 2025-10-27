test_that("prepare_call builds URL with correct params and drops NULLs", {
  # With PKCE and nonce
  cli <- make_test_client(use_pkce = TRUE, use_nonce = TRUE)
  tok <- valid_browser_token()
  url <- shinyOAuth:::prepare_call(cli, browser_token = tok)
  expect_match(url, ".*code_challenge=", perl = TRUE)
  expect_match(url, ".*code_challenge_method=S256", perl = TRUE)
  expect_match(url, ".*nonce=", perl = TRUE)
  expect_match(url, ".*state=", perl = TRUE)

  # Without nonce
  cli2 <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  url2 <- shinyOAuth:::prepare_call(cli2, browser_token = tok)
  expect_false(grepl("[?&]nonce=", url2))
})
