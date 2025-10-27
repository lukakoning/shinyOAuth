test_that("OAuthClient accepts raw state_key and seals state", {
  # Allow skipping strict browser token check during this unit test
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))
  prov <- oauth_provider_github()
  raw_key <- as.raw(sample(0:255, 40, replace = TRUE)) # >= 32 bytes

  cli <- oauth_client(
    provider = prov,
    client_id = "id",
    client_secret = "secret",
    redirect_uri = "http://localhost:8100",
    scopes = character(),
    state_store = cachem::cache_mem(max_age = 60),
    state_entropy = 32,
    state_key = raw_key
  )

  # Prepare a call to exercise sealing path; requires a browser token
  url <- prepare_call(cli, browser_token = "__SKIPPED__")
  expect_true(is_valid_string(url))

  # Extract state from URL and try decrypting with same key to ensure roundtrip
  qs <- httr2::url_parse(url)$query
  st <- qs[["state"]]
  expect_true(is_valid_string(st))
  p <- state_decrypt_gcm(st, key = raw_key)
  expect_true(is.list(p) && is_valid_string(p$state))
})
