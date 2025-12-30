test_that("issued_at freshness window is independent of state store TTL", {
  # Long server-side state store TTL
  cli <- make_test_client(state_max_age = 3600)

  expect_equal(shinyOAuth:::client_state_store_max_age(cli), 3600)
  # Default payload freshness is intentionally shorter (300s)
  expect_equal(shinyOAuth:::client_state_payload_max_age(cli), 300)

  now <- as.numeric(Sys.time())
  p <- list(
    state = "s",
    client_id = cli@client_id,
    redirect_uri = cli@redirect_uri,
    scopes = cli@scopes,
    provider = shinyOAuth:::provider_fingerprint(cli@provider),
    issued_at = now - 301
  )

  expect_error(
    shinyOAuth:::payload_verify_issued_at(cli, p),
    class = "shinyOAuth_state_error",
    regexp = "too old"
  )
})
