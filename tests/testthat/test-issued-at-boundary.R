test_that("issued_at boundary behavior around max_age", {
  # Small max_age to keep tests fast and deterministic
  cli <- make_test_client(state_max_age = 600, state_payload_max_age = 2)

  now <- as.numeric(Sys.time())
  base <- list(
    state = "s",
    client_id = cli@client_id,
    redirect_uri = cli@redirect_uri,
    scopes = cli@scopes,
    provider = shinyOAuth:::provider_fingerprint(cli@provider),
    issued_at = now
  )

  # Exactly at now should pass
  expect_silent(shinyOAuth:::payload_verify_issued_at(cli, base))

  # Just under max_age should pass
  just_under <- base
  just_under$issued_at <- now - 1.9
  expect_silent(shinyOAuth:::payload_verify_issued_at(cli, just_under))

  # Just over max_age should fail
  just_over <- base
  just_over$issued_at <- now - 2.1
  expect_error(
    shinyOAuth:::payload_verify_issued_at(cli, just_over),
    class = "shinyOAuth_state_error",
    regexp = "too old"
  )

  # Future by a tiny epsilon should fail consistently
  tiny_future <- base
  tiny_future$issued_at <- now + 1.0
  expect_error(
    shinyOAuth:::payload_verify_issued_at(cli, tiny_future),
    class = "shinyOAuth_state_error",
    regexp = "future"
  )
})
