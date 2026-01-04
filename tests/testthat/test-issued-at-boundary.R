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

  # Future within default leeway (30s) should pass (now + 1 is within leeway)
  within_leeway <- base
  within_leeway$issued_at <- now + 1.0
  expect_silent(shinyOAuth:::payload_verify_issued_at(cli, within_leeway))
})

test_that("issued_at future check respects leeway", {
  # Use a small leeway to test the boundary precisely
  cli <- make_test_client(state_max_age = 600, state_payload_max_age = 300)
  cli@provider@leeway <- 5

  now <- as.numeric(Sys.time())
  base <- list(
    state = "s",
    client_id = cli@client_id,
    redirect_uri = cli@redirect_uri,
    scopes = cli@scopes,
    provider = shinyOAuth:::provider_fingerprint(cli@provider),
    issued_at = now
  )

  # issued_at at now should pass
  expect_silent(shinyOAuth:::payload_verify_issued_at(cli, base))

  # issued_at in future within leeway (now + 4s with 5s leeway) should pass
  within_leeway <- base
  within_leeway$issued_at <- now + 4
  expect_silent(shinyOAuth:::payload_verify_issued_at(cli, within_leeway))

  # issued_at exactly at leeway boundary (now + 5s with 5s leeway) should pass
  at_boundary <- base
  at_boundary$issued_at <- now + 5
  expect_silent(shinyOAuth:::payload_verify_issued_at(cli, at_boundary))

  # issued_at beyond leeway (now + 10s with 5s leeway) should fail
  beyond_leeway <- base
  beyond_leeway$issued_at <- now + 10
  expect_error(
    shinyOAuth:::payload_verify_issued_at(cli, beyond_leeway),
    class = "shinyOAuth_state_error",
    regexp = "future"
  )
})
