test_that("issued_at boundary behavior around max_age", {
  cli <- make_test_client(state_max_age = 600, state_payload_max_age = 2)
  fixed_now <- as.POSIXct(1700000000, origin = "1970-01-01", tz = "UTC")
  local_mocked_bindings(Sys.time = function() fixed_now, .package = "base")

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
  just_under[["issued_at"]] <- now - 1.875
  expect_silent(shinyOAuth:::payload_verify_issued_at(cli, just_under))

  at_boundary <- base
  at_boundary[["issued_at"]] <- now - 2
  expect_silent(shinyOAuth:::payload_verify_issued_at(cli, at_boundary))

  # Just over max_age should fail
  just_over <- base
  just_over[["issued_at"]] <- now - 2.125
  expect_error(
    shinyOAuth:::payload_verify_issued_at(cli, just_over),
    class = "shinyOAuth_state_error",
    regexp = "too old"
  )

  # Future within default leeway (30s) should pass (now + 1 is within leeway)
  within_leeway <- base
  within_leeway[["issued_at"]] <- now + 1.0
  expect_silent(shinyOAuth:::payload_verify_issued_at(cli, within_leeway))
})

test_that("issued_at future check respects leeway", {
  cli <- make_test_client(state_max_age = 600, state_payload_max_age = 300)
  cli@provider@leeway <- 5
  fixed_now <- as.POSIXct(1700000000, origin = "1970-01-01", tz = "UTC")
  local_mocked_bindings(Sys.time = function() fixed_now, .package = "base")

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

  # issued_at just inside the future leeway should pass
  within_leeway <- base
  within_leeway[["issued_at"]] <- now + 4.875
  expect_silent(shinyOAuth:::payload_verify_issued_at(cli, within_leeway))

  # issued_at exactly at leeway boundary (now + 5s with 5s leeway) should pass
  at_boundary <- base
  at_boundary[["issued_at"]] <- now + 5
  expect_silent(shinyOAuth:::payload_verify_issued_at(cli, at_boundary))

  # issued_at just beyond leeway should fail
  beyond_leeway <- base
  beyond_leeway[["issued_at"]] <- now + 5.125
  expect_error(
    shinyOAuth:::payload_verify_issued_at(cli, beyond_leeway),
    class = "shinyOAuth_state_error",
    regexp = "future"
  )
})
