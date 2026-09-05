test_that("trusted introspection deadlines constrain local authentication", {
  client <- make_test_client(use_nonce = FALSE)
  now <- as.numeric(Sys.time())
  token <- OAuthToken(
    access_token = "opaque",
    token_type = "Bearer",
    expires_at = now + 3600
  )
  enforce <- function(raw, missing = FALSE) {
    enforce_token_introspection_policy(
      client,
      token,
      list(supported = TRUE, active = TRUE, raw = raw),
      expires_in_missing = missing
    )
  }
  expect_equal(enforce(list())@expires_at, token@expires_at)
  expect_equal(enforce(list(exp = now + 30))@expires_at, now + 30)
  expect_equal(enforce(list(exp = now + 7200))@expires_at, now + 3600)
  expect_equal(enforce(list(exp = now + 7200), TRUE)@expires_at, now + 7200)
  for (exp in list(NULL, "123", TRUE, NA_real_, Inf, c(1, 2), list(1))) {
    expect_error(enforce(list(exp = exp)), "finite numeric timestamp")
  }
  expect_error(enforce(list(exp = now - 1)), "already elapsed")
})
