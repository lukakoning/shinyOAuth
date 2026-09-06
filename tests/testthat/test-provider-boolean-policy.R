test_that("provider policy flags reject malformed values before normalization", {
  args <- list(name = "test", auth_url = "https://example.test/auth",
               token_url = "https://example.test/token")
  for (field in oauth_provider_boolean_fields()) {
    for (value in list(NA, logical(), c(TRUE, FALSE), "false", 0)) {
      input <- args
      input[[field]] <- value
      expect_error(do.call(oauth_provider, input), "single non-NA logical")
      expect_error(do.call(OAuthProvider, input))
    }
  }
  provider <- do.call(oauth_provider, args)
  for (field in oauth_provider_boolean_fields()) {
    expect_error(S7::prop(provider, field) <- NA, "single non-NA logical")
  }
  expect_true(provider@use_pkce)
  expect_false(provider@use_nonce)
})
