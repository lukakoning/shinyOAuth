testthat::test_that("OAuthProvider validation rejects unknown token_auth_style", {
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  testthat::expect_error({
    cli@provider@token_auth_style <- "unknown-style"
  })
})
