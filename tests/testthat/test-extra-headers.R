test_that("extra_token_headers must be a named character vector", {
  # Valid
  prov <- oauth_provider_github()
  expect_true(S7::S7_inherits(prov, shinyOAuth::OAuthProvider))

  # Invalid: unnamed character vector
  expect_error(
    prov@extra_token_headers <- c("application/json"),
    regexp = "extra_token_headers.*names|non-empty"
  )

  # Invalid: non-character
  expect_error(
    prov@extra_token_headers <- list(Accept = 1),
    regexp = "named character vector|must be <character>"
  )

  # Invalid: NA value not allowed
  expect_error(
    prov@extra_token_headers <- c(Accept = NA_character_),
    regexp = "non-empty|NA"
  )

  # Invalid: empty value
  expect_error(
    prov@extra_token_headers <- c(Accept = ""),
    regexp = "non-empty"
  )
})
