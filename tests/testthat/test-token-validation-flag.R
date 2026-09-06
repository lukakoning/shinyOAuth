test_that("raw tokens require a scalar ID-token validation flag", {
  for (value in list(NA, logical(), c(TRUE, FALSE))) {
    expect_error(
      OAuthToken(access_token = "opaque", id_token_validated = value),
      "id_token_validated must be a single non-NA logical"
    )
  }
  expect_false(OAuthToken(access_token = "opaque")@id_token_validated)
  expect_error(
    OAuthToken(access_token = "opaque", id_token_validated = TRUE),
    "requires a non-empty id_token"
  )
})
