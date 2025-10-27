test_that("NA optional fields yield clean validator errors", {
  prov_base <- list(
    name = "ex",
    auth_url = "https://example.com/auth",
    token_url = "https://example.com/token",
    userinfo_url = "https://example.com/userinfo",
    issuer = "https://example.com"
  )

  # token_auth_style = NA -> targeted error (not base NA if)
  expect_error(
    do.call(
      oauth_provider,
      c(prov_base, list(token_auth_style = NA_character_))
    ),
    regexp = "token_auth_style must be one of 'header', 'body', 'client_secret_jwt', or 'private_key_jwt'"
  )

  # jwks_pin_mode = NA -> targeted error
  expect_error(
    do.call(oauth_provider, c(prov_base, list(jwks_pin_mode = NA_character_))),
    regexp = "jwks_pin_mode must be 'any' or 'all'"
  )

  # pkce_method = NA -> no error; normalizes to S256
  prov <- do.call(
    oauth_provider,
    c(prov_base, list(pkce_method = NA_character_))
  )
  expect_s3_class(prov, "S7_object")
  expect_identical(prov@pkce_method, "S256")
})
