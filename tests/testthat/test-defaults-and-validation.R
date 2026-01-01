test_that("OAuthClient state_entropy fails fast on NA and non-scalar", {
  prov <- oauth_provider(
    name = "ex",
    auth_url = "https://example.com/auth",
    token_url = "https://example.com/token",
    userinfo_url = NA_character_,
    issuer = NA_character_,
    # Form-body + PKCE allows empty client_secret during validation
    token_auth_style = "body",
    use_pkce = TRUE
  )

  # NA should error
  expect_error(
    oauth_client(
      provider = prov,
      client_id = "id",
      client_secret = "",
      redirect_uri = "https://app.example.com/callback",
      state_entropy = NA_integer_
    ),
    regexp = "state_entropy"
  )

  # Vector should error deterministically (no 'condition length > 1' warnings)
  expect_error(
    oauth_client(
      provider = prov,
      client_id = "id",
      client_secret = "",
      redirect_uri = "https://app.example.com/callback",
      state_entropy = c(64, 128)
    ),
    regexp = "state_entropy"
  )
})

test_that("OAuthProvider default jwks_host_issuer_match is FALSE", {
  p <- OAuthProvider(
    name = "t",
    auth_url = "https://example.com/authorize",
    token_url = "https://example.com/token"
  )
  expect_identical(p@jwks_host_issuer_match, FALSE)
})

test_that("OAuthProvider HS* algs require allow_hs opt-in", {
  base_args <- list(
    name = "t",
    auth_url = "https://example.com/auth",
    token_url = "https://example.com/token",
    issuer = "https://issuer.example.com",
    id_token_validation = TRUE,
    id_token_required = TRUE,
    allowed_algs = c("HS256")
  )

  withr::with_options(list(shinyOAuth.allow_hs = FALSE), {
    expect_error(
      do.call(oauth_provider, base_args),
      regexp = "allow_hs|HS\\*",
      fixed = FALSE
    )
  })

  withr::with_options(list(shinyOAuth.allow_hs = TRUE), {
    expect_no_error(do.call(oauth_provider, base_args))
  })
})

test_that("oauth_provider_microsoft defaults are compatible with multi-tenant aliases", {
  p <- oauth_provider_microsoft(tenant = "common")

  # Multi-tenant issuer varies by signing tenant; default disables validation.
  expect_true(is.na(p@issuer))
  expect_identical(p@id_token_validation, FALSE)
  expect_identical(p@id_token_required, FALSE)
  expect_identical(p@use_nonce, FALSE)
  expect_identical(p@allowed_algs, c("RS256"))
})

test_that("oauth_provider_microsoft enables issuer+nonce for GUID tenant", {
  tenant_guid <- "00000000-0000-0000-0000-000000000000"
  p <- oauth_provider_microsoft(tenant = tenant_guid)

  expect_true(is.character(p@issuer) && nzchar(p@issuer))
  expect_match(p@issuer, tenant_guid, fixed = TRUE)

  expect_identical(p@id_token_validation, TRUE)
  expect_identical(p@id_token_required, TRUE)
  expect_identical(p@use_nonce, TRUE)
  expect_identical(p@allowed_algs, c("RS256"))
})
