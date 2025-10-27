testthat::test_that("jwks_host_allow_only accepts host or URL forms identically", {
  # Common issuer and matching JWKS URI
  iss <- "https://issuer.example.com"
  jwks_uri <- "https://www.googleapis.com/oauth2/v3/certs"

  # Provider pinned with bare host
  prov_host <- shinyOAuth::oauth_provider(
    name = "test-host",
    auth_url = "https://auth.example.com/auth",
    token_url = "https://auth.example.com/token",
    issuer = iss,
    jwks_host_allow_only = "www.googleapis.com"
  )
  expect_silent(
    shinyOAuth:::validate_jwks_host_matches_issuer(
      issuer = iss,
      jwks_uri = jwks_uri,
      provider = prov_host
    )
  )

  # Provider pinned with full URL (should normalize to host-only)
  prov_url <- shinyOAuth::oauth_provider(
    name = "test-url",
    auth_url = "https://auth.example.com/auth",
    token_url = "https://auth.example.com/token",
    issuer = iss,
    jwks_host_allow_only = "https://www.googleapis.com"
  )
  expect_silent(
    shinyOAuth:::validate_jwks_host_matches_issuer(
      issuer = iss,
      jwks_uri = jwks_uri,
      provider = prov_url
    )
  )

  # Negative control: different host should be rejected
  prov_bad <- shinyOAuth::oauth_provider(
    name = "test-bad",
    auth_url = "https://auth.example.com/auth",
    token_url = "https://auth.example.com/token",
    issuer = iss,
    jwks_host_allow_only = "www.google.com"
  )
  testthat::expect_error(
    shinyOAuth:::validate_jwks_host_matches_issuer(
      issuer = iss,
      jwks_uri = jwks_uri,
      provider = prov_bad
    ),
    class = "shinyOAuth_config_error"
  )
})
