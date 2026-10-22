test_that("malformed JWKS host pins fail closed at construction and runtime", {
  invalid <- list(
    c("keys.example", "backup.example"),
    42L,
    character(),
    "",
    " ",
    c(NA_character_, NA_character_),
    list("keys.example"),
    "."
  )
  for (pin in invalid) {
    expect_error(
      oauth_provider(
        name = "pin-test",
        auth_url = "https://issuer.example/auth",
        token_url = "https://issuer.example/token",
        jwks_host_allow_only = pin
      ),
      "jwks_host_allow_only",
      class = "shinyOAuth_input_error"
    )
    expect_error(
      validate_jwks_host_matches_issuer(
        "https://issuer.example",
        "https://unexpected.example/keys",
        check_host = FALSE,
        pinned_host = pin
      ),
      "jwks_host_allow_only",
      class = "shinyOAuth_config_error"
    )
  }
  for (pin in list(NULL, NA_character_, NA)) {
    provider <- oauth_provider(
      name = "pin-test",
      auth_url = "https://issuer.example/auth",
      token_url = "https://issuer.example/token",
      jwks_host_allow_only = pin
    )
    expect_identical(provider@jwks_host_allow_only, NA_character_)
  }
})

test_that("normal S7 assignment cannot disable a JWKS pin with malformed input", {
  provider <- oauth_provider(
    name = "pin-test",
    auth_url = "https://issuer.example/auth",
    token_url = "https://issuer.example/token",
    jwks_host_issuer_match = FALSE,
    jwks_host_allow_only = "keys.example"
  )
  for (pin in list(c("keys.example", "backup.example"), character(), "", " ")) {
    expect_error(provider@jwks_host_allow_only <- pin, "jwks_host_allow_only")
  }
  # Restored objects may bypass normal property setters. Runtime policy must
  # reject these before any key fetch, even with issuer matching disabled.
  S7::prop(provider, "jwks_host_allow_only", check = FALSE) <- c(
    "keys.example",
    "backup.example"
  )
  expect_error(
    validate_jwks_host_matches_issuer(
      "https://issuer.example",
      "https://unexpected.example/keys",
      provider
    ),
    "jwks_host_allow_only",
    class = "shinyOAuth_config_error"
  )
  local_mocked_bindings(req_with_retry = function(...) {
    fail("must not fetch keys")
  })
  expect_error(
    fetch_jwks(
      "https://issuer.example",
      cachem::cache_mem(),
      provider = provider
    ),
    "jwks_host_allow_only",
    class = "shinyOAuth_config_error"
  )
})

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
