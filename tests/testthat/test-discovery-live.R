expect_live_oidc_discovery <- function(
  issuer,
  extra_hosts = character(),
  auth_styles = "header",
  ...
) {
  skip_on_cran()
  host <- httr2::url_parse(issuer)[["hostname"]]
  skip_if_offline(host = host)
  local_options(shinyOAuth.allowed_hosts = c(host, extra_hosts))

  for (style in auth_styles) {
    provider <- oauth_provider_oidc_discover(
      issuer,
      token_auth_style = style,
      ...
    )
    expect_s7_class(provider, OAuthProvider)
    expect_identical(provider@issuer, issuer)
    expect_identical(provider@token_auth_style, style)
    expect_match(provider@auth_url, "^https://")
    expect_match(provider@token_url, "^https://")
    expect_match(provider@jwks_uri, "^https://")
  }
}

test_that("live Okta org discovery supports Basic and POST authentication", {
  expect_live_oidc_discovery(
    "https://okta.okta.com",
    auth_styles = c("header", "body")
  )
})

test_that("live Google discovery supports a trusted JWKS host", {
  expect_live_oidc_discovery(
    "https://accounts.google.com",
    extra_hosts = c(
      "oauth2.googleapis.com",
      "openidconnect.googleapis.com",
      "www.googleapis.com"
    ),
    jwks_host_allow_only = "www.googleapis.com"
  )
})

test_that("live GitLab.com discovery returns an OIDC provider", {
  expect_live_oidc_discovery("https://gitlab.com")
})

test_that("live Microsoft consumer tenant discovery returns an OIDC provider", {
  expect_live_oidc_discovery(
    "https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0",
    extra_hosts = "graph.microsoft.com"
  )
})
