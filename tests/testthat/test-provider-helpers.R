# Tests for provider helper constructors
#
# Verifies that each pre-configured provider constructor produces an
# OAuthProvider with the expected properties. Discovery-based providers
# (Slack, Keycloak, Okta, Auth0) are tested by mocking the discovery
# call to avoid network access.

# ── Non-discovery providers ─────────────────────────────────────────────────

test_that("oauth_provider_github returns valid OAuthProvider with expected defaults", {
  p <- oauth_provider_github()

  expect_s3_class(p, "shinyOAuth::OAuthProvider")
  expect_identical(p@name, "github")
  expect_match(p@auth_url, "github\\.com/login/oauth/authorize")
  expect_match(p@token_url, "github\\.com/login/oauth/access_token")
  expect_match(p@userinfo_url, "api\\.github\\.com/user")
  expect_true(is.na(p@issuer))
  expect_true(is.na(p@introspection_url))
  expect_false(p@use_nonce)
  expect_true(p@use_pkce)
  expect_identical(p@pkce_method, "S256")
  expect_identical(p@token_auth_style, "body")
  expect_true(p@userinfo_required)
  expect_false(p@userinfo_id_token_match)
  expect_false(p@id_token_required)
  expect_false(p@id_token_validation)

  # extra_token_headers should include Accept: application/json (GitHub quirk)
  expect_true("Accept" %in% names(p@extra_token_headers))
  expect_identical(
    unname(p@extra_token_headers[["Accept"]]),
    "application/json"
  )

  # userinfo_id_selector should extract $id (not $sub)
  fake_ui <- list(id = 12345, login = "octocat")
  expect_identical(p@userinfo_id_selector(fake_ui), "12345")
})

test_that("oauth_provider_github allows custom name", {
  p <- oauth_provider_github(name = "my-github")
  expect_identical(p@name, "my-github")
})

test_that("oauth_provider_google returns valid OAuthProvider with expected defaults", {
  p <- oauth_provider_google()

  expect_s3_class(p, "shinyOAuth::OAuthProvider")
  expect_identical(p@name, "google")
  expect_match(p@auth_url, "accounts\\.google\\.com")
  expect_match(p@token_url, "googleapis\\.com/token")
  expect_identical(p@issuer, "https://accounts.google.com")
  expect_true(p@use_nonce)
  expect_true(p@use_pkce)
  expect_identical(p@token_auth_style, "header")
  expect_true(p@userinfo_required)
  expect_true(p@userinfo_id_token_match)
  expect_true(p@id_token_required)
  expect_true(p@id_token_validation)

  # Google has a revocation endpoint
  expect_match(p@revocation_url, "googleapis\\.com/revoke")
})

test_that("oauth_provider_google allows custom name", {
  p <- oauth_provider_google(name = "my-google")
  expect_identical(p@name, "my-google")
})

test_that("oauth_provider_spotify returns valid OAuthProvider with expected defaults", {
  p <- oauth_provider_spotify()

  expect_s3_class(p, "shinyOAuth::OAuthProvider")
  expect_identical(p@name, "spotify")
  expect_match(p@auth_url, "accounts\\.spotify\\.com/authorize")
  expect_match(p@token_url, "accounts\\.spotify\\.com/api/token")
  expect_match(p@userinfo_url, "api\\.spotify\\.com/v1/me")
  expect_true(is.na(p@issuer))
  expect_true(is.na(p@introspection_url))
  expect_false(p@use_nonce)
  expect_true(p@use_pkce)
  expect_identical(p@pkce_method, "S256")
  expect_identical(p@token_auth_style, "header")
  expect_true(p@userinfo_required)
  expect_false(p@userinfo_id_token_match)
  expect_false(p@id_token_required)
  expect_false(p@id_token_validation)

  # userinfo_id_selector should extract $id
  fake_ui <- list(id = "spotify-user-123", display_name = "DJ Test")
  expect_identical(p@userinfo_id_selector(fake_ui), "spotify-user-123")
})

test_that("oauth_provider_microsoft with common tenant has correct defaults", {
  p <- oauth_provider_microsoft(tenant = "common")

  expect_s3_class(p, "shinyOAuth::OAuthProvider")
  expect_identical(p@name, "microsoft")
  expect_match(p@auth_url, "login\\.microsoftonline\\.com/common")
  expect_match(p@token_url, "login\\.microsoftonline\\.com/common")
  expect_match(p@userinfo_url, "graph\\.microsoft\\.com")
  expect_true(is.na(p@issuer))
  expect_true(is.na(p@introspection_url))
  expect_false(p@use_nonce)
  expect_true(p@use_pkce)
  expect_identical(p@token_auth_style, "body")
  expect_identical(p@allowed_algs, c("RS256"))
  expect_false(p@id_token_validation)
  expect_false(p@id_token_required)
})

test_that("oauth_provider_microsoft with GUID tenant enables validation", {
  guid <- "12345678-1234-1234-1234-123456789abc"
  p <- oauth_provider_microsoft(tenant = guid)

  expect_match(p@auth_url, guid, fixed = TRUE)
  expect_match(p@token_url, guid, fixed = TRUE)
  expect_match(p@issuer, guid, fixed = TRUE)
  expect_true(p@use_nonce)
  expect_true(p@id_token_validation)
  expect_true(p@id_token_required)
  expect_true(p@userinfo_id_token_match)
})

test_that("oauth_provider_microsoft respects explicit id_token_validation override", {
  # Explicitly disable for GUID tenant
  guid <- "12345678-1234-1234-1234-123456789abc"
  p <- oauth_provider_microsoft(
    tenant = guid,
    id_token_validation = FALSE
  )
  expect_false(p@id_token_validation)

  # Explicitly enable for common tenant is impossible because it requires
  # use_nonce = TRUE which requires an issuer, and common has no stable issuer.
  # This should error at validation.
  expect_error(
    oauth_provider_microsoft(
      tenant = "common",
      id_token_validation = TRUE
    ),
    regexp = "use_nonce.*issuer"
  )
})

test_that("oauth_provider_oidc builds correct endpoint URLs from base_url", {
  p <- oauth_provider_oidc(
    name = "test-oidc",
    base_url = "https://auth.example.com"
  )

  expect_s3_class(p, "shinyOAuth::OAuthProvider")
  expect_identical(p@name, "test-oidc")
  expect_identical(p@auth_url, "https://auth.example.com/authorize")
  expect_identical(p@token_url, "https://auth.example.com/token")
  expect_identical(p@userinfo_url, "https://auth.example.com/userinfo")
  expect_identical(p@introspection_url, "https://auth.example.com/introspect")
  expect_identical(p@issuer, "https://auth.example.com")
  expect_true(p@use_nonce)
  expect_true(p@id_token_validation)
  expect_identical(p@token_auth_style, "header")
  expect_identical(p@allowed_token_types, "Bearer")
})

test_that("oauth_provider_oidc allows custom paths", {
  p <- oauth_provider_oidc(
    name = "custom-oidc",
    base_url = "https://auth.example.com",
    auth_path = "/oauth/authorize",
    token_path = "/oauth/token",
    userinfo_path = "/oauth/userinfo",
    introspection_path = "/oauth/introspect"
  )

  expect_identical(p@auth_url, "https://auth.example.com/oauth/authorize")
  expect_identical(p@token_url, "https://auth.example.com/oauth/token")
  expect_identical(p@userinfo_url, "https://auth.example.com/oauth/userinfo")
  expect_identical(
    p@introspection_url,
    "https://auth.example.com/oauth/introspect"
  )
})

test_that("oauth_provider_oidc passes through extra args", {
  p <- oauth_provider_oidc(
    name = "passthru",
    base_url = "https://auth.example.com",
    use_pkce = FALSE,
    use_nonce = FALSE,
    extra_auth_params = list(prompt = "consent")
  )

  expect_false(p@use_pkce)
  expect_false(p@use_nonce)
  expect_identical(p@extra_auth_params, list(prompt = "consent"))
})

# ── Discovery-based providers (mocked) ──────────────────────────────────────

# Minimal OIDC discovery document for mocking
make_discovery_doc <- function(
  issuer,
  auth_endpoint = paste0(issuer, "/authorize"),
  token_endpoint = paste0(issuer, "/token"),
  userinfo_endpoint = paste0(issuer, "/userinfo"),
  introspection_endpoint = paste0(issuer, "/introspect"),
  jwks_uri = paste0(issuer, "/.well-known/jwks.json")
) {
  jsonlite::toJSON(
    list(
      issuer = issuer,
      authorization_endpoint = auth_endpoint,
      token_endpoint = token_endpoint,
      userinfo_endpoint = userinfo_endpoint,
      introspection_endpoint = introspection_endpoint,
      jwks_uri = jwks_uri,
      token_endpoint_auth_methods_supported = list(
        "client_secret_basic",
        "client_secret_post"
      ),
      id_token_signing_alg_values_supported = list("RS256", "ES256")
    ),
    auto_unbox = TRUE
  )
}

test_that("oauth_provider_keycloak constructs correct issuer from base_url + realm", {
  issuer <- "http://localhost:8080/realms/myrealm"
  disc_json <- make_discovery_doc(issuer)

  testthat::local_mocked_bindings(
    req_with_retry = function(req) {
      httr2::response(
        url = as.character(req$url),
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw(as.character(disc_json))
      )
    },
    .package = "shinyOAuth"
  )

  # Allow non-HTTPS for localhost (Keycloak dev)
  withr::local_options(list(
    shinyOAuth.allowed_non_https_hosts = c("localhost")
  ))

  p <- oauth_provider_keycloak(
    base_url = "http://localhost:8080",
    realm = "myrealm"
  )

  expect_s3_class(p, "shinyOAuth::OAuthProvider")
  expect_identical(p@name, "keycloak-myrealm")
  expect_identical(p@issuer, issuer)
  expect_identical(p@token_auth_style, "body")
})

test_that("oauth_provider_okta constructs correct issuer from domain + auth_server", {
  issuer <- "https://dev-123456.okta.com/oauth2/default"
  disc_json <- make_discovery_doc(issuer)

  testthat::local_mocked_bindings(
    req_with_retry = function(req) {
      httr2::response(
        url = as.character(req$url),
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw(as.character(disc_json))
      )
    },
    .package = "shinyOAuth"
  )

  p <- oauth_provider_okta(
    domain = "dev-123456.okta.com",
    auth_server = "default"
  )

  expect_s3_class(p, "shinyOAuth::OAuthProvider")
  expect_identical(p@name, "okta")
  expect_identical(p@issuer, issuer)
})

test_that("oauth_provider_auth0 constructs correct issuer from domain", {
  issuer <- "https://my-domain.auth0.com"
  disc_json <- make_discovery_doc(issuer)

  testthat::local_mocked_bindings(
    req_with_retry = function(req) {
      httr2::response(
        url = as.character(req$url),
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw(as.character(disc_json))
      )
    },
    .package = "shinyOAuth"
  )

  p <- oauth_provider_auth0(domain = "my-domain.auth0.com")

  expect_s3_class(p, "shinyOAuth::OAuthProvider")
  expect_identical(p@name, "auth0")
  expect_identical(p@issuer, issuer)
})

test_that("oauth_provider_auth0 includes audience in extra_auth_params", {
  issuer <- "https://my-domain.auth0.com"
  disc_json <- make_discovery_doc(issuer)

  testthat::local_mocked_bindings(
    req_with_retry = function(req) {
      httr2::response(
        url = as.character(req$url),
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw(as.character(disc_json))
      )
    },
    .package = "shinyOAuth"
  )

  p <- oauth_provider_auth0(
    domain = "my-domain.auth0.com",
    audience = "https://my-api.example.com"
  )

  expect_identical(
    p@extra_auth_params[["audience"]],
    "https://my-api.example.com"
  )
})

test_that("oauth_provider_slack constructs correct issuer", {
  issuer <- "https://slack.com"
  disc_json <- make_discovery_doc(issuer)

  testthat::local_mocked_bindings(
    req_with_retry = function(req) {
      httr2::response(
        url = as.character(req$url),
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw(as.character(disc_json))
      )
    },
    .package = "shinyOAuth"
  )

  p <- oauth_provider_slack()

  expect_s3_class(p, "shinyOAuth::OAuthProvider")
  expect_identical(p@name, "slack")
  expect_identical(p@issuer, issuer)
})

# ── Input validation for discovery-based providers ──────────────────────────

test_that("oauth_provider_keycloak rejects empty base_url and realm", {
  expect_error(oauth_provider_keycloak(base_url = "", realm = "r"))
  expect_error(oauth_provider_keycloak(
    base_url = "http://localhost",
    realm = ""
  ))
})

test_that("oauth_provider_okta rejects empty domain", {
  expect_error(oauth_provider_okta(domain = ""))
})

test_that("oauth_provider_auth0 rejects empty domain", {
  expect_error(oauth_provider_auth0(domain = ""))
})
