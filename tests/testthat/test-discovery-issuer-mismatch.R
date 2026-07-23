withr::local_options(
  shinyOAuth.allow_insecure_oidc_loopback = TRUE,
  .local_envir = environment()
)

test_that("validate_discovery_issuer errors on host mismatch by default", {
  f <- shinyOAuth:::validate_discovery_issuer
  expect_error(
    f(
      "https://login.example.com",
      "https://accounts.example.com"
    ),
    class = "shinyOAuth_config_error"
  )
})

test_that("validate_discovery_issuer errors on scheme mismatch by default", {
  f <- shinyOAuth:::validate_discovery_issuer
  expect_error(
    f("http://login.example.com", "https://login.example.com"),
    class = "shinyOAuth_config_error"
  )
})

test_that("validate_discovery_issuer returns discovered on match", {
  f <- shinyOAuth:::validate_discovery_issuer
  expect_identical(
    f(
      "https://login.example.com",
      "https://login.example.com"
    ),
    "https://login.example.com"
  )
})

test_that("validate_discovery_issuer can be overridden via arg", {
  f <- shinyOAuth:::validate_discovery_issuer
  expect_identical(
    f(
      "https://login.example.com",
      "https://accounts.example.com",
      issuer_match = "none"
    ),
    "https://accounts.example.com"
  )
})

test_that("validate_discovery_issuer rejects missing discovery issuer", {
  f <- shinyOAuth:::validate_discovery_issuer
  expect_error(
    f("https://login.example.com", NULL),
    class = "shinyOAuth_parse_error",
    regexp = "missing required issuer"
  )
})

test_that("validate_discovery_issuer rejects non-scalar discovery issuer", {
  f <- shinyOAuth:::validate_discovery_issuer
  expect_error(
    f(
      "https://login.example.com",
      c("https://login.example.com", "https://accounts.example.com")
    ),
    class = "shinyOAuth_parse_error",
    regexp = "single non-empty string"
  )
})

test_that("validate_discovery_issuer errors on issuer path mismatch by default", {
  f <- shinyOAuth:::validate_discovery_issuer
  expect_error(
    f(
      "https://login.example.com/tenant-a",
      "https://login.example.com/tenant-b"
    ),
    class = "shinyOAuth_config_error"
  )
})

test_that("validate_discovery_issuer matches without a trailing slash", {
  f <- shinyOAuth:::validate_discovery_issuer
  expect_identical(
    f(
      "https://login.example.com/tenant-a/",
      "https://login.example.com/tenant-a"
    ),
    "https://login.example.com/tenant-a"
  )
})

test_that("validate_discovery_issuer matches with a trailing slash", {
  f <- shinyOAuth:::validate_discovery_issuer
  expect_identical(
    f(
      "https://login.example.com/tenant-a",
      "https://login.example.com/tenant-a/"
    ),
    "https://login.example.com/tenant-a/"
  )
})

test_that("validate_discovery_issuer errors on host case mismatch by default", {
  f <- shinyOAuth:::validate_discovery_issuer
  expect_error(
    f(
      "https://EXAMPLE.com/issuer",
      "https://example.com/issuer"
    ),
    class = "shinyOAuth_config_error"
  )
})

test_that("validate_discovery_issuer can opt out to host-only matching", {
  f <- shinyOAuth:::validate_discovery_issuer
  expect_identical(
    f(
      "https://login.example.com/tenant-a",
      "https://login.example.com/tenant-b",
      issuer_match = "host"
    ),
    "https://login.example.com/tenant-b"
  )
})

test_that("discovery input normalization strips a full discovery URL", {
  f <- shinyOAuth:::.discover_normalize_issuer_input

  expect_identical(
    f("https://login.example.com/tenant-a/.well-known/openid-configuration"),
    "https://login.example.com/tenant-a"
  )
  expect_identical(
    f("https://login.example.com/tenant-a/.well-known/openid-configuration/"),
    "https://login.example.com/tenant-a"
  )
  expect_identical(
    f("https://login.example.com/tenant-a"),
    "https://login.example.com/tenant-a"
  )
  expect_identical(
    f("https://login.example.com/tenant-a/"),
    "https://login.example.com/tenant-a/"
  )
})

test_that("oauth_provider_oidc_discover accepts a full discovery URL", {
  testthat::skip_if_not_installed("webfakes")
  testthat::skip_on_cran()

  tenant_path <- "/tenant-a"
  app <- webfakes::new_app()
  app$get(
    paste0(tenant_path, "/.well-known/openid-configuration"),
    function(req, res) {
      issuer_url <- paste0("http://", req$get_header("host"), tenant_path)
      res$set_status(200)$set_type("application/json")$send(
        jsonlite::toJSON(
          list(
            issuer = issuer_url,
            authorization_endpoint = paste0(issuer_url, "/auth"),
            token_endpoint = paste0(issuer_url, "/token"),
            jwks_uri = paste0(issuer_url, "/jwks"),
            response_types_supported = list("code"),
            subject_types_supported = list("public"),
            id_token_signing_alg_values_supported = list("RS256")
          ),
          auto_unbox = TRUE
        )
      )
    }
  )

  srv <- webfakes::local_app_process(app)
  issuer_url <- paste0(sub("/$", "", srv$url()), tenant_path)

  prov <- oauth_provider_oidc_discover(
    issuer = paste0(issuer_url, "/.well-known/openid-configuration")
  )

  expect_identical(prov@issuer, issuer_url)
  expect_identical(prov@auth_url, paste0(issuer_url, "/auth"))
  expect_identical(prov@token_url, paste0(issuer_url, "/token"))
})
