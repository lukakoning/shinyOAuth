strict_oidc_metadata <- function() {
  list(
    issuer = "https://issuer.example.com",
    authorization_endpoint = "https://issuer.example.com/auth",
    token_endpoint = "https://issuer.example.com/token",
    jwks_uri = "https://issuer.example.com/jwks",
    response_types_supported = list("code"),
    subject_types_supported = list("public"),
    id_token_signing_alg_values_supported = list("RS256")
  )
}

test_that("OIDC discovery requires its mandatory string-array metadata", {
  required_arrays <- c(
    "response_types_supported",
    "subject_types_supported",
    "id_token_signing_alg_values_supported"
  )

  for (field in required_arrays) {
    metadata <- strict_oidc_metadata()
    metadata[field] <- list(NULL)

    expect_error(
      shinyOAuth:::.discover_validate_required_metadata(metadata),
      class = "shinyOAuth_parse_error",
      regexp = field,
      fixed = TRUE
    )
  }

  malformed_values <- list(
    "code",
    list(),
    list("code", 1),
    list(named = "code"),
    list(" ")
  )
  for (value in malformed_values) {
    metadata <- strict_oidc_metadata()
    metadata$response_types_supported <- value

    expect_error(
      shinyOAuth:::.discover_validate_required_metadata(metadata),
      class = "shinyOAuth_parse_error",
      regexp = "response_types_supported",
      fixed = TRUE
    )
  }
})

test_that("OIDC discovery requires the capabilities used by this client", {
  metadata <- strict_oidc_metadata()
  metadata$response_types_supported <- list("id_token")
  expect_error(
    shinyOAuth:::.discover_validate_required_metadata(metadata),
    class = "shinyOAuth_parse_error",
    regexp = "include code",
    fixed = TRUE
  )

  metadata <- strict_oidc_metadata()
  metadata$id_token_signing_alg_values_supported <- list("ES256")
  expect_error(
    shinyOAuth:::.discover_validate_required_metadata(metadata),
    class = "shinyOAuth_parse_error",
    regexp = "RS256",
    fixed = TRUE
  )
})

test_that("OIDC discovery rejects scalar optional multi-valued metadata", {
  optional_arrays <- c(
    "scopes_supported",
    "response_modes_supported",
    "token_endpoint_auth_methods_supported",
    "request_object_signing_alg_values_supported",
    "dpop_signing_alg_values_supported",
    "claims_supported"
  )

  for (field in optional_arrays) {
    metadata <- strict_oidc_metadata()
    metadata[[field]] <- "value"

    expect_error(
      shinyOAuth:::.discover_validate_required_metadata(metadata),
      class = "shinyOAuth_parse_error",
      regexp = field,
      fixed = TRUE
    )

    metadata[[field]] <- list("value")
    expect_no_error(
      shinyOAuth:::.discover_validate_required_metadata(metadata)
    )
  }
})

test_that("OIDC discovery always requires jwks_uri", {
  metadata <- strict_oidc_metadata()
  metadata["jwks_uri"] <- list(NULL)

  testthat::local_mocked_bindings(
    .discover_fetch_response = function(req, issuer) {
      structure(list(), class = "mock_discovery_response")
    },
    .discover_parse_json = function(resp) metadata,
    .package = "shinyOAuth"
  )

  expect_error(
    oauth_provider_oidc_discover(
      issuer = metadata$issuer,
      id_token_validation = FALSE,
      use_nonce = FALSE
    ),
    class = "shinyOAuth_parse_error",
    regexp = "jwks_uri",
    fixed = TRUE
  )
})

test_that("OIDC discovery negotiates from validated algorithm metadata", {
  metadata <- strict_oidc_metadata()
  metadata$id_token_signing_alg_values_supported <- list("RS256", "ES256")

  testthat::local_mocked_bindings(
    .discover_fetch_response = function(req, issuer) {
      structure(list(), class = "mock_discovery_response")
    },
    .discover_parse_json = function(resp) metadata,
    .package = "shinyOAuth"
  )

  provider <- oauth_provider_oidc_discover(
    issuer = metadata$issuer,
    allowed_algs = c("ES256", "EdDSA")
  )

  expect_identical(provider@allowed_algs, "ES256")
})
