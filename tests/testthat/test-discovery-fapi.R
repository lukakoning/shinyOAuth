test_that("explicit FAPI ID-token policy accepts and restricts FAPI signing metadata", {
  metadata <- list(
    issuer = "https://issuer.example.com",
    authorization_endpoint = "https://issuer.example.com/auth",
    token_endpoint = "https://issuer.example.com/token",
    jwks_uri = "https://issuer.example.com/jwks",
    response_types_supported = list("code"),
    subject_types_supported = list("public"),
    id_token_signing_alg_values_supported = list(
      "PS256",
      "ES256",
      "EdDSA",
      "Ed25519"
    )
  )
  local_mocked_bindings(
    .discover_fetch_response = function(req, issuer) {
      structure(list(), class = "mock_discovery_response")
    },
    .discover_parse_json = function(resp) metadata,
    .package = "shinyOAuth"
  )
  expect_error(
    oauth_provider_oidc_discover(metadata[["issuer"]]),
    "must include RS256",
    class = "shinyOAuth_parse_error"
  )
  provider <- oauth_provider_oidc_discover(
    metadata[["issuer"]],
    id_token_profile = "fapi2"
  )
  expect_setequal(provider@allowed_algs, c("ES256", "EDDSA", "ED25519"))
  expect_identical(provider@issuer, metadata[["issuer"]])
  expect_true(provider@id_token_validation)
  for (argument in c("id_token_allowed_algs", "allowed_algs")) {
    args <- list(issuer = metadata[["issuer"]], id_token_profile = "fapi2")
    args[[argument]] <- c("RS256", "ES256", "ES384")
    expect_identical(
      do.call(oauth_provider_oidc_discover, args)@allowed_algs,
      "ES256"
    )
    args[[argument]] <- "RS256"
    expect_error(
      do.call(oauth_provider_oidc_discover, args),
      "No supported FAPI",
      class = "shinyOAuth_config_error"
    )
  }
  metadata[["id_token_signing_alg_values_supported"]] <- list("PS256")
  expect_error(
    oauth_provider_oidc_discover(
      metadata[["issuer"]],
      id_token_profile = "fapi2"
    ),
    class = "shinyOAuth_config_error"
  )
  for (alg in c("RS256", "ES384", "HS256", "none")) {
    metadata[["id_token_signing_alg_values_supported"]] <- list(alg)
    expect_error(
      oauth_provider_oidc_discover(
        metadata[["issuer"]],
        id_token_profile = "fapi2"
      ),
      class = "shinyOAuth_parse_error"
    )
  }
})

test_that("FAPI ID-token profile keeps metadata, issuer, endpoint and caller checks", {
  metadata <- list(
    issuer = "https://issuer.example.com",
    authorization_endpoint = "https://issuer.example.com/auth",
    token_endpoint = "https://issuer.example.com/token",
    jwks_uri = "https://issuer.example.com/jwks",
    response_types_supported = list("code"),
    subject_types_supported = list("public"),
    id_token_signing_alg_values_supported = list("ES256")
  )
  local_mocked_bindings(
    .discover_fetch_response = function(req, issuer) {
      structure(list(), class = "mock_discovery_response")
    },
    .discover_parse_json = function(resp) metadata,
    .package = "shinyOAuth"
  )
  original <- metadata
  for (field in c(
    "jwks_uri",
    "response_types_supported",
    "subject_types_supported",
    "id_token_signing_alg_values_supported"
  )) {
    metadata <- original
    metadata[[field]] <- NULL
    expect_error(
      oauth_provider_oidc_discover(
        original[["issuer"]],
        id_token_profile = "fapi2"
      ),
      class = "shinyOAuth_parse_error"
    )
  }
  metadata <- original
  metadata[["issuer"]] <- "https://other.example.com"
  expect_error(
    oauth_provider_oidc_discover(
      original[["issuer"]],
      id_token_profile = "fapi2"
    ),
    class = "shinyOAuth_config_error"
  )
  metadata <- original
  metadata[["token_endpoint"]] <- "http://issuer.example.com/token"
  expect_error(
    oauth_provider_oidc_discover(
      original[["issuer"]],
      id_token_profile = "fapi2"
    ),
    class = "shinyOAuth_config_error"
  )
  metadata <- original
  expect_error(
    oauth_provider_oidc_discover(
      original[["issuer"]],
      id_token_profile = "fapi2",
      id_token_allowed_algs = "EdDSA"
    ),
    class = "shinyOAuth_config_error"
  )
  expect_error(oauth_provider_oidc_discover(
    original[["issuer"]],
    id_token_profile = "unknown"
  ))
})
