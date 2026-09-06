test_that("registered JARM metadata takes precedence and conflicting aliases fail", {
  metadata <- list(
    issuer = "https://issuer.example.com",
    authorization_endpoint = "https://issuer.example.com/auth",
    token_endpoint = "https://issuer.example.com/token",
    jwks_uri = "https://issuer.example.com/jwks",
    response_types_supported = list("code"),
    subject_types_supported = list("public"),
    id_token_signing_alg_values_supported = list("RS256")
  )
  document <- metadata
  local_mocked_bindings(
    .discover_fetch_response = function(...) NULL,
    .discover_parse_json = function(...) document,
    .package = "shinyOAuth"
  )
  fields <- list(
    signing_alg = c("RS256", "ES256"),
    encryption_alg = c("RSA-OAEP", "RSA-OAEP-256"),
    encryption_enc = c("A128CBC-HS256", "A256CBC-HS512")
  )
  for (kind in names(fields)) {
    registered <- paste0("authorization_", kind, "_values_supported")
    legacy <- paste0("jarm_", kind, "_values_supported")
    expected <- fields[[kind]]
    for (mode in c("registered", "legacy", "both")) {
      document <- metadata
      if (mode != "legacy") {
        document[[registered]] <- as.list(expected)
      }
      if (mode != "registered") {
        document[[legacy]] <- as.list(rev(expected))
      }
      provider <- oauth_provider_oidc_discover(
        metadata$issuer,
        id_token_validation = FALSE
      )
      expect_identical(
        S7::prop(provider, legacy),
        if (mode == "legacy") rev(expected) else expected
      )
    }
    document <- metadata
    document[[registered]] <- as.list(expected)
    document[[legacy]] <- as.list(expected[[1L]])
    expect_error(
      oauth_provider_oidc_discover(metadata$issuer),
      "Conflicting discovery metadata",
      class = "shinyOAuth_config_error"
    )
    document[[registered]] <- list()
    expect_error(
      oauth_provider_oidc_discover(metadata$issuer),
      class = "shinyOAuth_config_error"
    )
  }
})
