test_that("JARM alias conflicts only prevent clients from using the affected feature", {
  metadata <- list(
    issuer = "https://issuer.example.com",
    authorization_endpoint = "https://issuer.example.com/auth",
    token_endpoint = "https://issuer.example.com/token",
    jwks_uri = "https://issuer.example.com/jwks",
    response_types_supported = list("code"),
    subject_types_supported = list("public"),
    id_token_signing_alg_values_supported = list("RS256"),
    response_modes_supported = list("query", "query.jwt")
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
  key <- openssl::rsa_keygen()
  create <- function(provider, ...) {
    oauth_client(
      provider,
      "client",
      "secret",
      "https://app.example.com/callback",
      ...
    )
  }
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
        metadata[["issuer"]],
        id_token_validation = FALSE
      )
      expect_identical(
        S7::prop(provider, legacy),
        if (mode == "legacy") rev(expected) else expected
      )
    }
    document <- metadata
    for (advertised in list(as.list(expected), list())) {
      document[[registered]] <- advertised
      document[[legacy]] <- as.list(expected[[1L]])
      provider <- oauth_provider_oidc_discover(metadata[["issuer"]])
      expect_s7_class(create(provider), OAuthClient)
      if (kind == "signing_alg") {
        expect_error(
          create(provider, response_mode = "query.jwt"),
          "Conflicting discovery metadata"
        )
      } else {
        expect_s7_class(
          create(provider, response_mode = "query.jwt"),
          OAuthClient
        )
        expect_error(
          create(
            provider,
            response_mode = "query.jwt",
            jarm_encrypted_response_alg = "RSA-OAEP",
            jarm_decryption_private_key = key
          ),
          "Conflicting discovery metadata"
        )
      }
    }
    document[[legacy]] <- list()
    expect_length(
      S7::prop(oauth_provider_oidc_discover(metadata[["issuer"]]), legacy),
      0L
    )
  }
})
