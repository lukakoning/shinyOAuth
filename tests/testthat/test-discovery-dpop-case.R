for (oidc in c(FALSE, TRUE)) {
  protocol <- if (oidc) "OIDC" else "OAuth"
  discover <- if (oidc) {
    shinyOAuth::oauth_provider_oidc_discover
  } else {
    shinyOAuth::oauth_provider_oauth_discover
  }
  issuer <- "https://issuer.example/tenant"
  discovery_url <- if (oidc) {
    "https://issuer.example/tenant/.well-known/openid-configuration"
  } else {
    "https://issuer.example/.well-known/oauth-authorization-server/tenant"
  }

  test_that(
    paste(protocol, "public discovery rejects DPoP JOSE case repairs"),
    {
      withr::local_options(shinyOAuth.allowed_hosts = "issuer.example")
      metadata <- list(
        issuer = issuer,
        authorization_endpoint = paste0(issuer, "/authorize"),
        token_endpoint = paste0(issuer, "/token"),
        jwks_uri = paste0(issuer, "/jwks"),
        response_types_supported = list("code"),
        subject_types_supported = list("public"),
        id_token_signing_alg_values_supported = list("RS256"),
        token_endpoint_auth_methods_supported = list("client_secret_basic"),
        code_challenge_methods_supported = list("S256")
      )
      requests <- character()
      # Only the HTTP response is replaced. Both exported discovery paths run
      # their real request, JSON, required-metadata and JOSE validation code.
      local_mocked_bindings(
        req_perform = function(req, ...) {
          requests <<- c(requests, req[["url"]])
          expect_identical(req[["url"]], discovery_url)
          httr2::response(
            url = req[["url"]],
            status = 200L,
            headers = list("content-type" = "application/json"),
            body = charToRaw(jsonlite::toJSON(metadata, auto_unbox = TRUE))
          )
        },
        .package = "httr2"
      )
      for (algorithms in list(
        "es256",
        "Es256",
        "eddsa",
        "EDDSA",
        "ed25519",
        "ED25519",
        c("ES256", "es256"),
        c("ES256", "EDDSA"),
        c("ES256", "ed25519"),
        c("EdDSA", "ES256", "eDdSa")
      )) {
        metadata[["dpop_signing_alg_values_supported"]] <- as.list(algorithms)
        requests <- character()
        provider <- NULL
        expect_error(
          provider <- discover(issuer, allowed_token_types = "DPoP"),
          "dpop_signing_alg_values_supported.*invalid case",
          class = "shinyOAuth_parse_error",
          info = paste(algorithms, collapse = ", ")
        )
        expect_null(provider)
        # No alternate discovery location, JWKS fetch, or retry can conceal a
        # malformed advertised identifier behind a later successful response.
        expect_identical(requests, discovery_url)
      }
    }
  )

  test_that(
    paste(protocol, "public discovery retains valid DPoP JOSE capabilities"),
    {
      withr::local_options(shinyOAuth.allowed_hosts = "issuer.example")
      metadata <- list(
        issuer = issuer,
        authorization_endpoint = paste0(issuer, "/authorize"),
        token_endpoint = paste0(issuer, "/token"),
        jwks_uri = paste0(issuer, "/jwks"),
        response_types_supported = list("code"),
        subject_types_supported = list("public"),
        id_token_signing_alg_values_supported = list("RS256"),
        token_endpoint_auth_methods_supported = list("client_secret_basic"),
        code_challenge_methods_supported = list("S256")
      )
      requests <- character()
      local_mocked_bindings(
        req_perform = function(req, ...) {
          requests <<- c(requests, req[["url"]])
          expect_identical(req[["url"]], discovery_url)
          httr2::response(
            url = req[["url"]],
            status = 200L,
            headers = list("content-type" = "application/json"),
            body = charToRaw(jsonlite::toJSON(metadata, auto_unbox = TRUE))
          )
        },
        .package = "httr2"
      )
      for (algorithms in list(
        "ES256",
        "EdDSA",
        "Ed25519",
        c("ES256", "EdDSA", "Ed25519")
      )) {
        metadata[["dpop_signing_alg_values_supported"]] <- as.list(algorithms)
        requests <- character()
        provider <- discover(issuer, allowed_token_types = "DPoP")
        # Valid wire spellings retain their existing internal uppercase form.
        expect_identical(
          provider@dpop_signing_alg_values_supported,
          toupper(algorithms)
        )
        expect_identical(provider@issuer, issuer)
        expect_identical(provider@allowed_token_types, "DPoP")
        expect_identical(provider@infer_oidc_from_issuer, oidc)
        expect_identical(requests, discovery_url)
      }
    }
  )
}
