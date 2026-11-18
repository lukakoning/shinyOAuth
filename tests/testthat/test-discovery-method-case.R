method_case_discover <- function(
  oidc,
  auth_methods = "client_secret_basic",
  pkce_methods = "S256",
  ...
) {
  issuer <- "https://issuer.example"
  metadata <- list(
    issuer = issuer,
    authorization_endpoint = paste0(issuer, "/authorize"),
    token_endpoint = paste0(issuer, "/token"),
    jwks_uri = paste0(issuer, "/jwks"),
    response_types_supported = list("code"),
    subject_types_supported = list("public"),
    id_token_signing_alg_values_supported = list("RS256"),
    token_endpoint_auth_methods_supported = as.list(auth_methods),
    token_endpoint_auth_signing_alg_values_supported = list("RS256", "ES256"),
    code_challenge_methods_supported = as.list(pkce_methods)
  )
  discover <- if (oidc) {
    oauth_provider_oidc_discover
  } else {
    oauth_provider_oauth_discover
  }
  withr::local_options(shinyOAuth.allowed_hosts = "issuer.example")
  testthat::with_mocked_bindings(
    req_with_retry = function(req, ...) {
      httr2::response(
        url = req[["url"]],
        status = 200L,
        headers = list("content-type" = "application/json"),
        body = charToRaw(jsonlite::toJSON(metadata, auto_unbox = TRUE))
      )
    },
    .package = "shinyOAuth",
    discover(issuer, ...)
  )
}

for (oidc in c(FALSE, TRUE)) {
  protocol <- if (oidc) "OIDC" else "OAuth"

  test_that(
    paste(protocol, "discovery infers only exact registered auth methods"),
    {
      for (method in c(
        "CLIENT_SECRET_BASIC",
        "Client_Secret_Post",
        "NONE",
        "PRIVATE_KEY_JWT",
        "TLS_CLIENT_AUTH"
      )) {
        expect_error(
          method_case_discover(oidc, auth_methods = method),
          class = "shinyOAuth_config_error",
          info = method
        )
      }
      cases <- list(
        list(
          methods = c("CLIENT_SECRET_BASIC", "client_secret_post"),
          style = "body"
        ),
        list(methods = c("CLIENT_SECRET_BASIC", "none"), style = "public"),
        list(methods = c("client_secret_basic", "NONE"), style = "header"),
        list(
          methods = c("CLIENT_SECRET_BASIC", "client_secret_basic"),
          style = "header"
        ),
        list(
          methods = c("unknown_extension", "client_secret_post"),
          style = "body"
        )
      )
      for (case in cases) {
        provider <- method_case_discover(oidc, auth_methods = case[["methods"]])
        expect_identical(provider@token_auth_style, case[["style"]])
      }
    }
  )

  test_that(paste(protocol, "explicit auth needs an exact advertised match"), {
    methods <- c(
      header = "client_secret_basic",
      body = "client_secret_post",
      public = "none",
      client_secret_jwt = "client_secret_jwt",
      private_key_jwt = "private_key_jwt",
      tls_client_auth = "tls_client_auth",
      self_signed_tls_client_auth = "self_signed_tls_client_auth"
    )
    for (style in names(methods)) {
      method <- methods[[style]]
      expect_error(
        method_case_discover(
          oidc,
          auth_methods = toupper(method),
          token_auth_style = style
        ),
        class = "shinyOAuth_config_error",
        info = method
      )
      provider <- method_case_discover(
        oidc,
        auth_methods = c(toupper(method), "unknown_extension", method),
        token_auth_style = style
      )
      expect_identical(provider@token_auth_style, style)
    }
    expect_error(
      method_case_discover(
        oidc,
        auth_methods = c("CLIENT_SECRET_BASIC", "client_secret_post"),
        token_auth_style = "header"
      ),
      class = "shinyOAuth_config_error"
    )
  })

  test_that(
    paste(protocol, "PKCE capability matching never changes advertised case"),
    {
      for (requested in list(NULL, "S256", " s256 ")) {
        for (advertised in list("s256", c("s256", "plain"))) {
          expect_error(
            method_case_discover(
              oidc,
              pkce_methods = advertised,
              pkce_method = requested
            ),
            class = "shinyOAuth_config_error"
          )
        }
        for (advertised in list(
          "S256",
          c("s256", "S256", "plain", "extension")
        )) {
          provider <- method_case_discover(
            oidc,
            pkce_methods = advertised,
            pkce_method = requested
          )
          expect_identical(provider@pkce_method, "S256")
        }
      }
      expect_error(
        method_case_discover(oidc, pkce_methods = "plain"),
        class = "shinyOAuth_config_error"
      )
      for (requested in c("plain", " PLAIN ")) {
        for (advertised in list("PLAIN", c("PLAIN", "S256"))) {
          expect_error(
            method_case_discover(
              oidc,
              pkce_methods = advertised,
              pkce_method = requested
            ),
            class = "shinyOAuth_config_error"
          )
        }
        provider <- method_case_discover(
          oidc,
          pkce_methods = c("PLAIN", "plain", "s256", "extension"),
          pkce_method = requested
        )
        expect_identical(provider@pkce_method, "plain")
      }
    }
  )

  test_that(
    paste(protocol, "caller auth spelling normalization remains available"),
    {
      for (case in list(
        list(
          method = "client_secret_basic",
          requested = " HeAdEr ",
          style = "header"
        ),
        list(
          method = "client_secret_post",
          requested = " BoDy ",
          style = "body"
        ),
        list(method = "none", requested = " NoNe ", style = "public")
      )) {
        provider <- method_case_discover(
          oidc,
          auth_methods = case[["method"]],
          token_auth_style = case[["requested"]]
        )
        expect_identical(provider@token_auth_style, case[["style"]])
      }
    }
  )
}
