testthat::test_that("discovery selects conservative client auth methods (basic/post) and avoids JWT by default", {
  testthat::skip_if_not_installed("webfakes")
  testthat::skip_on_cran() # webfakes subprocess can timeout on slow CRAN machines
  app <- webfakes::new_app()
  app$get("/.well-known/openid-configuration", function(req, res) {
    issuer_url <- paste0("http://", req$get_header("host"))
    res$set_status(200)$set_type("application/json")$send(
      jsonlite::toJSON(
        list(
          issuer = issuer_url,
          authorization_endpoint = "https://127.0.0.1/auth",
          token_endpoint = "https://127.0.0.1/token",
          jwks_uri = "https://127.0.0.1/jwks",
          token_endpoint_auth_methods_supported = list(
            # Server advertises JWT and basic; we should prefer basic (header)
            "private_key_jwt",
            "client_secret_basic"
          )
        ),
        auto_unbox = TRUE
      )
    )
  })
  srv <- webfakes::local_app_process(app)
  issuer <- srv$url()

  prov <- oauth_provider_oidc_discover(issuer = issuer)
  testthat::expect_identical(prov@token_auth_style, "header")
})


testthat::test_that("discovery returns body when only client_secret_post is advertised", {
  testthat::skip_if_not_installed("webfakes")
  testthat::skip_on_cran() # webfakes subprocess can timeout on slow CRAN machines
  app <- webfakes::new_app()
  app$get("/.well-known/openid-configuration", function(req, res) {
    issuer_url <- paste0("http://", req$get_header("host"))
    res$set_status(200)$set_type("application/json")$send(
      jsonlite::toJSON(
        list(
          issuer = issuer_url,
          authorization_endpoint = "https://127.0.0.1/auth",
          token_endpoint = "https://127.0.0.1/token",
          jwks_uri = "https://127.0.0.1/jwks",
          token_endpoint_auth_methods_supported = list("client_secret_post")
        ),
        auto_unbox = TRUE
      )
    )
  })
  srv <- webfakes::local_app_process(app)
  issuer <- srv$url()

  prov <- oauth_provider_oidc_discover(issuer = issuer)
  testthat::expect_identical(prov@token_auth_style, "body")
})


testthat::test_that("discovery with 'none' requires PKCE and uses public auth when enabled", {
  testthat::skip_if_not_installed("webfakes")
  testthat::skip_on_cran() # webfakes subprocess can timeout on slow CRAN machines
  app <- webfakes::new_app()
  app$get("/.well-known/openid-configuration", function(req, res) {
    issuer_url <- paste0("http://", req$get_header("host"))
    res$set_status(200)$set_type("application/json")$send(
      jsonlite::toJSON(
        list(
          issuer = issuer_url,
          authorization_endpoint = "https://127.0.0.1/auth",
          token_endpoint = "https://127.0.0.1/token",
          jwks_uri = "https://127.0.0.1/jwks",
          token_endpoint_auth_methods_supported = list("none")
        ),
        auto_unbox = TRUE
      )
    )
  })
  srv <- webfakes::local_app_process(app)
  issuer <- srv$url()

  # With PKCE (default TRUE), we accept and use the dedicated public style
  prov <- oauth_provider_oidc_discover(issuer = issuer, use_pkce = TRUE)
  testthat::expect_identical(prov@token_auth_style, "public")

  # Explicit metadata spelling is also accepted and canonicalized.
  prov_alias <- oauth_provider_oidc_discover(
    issuer = issuer,
    use_pkce = TRUE,
    token_auth_style = "none"
  )
  testthat::expect_identical(prov_alias@token_auth_style, "public")

  # Without PKCE, configuration error
  testthat::expect_error(
    oauth_provider_oidc_discover(issuer = issuer, use_pkce = FALSE),
    class = "shinyOAuth_config_error"
  )
})

testthat::test_that("public discovery auth does not send env client_secret", {
  testthat::skip_if_not_installed("webfakes")
  testthat::skip_on_cran() # webfakes subprocess can timeout on slow CRAN machines
  withr::local_envvar(c(OAUTH_CLIENT_SECRET = "env-secret-value"))

  app <- webfakes::new_app()
  app$get("/.well-known/openid-configuration", function(req, res) {
    issuer_url <- paste0("http://", req$get_header("host"))
    res$set_status(200)$set_type("application/json")$send(
      jsonlite::toJSON(
        list(
          issuer = issuer_url,
          authorization_endpoint = "https://127.0.0.1/auth",
          token_endpoint = "https://127.0.0.1/token",
          jwks_uri = "https://127.0.0.1/jwks",
          token_endpoint_auth_methods_supported = list("none")
        ),
        auto_unbox = TRUE
      )
    )
  })
  srv <- webfakes::local_app_process(app)
  issuer <- srv$url()

  prov <- oauth_provider_oidc_discover(issuer = issuer, use_pkce = TRUE)
  testthat::expect_identical(prov@token_auth_style, "public")

  cl <- oauth_client(
    provider = prov,
    client_id = "abc",
    redirect_uri = "http://localhost:8100",
    scopes = character(0)
  )
  testthat::expect_identical(cl@client_secret, "env-secret-value")

  prepared <- shinyOAuth:::apply_direct_client_auth(
    req = httr2::request("https://127.0.0.1/token"),
    params = list(grant_type = "authorization_code"),
    client = cl,
    context = "token_exchange"
  )
  testthat::expect_identical(prepared$params$client_id, "abc")
  testthat::expect_null(prepared$params$client_secret)
})

test_that("oidc discovery accepts advertised signing algorithm supersets", {
  testthat::skip_if_not_installed("webfakes")
  testthat::skip_on_cran()
  app <- webfakes::new_app()
  app$get("/.well-known/openid-configuration", function(req, res) {
    issuer_url <- paste0("http://", req$get_header("host"))
    res$set_status(200)$set_type("application/json")$send(
      jsonlite::toJSON(
        list(
          issuer = issuer_url,
          authorization_endpoint = paste0(issuer_url, "/auth"),
          token_endpoint = paste0(issuer_url, "/token"),
          jwks_uri = paste0(issuer_url, "/jwks"),
          token_endpoint_auth_signing_alg_values_supported = list(
            "RS256",
            "ES256K"
          ),
          request_object_signing_alg_values_supported = list(
            "RS256",
            "ES256K"
          )
        ),
        auto_unbox = TRUE
      )
    )
  })
  srv <- webfakes::local_app_process(app)

  prov <- oauth_provider_oidc_discover(issuer = srv$url())

  testthat::expect_identical(
    prov@request_object_signing_alg_values_supported,
    c("RS256", "ES256K")
  )
  testthat::expect_identical(
    prov@token_endpoint_auth_signing_alg_values_supported,
    c("RS256", "ES256K")
  )
})

test_that("oidc discovery preserves RFC 9207 callback issuer metadata", {
  testthat::skip_if_not_installed("webfakes")
  testthat::skip_on_cran()
  app <- webfakes::new_app()
  app$get("/.well-known/openid-configuration", function(req, res) {
    issuer_url <- paste0("http://", req$get_header("host"))
    res$set_status(200)$set_type("application/json")$send(
      jsonlite::toJSON(
        list(
          issuer = issuer_url,
          authorization_endpoint = paste0(issuer_url, "/auth"),
          token_endpoint = paste0(issuer_url, "/token"),
          jwks_uri = paste0(issuer_url, "/jwks"),
          authorization_response_iss_parameter_supported = TRUE
        ),
        auto_unbox = TRUE
      )
    )
  })
  srv <- webfakes::local_app_process(app)

  prov <- oauth_provider_oidc_discover(issuer = srv$url())

  testthat::expect_true(
    isTRUE(prov@authorization_response_iss_parameter_supported)
  )
})

test_that("oidc discovery lets caller override request object signing algs", {
  testthat::skip_if_not_installed("webfakes")
  testthat::skip_on_cran()
  app <- webfakes::new_app()
  app$get("/.well-known/openid-configuration", function(req, res) {
    issuer_url <- paste0("http://", req$get_header("host"))
    res$set_status(200)$set_type("application/json")$send(
      jsonlite::toJSON(
        list(
          issuer = issuer_url,
          authorization_endpoint = paste0(issuer_url, "/auth"),
          token_endpoint = paste0(issuer_url, "/token"),
          jwks_uri = paste0(issuer_url, "/jwks"),
          request_object_signing_alg_values_supported = list(
            "RS256",
            "HS256"
          )
        ),
        auto_unbox = TRUE
      )
    )
  })
  srv <- webfakes::local_app_process(app)

  prov <- oauth_provider_oidc_discover(
    issuer = srv$url(),
    request_object_signing_alg_values_supported = "HS256"
  )

  testthat::expect_identical(
    prov@request_object_signing_alg_values_supported,
    "HS256"
  )
})

testthat::test_that("JWT-only advertisement requires explicit token_auth_style", {
  testthat::skip_if_not_installed("webfakes")
  testthat::skip_on_cran() # webfakes subprocess can timeout on slow CRAN machines
  app <- webfakes::new_app()
  app$get("/.well-known/openid-configuration", function(req, res) {
    issuer_url <- paste0("http://", req$get_header("host"))
    res$set_status(200)$set_type("application/json")$send(
      jsonlite::toJSON(
        list(
          issuer = issuer_url,
          authorization_endpoint = "https://127.0.0.1/auth",
          token_endpoint = "https://127.0.0.1/token",
          jwks_uri = "https://127.0.0.1/jwks",
          token_endpoint_auth_methods_supported = list("private_key_jwt")
        ),
        auto_unbox = TRUE
      )
    )
  })
  srv <- webfakes::local_app_process(app)
  issuer <- srv$url()

  # Should error because we no longer auto-select JWT
  testthat::expect_error(
    oauth_provider_oidc_discover(issuer = issuer),
    class = "shinyOAuth_config_error"
  )

  # When explicitly requested, discovery should pass through
  prov <- oauth_provider_oidc_discover(
    issuer = issuer,
    token_auth_style = "private_key_jwt"
  )
  testthat::expect_identical(prov@token_auth_style, "private_key_jwt")
})


testthat::test_that("mTLS-only advertisement requires explicit token_auth_style", {
  testthat::skip_if_not_installed("webfakes")
  testthat::skip_on_cran()
  app <- webfakes::new_app()
  app$get("/.well-known/openid-configuration", function(req, res) {
    issuer_url <- paste0("http://", req$get_header("host"))
    res$set_status(200)$set_type("application/json")$send(
      jsonlite::toJSON(
        list(
          issuer = issuer_url,
          authorization_endpoint = "https://127.0.0.1/auth",
          token_endpoint = "https://127.0.0.1/token",
          jwks_uri = "https://127.0.0.1/jwks",
          token_endpoint_auth_methods_supported = list("tls_client_auth")
        ),
        auto_unbox = TRUE
      )
    )
  })
  srv <- webfakes::local_app_process(app)
  issuer <- srv$url()

  testthat::expect_error(
    oauth_provider_oidc_discover(issuer = issuer),
    class = "shinyOAuth_config_error"
  )

  prov <- oauth_provider_oidc_discover(
    issuer = issuer,
    token_auth_style = "tls_client_auth"
  )
  testthat::expect_identical(prov@token_auth_style, "tls_client_auth")
})


testthat::test_that("mixed none + client_secret_basic prefers confidential auth", {
  testthat::skip_if_not_installed("webfakes")
  testthat::skip_on_cran()
  app <- webfakes::new_app()
  app$get("/.well-known/openid-configuration", function(req, res) {
    issuer_url <- paste0("http://", req$get_header("host"))
    res$set_status(200)$set_type("application/json")$send(
      jsonlite::toJSON(
        list(
          issuer = issuer_url,
          authorization_endpoint = "https://127.0.0.1/auth",
          token_endpoint = "https://127.0.0.1/token",
          jwks_uri = "https://127.0.0.1/jwks",
          token_endpoint_auth_methods_supported = list(
            "none",
            "client_secret_basic"
          )
        ),
        auto_unbox = TRUE
      )
    )
  })
  srv <- webfakes::local_app_process(app)
  issuer <- srv$url()

  # Even with PKCE enabled, confidential auth (header) should be preferred
  # over public-client 'none' when both are advertised.
  prov <- oauth_provider_oidc_discover(issuer = issuer, use_pkce = TRUE)
  testthat::expect_identical(prov@token_auth_style, "header")

  # Without PKCE, confidential auth should still be selected.
  prov2 <- oauth_provider_oidc_discover(issuer = issuer, use_pkce = FALSE)
  testthat::expect_identical(prov2@token_auth_style, "header")
})


testthat::test_that("mixed none + client_secret_post prefers confidential auth", {
  testthat::skip_if_not_installed("webfakes")
  testthat::skip_on_cran()
  app <- webfakes::new_app()
  app$get("/.well-known/openid-configuration", function(req, res) {
    issuer_url <- paste0("http://", req$get_header("host"))
    res$set_status(200)$set_type("application/json")$send(
      jsonlite::toJSON(
        list(
          issuer = issuer_url,
          authorization_endpoint = "https://127.0.0.1/auth",
          token_endpoint = "https://127.0.0.1/token",
          jwks_uri = "https://127.0.0.1/jwks",
          token_endpoint_auth_methods_supported = list(
            "none",
            "client_secret_post"
          )
        ),
        auto_unbox = TRUE
      )
    )
  })
  srv <- webfakes::local_app_process(app)
  issuer <- srv$url()

  # Confidential 'body' style should win over public 'none' + PKCE
  prov <- oauth_provider_oidc_discover(issuer = issuer, use_pkce = TRUE)
  testthat::expect_identical(prov@token_auth_style, "body")
})


testthat::test_that("when methods are not advertised, fall back to header (historic default)", {
  testthat::skip_if_not_installed("webfakes")
  testthat::skip_on_cran() # webfakes subprocess can timeout on slow CRAN machines
  app <- webfakes::new_app()
  app$get("/.well-known/openid-configuration", function(req, res) {
    issuer_url <- paste0("http://", req$get_header("host"))
    res$set_status(200)$set_type("application/json")$send(
      jsonlite::toJSON(
        list(
          issuer = issuer_url,
          authorization_endpoint = "https://127.0.0.1/auth",
          token_endpoint = "https://127.0.0.1/token",
          jwks_uri = "https://127.0.0.1/jwks"
          # no token_endpoint_auth_methods_supported field
        ),
        auto_unbox = TRUE
      )
    )
  })
  srv <- webfakes::local_app_process(app)
  issuer <- srv$url()

  prov <- oauth_provider_oidc_discover(issuer = issuer)
  testthat::expect_identical(prov@token_auth_style, "header")
})

testthat::test_that("discovery stores JAR, PAR, and JWT auth metadata", {
  testthat::skip_if_not_installed("webfakes")
  testthat::skip_on_cran()
  app <- webfakes::new_app()
  app$get("/.well-known/openid-configuration", function(req, res) {
    issuer_url <- paste0("http://", req$get_header("host"))
    res$set_status(200)$set_type("application/json")$send(
      jsonlite::toJSON(
        list(
          issuer = issuer_url,
          authorization_endpoint = paste0(issuer_url, "/auth"),
          token_endpoint = paste0(issuer_url, "/token"),
          pushed_authorization_request_endpoint = paste0(issuer_url, "/par"),
          jwks_uri = paste0(issuer_url, "/jwks"),
          require_pushed_authorization_requests = TRUE,
          token_endpoint_auth_signing_alg_values_supported = list(
            "PS256",
            "RS256"
          ),
          request_object_signing_alg_values_supported = list(
            "PS256",
            "RS256"
          ),
          require_signed_request_object = TRUE
        ),
        auto_unbox = TRUE
      )
    )
  })
  srv <- webfakes::local_app_process(app)
  issuer <- srv$url()

  prov <- oauth_provider_oidc_discover(issuer = issuer)

  expected_issuer <- sub("/$", "", issuer)
  testthat::expect_identical(prov@par_url, paste0(expected_issuer, "/par"))
  testthat::expect_true(isTRUE(prov@require_pushed_authorization_requests))
  testthat::expect_identical(
    prov@request_object_signing_alg_values_supported,
    c("PS256", "RS256")
  )
  testthat::expect_true(isTRUE(prov@require_signed_request_object))
  testthat::expect_identical(
    prov@token_endpoint_auth_signing_alg_values_supported,
    c("PS256", "RS256")
  )
})

testthat::test_that("discovery stores RFC 8705 mTLS metadata", {
  testthat::skip_if_not_installed("webfakes")
  testthat::skip_on_cran()
  app <- webfakes::new_app()
  app$get("/.well-known/openid-configuration", function(req, res) {
    issuer_url <- paste0("http://", req$get_header("host"))
    res$set_status(200)$set_type("application/json")$send(
      jsonlite::toJSON(
        list(
          issuer = issuer_url,
          authorization_endpoint = paste0(issuer_url, "/auth"),
          token_endpoint = paste0(issuer_url, "/token"),
          userinfo_endpoint = paste0(issuer_url, "/userinfo"),
          jwks_uri = paste0(issuer_url, "/jwks"),
          token_endpoint_auth_methods_supported = list("tls_client_auth"),
          tls_client_certificate_bound_access_tokens = TRUE,
          mtls_endpoint_aliases = list(
            token_endpoint = "https://127.0.0.1/mtls/token",
            userinfo_endpoint = "https://127.0.0.1/mtls/userinfo",
            pushed_authorization_request_endpoint = "https://127.0.0.1/mtls/par"
          )
        ),
        auto_unbox = TRUE
      )
    )
  })
  srv <- webfakes::local_app_process(app)

  prov <- oauth_provider_oidc_discover(
    issuer = srv$url(),
    token_auth_style = "tls_client_auth"
  )

  testthat::expect_true(isTRUE(prov@tls_client_certificate_bound_access_tokens))
  testthat::expect_identical(
    prov@mtls_endpoint_aliases$token_endpoint,
    "https://127.0.0.1/mtls/token"
  )
  testthat::expect_identical(
    prov@mtls_endpoint_aliases$userinfo_endpoint,
    "https://127.0.0.1/mtls/userinfo"
  )
  testthat::expect_identical(
    prov@mtls_endpoint_aliases$par_endpoint,
    "https://127.0.0.1/mtls/par"
  )
})


testthat::test_that("discovery rejects malformed tls_client_certificate_bound_access_tokens", {
  testthat::skip_if_not_installed("webfakes")
  testthat::skip_on_cran()

  expect_malformed_boolean <- function(bad_value) {
    app <- webfakes::new_app()
    app$get("/.well-known/openid-configuration", function(req, res) {
      issuer_url <- paste0("http://", req$get_header("host"))
      res$set_status(200)$set_type("application/json")$send(
        jsonlite::toJSON(
          list(
            issuer = issuer_url,
            authorization_endpoint = paste0(issuer_url, "/auth"),
            token_endpoint = paste0(issuer_url, "/token"),
            jwks_uri = paste0(issuer_url, "/jwks"),
            token_endpoint_auth_methods_supported = list("tls_client_auth"),
            tls_client_certificate_bound_access_tokens = bad_value
          ),
          auto_unbox = TRUE
        )
      )
    })
    srv <- webfakes::local_app_process(app)

    testthat::expect_error(
      oauth_provider_oidc_discover(
        issuer = srv$url(),
        token_auth_style = "tls_client_auth"
      ),
      class = "shinyOAuth_parse_error",
      regexp = "tls_client_certificate_bound_access_tokens"
    )
  }

  expect_malformed_boolean("true")
  expect_malformed_boolean(1)
})
