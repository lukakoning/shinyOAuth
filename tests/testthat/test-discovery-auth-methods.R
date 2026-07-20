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
          response_types_supported = list("code"),
          subject_types_supported = list("public"),
          id_token_signing_alg_values_supported = list("RS256"),
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
          response_types_supported = list("code"),
          subject_types_supported = list("public"),
          id_token_signing_alg_values_supported = list("RS256"),
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
          response_types_supported = list("code"),
          subject_types_supported = list("public"),
          id_token_signing_alg_values_supported = list("RS256"),
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

testthat::test_that("public discovery auth does not read env client_secret", {
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
          response_types_supported = list("code"),
          subject_types_supported = list("public"),
          id_token_signing_alg_values_supported = list("RS256"),
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
    client_secret = "",
    redirect_uri = "http://localhost:8100",
    scopes = character(0)
  )
  testthat::expect_identical(cl@client_secret, "")

  prepared <- shinyOAuth:::apply_direct_client_auth(
    req = httr2::request("https://127.0.0.1/token"),
    params = list(grant_type = "authorization_code"),
    client = cl,
    context = "token_exchange"
  )
  testthat::expect_identical(
    prepared[["params"]][["client_id"]],
    "abc"
  )
  testthat::expect_null(
    prepared[["params"]][["client_secret"]]
  )
})

testthat::test_that("oidc discovery transport errors include discovery url and transport detail", {
  testthat::local_mocked_bindings(
    req_with_retry = function(req) {
      stop("forced discovery transport fail")
    },
    .package = "shinyOAuth"
  )

  err <- tryCatch(
    oauth_provider_oidc_discover("https://issuer.example.com/tenant"),
    error = identity
  )

  testthat::expect_s3_class(err, "shinyOAuth_http_error")
  testthat::expect_identical(
    err$context$discovery_url,
    "https://issuer.example.com/tenant/.well-known/openid-configuration"
  )

  msg <- conditionMessage(err)
  testthat::expect_match(
    msg,
    "Failed to fetch OIDC discovery document",
    fixed = TRUE
  )
  testthat::expect_match(
    msg,
    "forced discovery transport fail",
    fixed = TRUE
  )
  testthat::expect_match(
    msg,
    "https://issuer.example.com/tenant/.well-known/openid-configuration",
    fixed = TRUE
  )
  testthat::expect_match(
    msg,
    "Issuer: https://issuer.example.com/tenant",
    fixed = TRUE
  )
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
          response_types_supported = list("code"),
          subject_types_supported = list("public"),
          id_token_signing_alg_values_supported = list("RS256"),
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

test_that("oidc discovery preserves request-object encryption metadata", {
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
          response_types_supported = list("code"),
          subject_types_supported = list("public"),
          id_token_signing_alg_values_supported = list("RS256"),
          request_object_encryption_alg_values_supported = list(
            "RSA-OAEP",
            "ECDH-ES"
          ),
          request_object_encryption_enc_values_supported = list(
            "A256CBC-HS512",
            "A256GCM"
          )
        ),
        auto_unbox = TRUE
      )
    )
  })
  srv <- webfakes::local_app_process(app)

  prov <- oauth_provider_oidc_discover(issuer = srv$url())

  testthat::expect_identical(
    prov@request_object_encryption_alg_values_supported,
    c("RSA-OAEP", "ECDH-ES")
  )
  testthat::expect_identical(
    prov@request_object_encryption_enc_values_supported,
    c("A256CBC-HS512", "A256GCM")
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
          response_types_supported = list("code"),
          subject_types_supported = list("public"),
          id_token_signing_alg_values_supported = list("RS256"),
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

test_that("oidc discovery preserves authorization request transport metadata", {
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
          response_types_supported = list("code"),
          subject_types_supported = list("public"),
          id_token_signing_alg_values_supported = list("RS256"),
          request_parameter_supported = FALSE,
          request_uri_parameter_supported = TRUE,
          require_request_uri_registration = TRUE
        ),
        auto_unbox = TRUE
      )
    )
  })
  srv <- webfakes::local_app_process(app)

  prov <- oauth_provider_oidc_discover(issuer = srv$url())

  testthat::expect_identical(prov@request_parameter_supported, FALSE)
  testthat::expect_identical(prov@request_uri_parameter_supported, TRUE)
  testthat::expect_identical(prov@request_uri_registration_required, TRUE)
})

test_that("discovery applies default request transport metadata when omitted", {
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
          response_types_supported = list("code"),
          subject_types_supported = list("public"),
          id_token_signing_alg_values_supported = list("RS256")
        ),
        auto_unbox = TRUE
      )
    )
  })
  srv <- webfakes::local_app_process(app)

  prov <- oauth_provider_oidc_discover(issuer = srv$url())

  testthat::expect_identical(prov@request_parameter_supported, FALSE)
  testthat::expect_identical(prov@request_uri_parameter_supported, TRUE)
  testthat::expect_identical(prov@request_uri_registration_required, FALSE)
})

test_that("oidc discovery allows PAR when caller-managed request_uri is disabled", {
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
          response_types_supported = list("code"),
          subject_types_supported = list("public"),
          id_token_signing_alg_values_supported = list("RS256"),
          pushed_authorization_request_endpoint = paste0(issuer_url, "/par"),
          request_uri_parameter_supported = FALSE
        ),
        auto_unbox = TRUE
      )
    )
  })
  srv <- webfakes::local_app_process(app)

  prov <- oauth_provider_oidc_discover(issuer = srv$url())

  testthat::expect_identical(
    prov@par_url,
    paste0(sub("/+$", "", srv$url()), "/par")
  )
  testthat::expect_identical(prov@request_uri_parameter_supported, FALSE)
})

test_that("request mode remains available when PAR carries the request object", {
  prov <- shinyOAuth::oauth_provider(
    name = "example",
    auth_url = "https://example.com/auth",
    token_url = "https://example.com/token",
    par_url = "https://example.com/par",
    issuer = "https://issuer.example.com",
    use_nonce = FALSE,
    use_pkce = TRUE,
    id_token_required = FALSE,
    id_token_validation = FALSE,
    request_parameter_supported = FALSE,
    allowed_token_types = character()
  )

  cli <- testthat::expect_no_error(
    shinyOAuth::oauth_client(
      provider = prov,
      client_id = "abc",
      client_secret = paste(rep("s", 32), collapse = ""),
      redirect_uri = "http://localhost:8100",
      scopes = c("openid"),
      state_store = cachem::cache_mem(max_age = 60),
      state_key = paste0(
        "0123456789abcdefghijklmnopqrstuvwxyz",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
      ),
      request_object_mode = "request"
    )
  )

  testthat::expect_s3_class(cli, "shinyOAuth::OAuthClient")
})

test_that("discovery blocks request mode when request transport is unsupported and PAR is absent", {
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
          response_types_supported = list("code"),
          subject_types_supported = list("public"),
          id_token_signing_alg_values_supported = list("RS256"),
          request_parameter_supported = FALSE
        ),
        auto_unbox = TRUE
      )
    )
  })
  srv <- webfakes::local_app_process(app)

  prov <- oauth_provider_oidc_discover(issuer = srv$url())

  testthat::expect_identical(prov@request_parameter_supported, FALSE)
  testthat::expect_error(
    shinyOAuth::oauth_client(
      provider = prov,
      client_id = "abc",
      client_secret = paste(rep("s", 32), collapse = ""),
      redirect_uri = "http://localhost:8100",
      scopes = c("openid"),
      state_store = cachem::cache_mem(max_age = 60),
      state_key = paste0(
        "0123456789abcdefghijklmnopqrstuvwxyz",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
      ),
      request_object_mode = "request"
    ),
    regexp = paste(
      "provider discovery metadata says request parameter transport is not supported;",
      "request_object_mode = 'request' cannot be used unless PAR is configured"
    )
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
          response_types_supported = list("code"),
          subject_types_supported = list("public"),
          id_token_signing_alg_values_supported = list("RS256"),
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
          response_types_supported = list("code"),
          subject_types_supported = list("public"),
          id_token_signing_alg_values_supported = list("RS256"),
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
          response_types_supported = list("code"),
          subject_types_supported = list("public"),
          id_token_signing_alg_values_supported = list("RS256"),
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
          response_types_supported = list("code"),
          subject_types_supported = list("public"),
          id_token_signing_alg_values_supported = list("RS256"),
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
          response_types_supported = list("code"),
          subject_types_supported = list("public"),
          id_token_signing_alg_values_supported = list("RS256"),
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
          jwks_uri = "https://127.0.0.1/jwks",
          response_types_supported = list("code"),
          subject_types_supported = list("public"),
          id_token_signing_alg_values_supported = list("RS256")
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
          response_types_supported = list("code"),
          subject_types_supported = list("public"),
          id_token_signing_alg_values_supported = list("RS256"),
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
  testthat::expect_true(isTRUE(prov@par_required))
  testthat::expect_identical(
    prov@request_object_signing_alg_values_supported,
    c("PS256", "RS256")
  )
  testthat::expect_true(isTRUE(prov@signed_request_object_required))
  testthat::expect_identical(
    prov@token_endpoint_auth_signing_alg_values_supported,
    c("PS256", "RS256")
  )
})

testthat::test_that("discovery stores RFC 9449 DPoP metadata", {
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
          response_types_supported = list("code"),
          subject_types_supported = list("public"),
          id_token_signing_alg_values_supported = list("RS256"),
          dpop_signing_alg_values_supported = list("ES256", "RS256")
        ),
        auto_unbox = TRUE
      )
    )
  })
  srv <- webfakes::local_app_process(app)

  prov <- oauth_provider_oidc_discover(issuer = srv$url())

  testthat::expect_identical(
    prov@dpop_signing_alg_values_supported,
    c("ES256", "RS256")
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
          response_types_supported = list("code"),
          subject_types_supported = list("public"),
          id_token_signing_alg_values_supported = list("RS256"),
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

  testthat::expect_true(isTRUE(
    prov@mtls_client_certificate_bound_access_tokens
  ))
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
            response_types_supported = list("code"),
            subject_types_supported = list("public"),
            id_token_signing_alg_values_supported = list("RS256"),
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
