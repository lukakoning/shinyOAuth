testthat::test_that("discovery enforces absolute endpoints and host pinning; allows loopback HTTP via is_ok_host", {
  testthat::skip_if_not_installed("webfakes")
  testthat::skip_on_cran() # webfakes subprocess can timeout on slow CRAN machines
  app <- webfakes::new_app()

  app$get("/.well-known/openid-configuration", function(req, res) {
    # issuer host for this test is 127.0.0.1 (no need to match port; validation uses hostname)
    issuer_url <- paste0("http://", req$get_header("host"))
    res$set_status(200)$set_type("application/json")$send(
      jsonlite::toJSON(
        list(
          issuer = issuer_url,
          authorization_endpoint = "https://127.0.0.1/auth",
          token_endpoint = "http://127.0.0.1/token",
          jwks_uri = "https://127.0.0.1/jwks"
        ),
        auto_unbox = TRUE
      )
    )
  })

  srv <- webfakes::local_app_process(app)
  issuer <- srv$url()

  prov <- NULL
  testthat::expect_no_error({
    prov <- oauth_provider_oidc_discover(issuer = issuer)
  })
  testthat::expect_s3_class(prov, "S7_object")
  testthat::expect_true(grepl("^http://127.0.0.1/token", prov@token_url))

  # Relative endpoint should be rejected
  app2 <- webfakes::new_app()
  app2$get("/.well-known/openid-configuration", function(req, res) {
    issuer_url <- paste0("http://", req$get_header("host"))
    res$set_status(200)$set_type("application/json")$send(
      jsonlite::toJSON(
        list(
          issuer = issuer_url,
          authorization_endpoint = "token", # relative -> invalid
          token_endpoint = "token"
        ),
        auto_unbox = TRUE
      )
    )
  })
  srv2 <- webfakes::local_app_process(app2)
  issuer2 <- srv2$url()
  testthat::expect_error(
    oauth_provider_oidc_discover(issuer = issuer2),
    class = "shinyOAuth_config_error"
  )

  # Host mismatch should be rejected
  app3 <- webfakes::new_app()
  app3$get("/.well-known/openid-configuration", function(req, res) {
    issuer_url <- paste0("http://", req$get_header("host"))
    res$set_status(200)$set_type("application/json")$send(
      jsonlite::toJSON(
        list(
          issuer = issuer_url,
          authorization_endpoint = "https://127.0.0.1/auth",
          token_endpoint = "https://evil.example.com/token"
        ),
        auto_unbox = TRUE
      )
    )
  })
  srv3 <- webfakes::local_app_process(app3)
  issuer3 <- srv3$url()
  testthat::expect_error(
    oauth_provider_oidc_discover(issuer = issuer3),
    class = "shinyOAuth_config_error"
  )
})

testthat::test_that("discovery enforces JWKS host pinning early", {
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
          jwks_uri = "https://evil.example.com/jwks.json"
        ),
        auto_unbox = TRUE
      )
    )
  })
  srv <- webfakes::local_app_process(app)
  issuer <- srv$url()

  testthat::expect_error(
    oauth_provider_oidc_discover(
      issuer = issuer,
      jwks_host_issuer_match = TRUE
    ),
    class = "shinyOAuth_config_error"
  )
})

testthat::test_that("discovery rejects JWKS issuer subdomains by default", {
  testthat::local_mocked_bindings(
    .discover_fetch_response = function(req, issuer) {
      structure(list(), class = "mock_discovery_response")
    },
    .discover_parse_json = function(resp) {
      list(
        issuer = "https://issuer.example.com",
        authorization_endpoint = "https://issuer.example.com/auth",
        token_endpoint = "https://issuer.example.com/token",
        jwks_uri = "https://sub.issuer.example.com/jwks.json"
      )
    },
    .package = "shinyOAuth"
  )

  testthat::expect_error(
    oauth_provider_oidc_discover(
      issuer = "https://issuer.example.com",
      jwks_host_issuer_match = TRUE
    ),
    class = "shinyOAuth_config_error"
  )
})

testthat::test_that("discovery honors jwks_host_allow_only during early JWKS checks", {
  testthat::local_mocked_bindings(
    .discover_fetch_response = function(req, issuer) {
      structure(list(), class = "mock_discovery_response")
    },
    .discover_parse_json = function(resp) {
      list(
        issuer = "https://issuer.example.com",
        authorization_endpoint = "https://issuer.example.com/auth",
        token_endpoint = "https://issuer.example.com/token",
        jwks_uri = "https://keys.example.com/jwks.json"
      )
    },
    .package = "shinyOAuth"
  )

  prov <- oauth_provider_oidc_discover(
    issuer = "https://issuer.example.com",
    jwks_host_issuer_match = TRUE,
    jwks_host_allow_only = "keys.example.com"
  )

  testthat::expect_identical(prov@jwks_host_allow_only, "keys.example.com")
  testthat::expect_identical(prov@jwks_host_issuer_match, TRUE)
})

testthat::test_that("discovery requires jwks_uri when ID token validation is enabled", {
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
          token_endpoint = "https://127.0.0.1/token"
        ),
        auto_unbox = TRUE
      )
    )
  })
  srv <- webfakes::local_app_process(app)
  issuer <- srv$url()

  testthat::expect_error(
    oauth_provider_oidc_discover(issuer = issuer),
    class = "shinyOAuth_config_error",
    regexp = "jwks_uri"
  )

  prov <- NULL
  testthat::expect_no_error({
    prov <- oauth_provider_oidc_discover(
      issuer = issuer,
      id_token_validation = FALSE
    )
  })
  testthat::expect_s3_class(prov, "S7_object")
})

testthat::test_that("allowed_hosts option allows cross-host endpoints", {
  testthat::skip_if_not_installed("webfakes")
  testthat::skip_on_cran() # webfakes subprocess can timeout on slow CRAN machines
  app <- webfakes::new_app()
  app$get("/.well-known/openid-configuration", function(req, res) {
    issuer_url <- paste0("http://", req$get_header("host"))
    res$set_status(200)$set_type("application/json")$send(
      jsonlite::toJSON(
        list(
          issuer = issuer_url,
          authorization_endpoint = "https://api.example.com/auth",
          token_endpoint = "https://api.example.com/token",
          jwks_uri = "https://api.example.com/jwks"
        ),
        auto_unbox = TRUE
      )
    )
  })
  srv <- webfakes::local_app_process(app)
  issuer <- srv$url()

  withr::local_options(list(
    shinyOAuth.allowed_hosts = c("127.0.0.1", "api.example.com")
  ))
  prov <- oauth_provider_oidc_discover(issuer = issuer)
  testthat::expect_s3_class(prov, "S7_object")
  testthat::expect_true(grepl("^https://api.example.com/token", prov@token_url))
})

testthat::test_that("discovery rejects separate-host mTLS aliases by default", {
  testthat::skip_if_not_installed("webfakes")
  testthat::skip_on_cran() # webfakes subprocess can timeout on slow CRAN machines
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
          mtls_endpoint_aliases = list(
            token_endpoint = "https://mtls.example.com/token",
            introspection_endpoint = "https://mtls.example.com/introspect",
            revocation_endpoint = "https://mtls.example.com/revoke"
          )
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
    class = "shinyOAuth_config_error",
    regexp = "Allowed hosts"
  )
})

testthat::test_that("discovery allows separate-host mTLS aliases when allowed_hosts permits them", {
  testthat::skip_if_not_installed("webfakes")
  testthat::skip_on_cran() # webfakes subprocess can timeout on slow CRAN machines
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
          mtls_endpoint_aliases = list(
            token_endpoint = "https://mtls.example.com/token",
            introspection_endpoint = "https://mtls.example.com/introspect",
            revocation_endpoint = "https://mtls.example.com/revoke"
          )
        ),
        auto_unbox = TRUE
      )
    )
  })

  srv <- webfakes::local_app_process(app)
  withr::local_options(list(
    shinyOAuth.allowed_hosts = c("127.0.0.1", "mtls.example.com")
  ))

  prov <- oauth_provider_oidc_discover(
    issuer = srv$url(),
    token_auth_style = "tls_client_auth"
  )

  testthat::expect_identical(
    prov@mtls_endpoint_aliases$token_endpoint,
    "https://mtls.example.com/token"
  )
  testthat::expect_identical(
    prov@mtls_endpoint_aliases$introspection_endpoint,
    "https://mtls.example.com/introspect"
  )
  testthat::expect_identical(
    prov@mtls_endpoint_aliases$revocation_endpoint,
    "https://mtls.example.com/revoke"
  )
})

testthat::test_that("explicit allowed_hosts still constrains discovered mTLS aliases", {
  testthat::skip_if_not_installed("webfakes")
  testthat::skip_on_cran() # webfakes subprocess can timeout on slow CRAN machines
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
          mtls_endpoint_aliases = list(
            token_endpoint = "https://mtls.example.com/token"
          )
        ),
        auto_unbox = TRUE
      )
    )
  })

  srv <- webfakes::local_app_process(app)
  withr::local_options(list(shinyOAuth.allowed_hosts = "127.0.0.1"))

  testthat::expect_error(
    oauth_provider_oidc_discover(
      issuer = srv$url(),
      token_auth_style = "tls_client_auth"
    ),
    class = "shinyOAuth_config_error",
    regexp = "Allowed hosts"
  )
})

testthat::test_that("discovery rejects non-JSON content-type", {
  testthat::skip_if_not_installed("webfakes")
  testthat::skip_on_cran() # webfakes subprocess can timeout on slow CRAN machines
  app <- webfakes::new_app()
  app$get("/.well-known/openid-configuration", function(req, res) {
    res$set_status(200)$set_header("content-type", "text/plain")$send("ok")
  })
  srv <- webfakes::local_app_process(app)
  issuer <- srv$url()

  testthat::expect_error(
    oauth_provider_oidc_discover(issuer = issuer),
    class = "shinyOAuth_parse_error"
  )
})

testthat::test_that("discovery rejects duplicate issuer members", {
  testthat::skip_if_not_installed("webfakes")
  testthat::skip_on_cran()

  app <- webfakes::new_app()
  app$get("/.well-known/openid-configuration", function(req, res) {
    issuer_url <- paste0("http://", req$get_header("host"))
    res$set_status(200)$set_type("application/json")$send(
      paste0(
        '{"issuer":"',
        issuer_url,
        '","issuer":"',
        issuer_url,
        '","authorization_endpoint":"https://127.0.0.1/auth"',
        ',"token_endpoint":"https://127.0.0.1/token"',
        ',"jwks_uri":"https://127.0.0.1/jwks"}'
      )
    )
  })
  srv <- webfakes::local_app_process(app)

  testthat::expect_error(
    oauth_provider_oidc_discover(issuer = srv$url()),
    class = "shinyOAuth_parse_error",
    regexp = "duplicate member name: issuer"
  )
})

testthat::test_that("discovery errors when S256 is not advertised and plain is not explicit", {
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
          code_challenge_methods_supported = list("plain")
        ),
        auto_unbox = TRUE
      )
    )
  })
  srv <- webfakes::local_app_process(app)
  issuer <- srv$url()

  testthat::expect_error(
    oauth_provider_oidc_discover(issuer = issuer, use_pkce = TRUE),
    class = "shinyOAuth_config_error",
    regexp = "does not advertise PKCE S256 support|pkce_method = 'plain'"
  )
})

testthat::test_that("discovery rejects invalid explicit pkce_method values", {
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
          code_challenge_methods_supported = list("S256", "plain")
        ),
        auto_unbox = TRUE
      )
    )
  })
  srv <- webfakes::local_app_process(app)
  issuer <- srv$url()

  testthat::expect_error(
    oauth_provider_oidc_discover(
      issuer = issuer,
      use_pkce = TRUE,
      pkce_method = "s512"
    ),
    class = "shinyOAuth_config_error",
    regexp = "pkce_method must be 'S256' or 'plain'"
  )
})

testthat::test_that("discovery allows explicit plain PKCE downgrade when advertised", {
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
          code_challenge_methods_supported = list("plain")
        ),
        auto_unbox = TRUE
      )
    )
  })
  srv <- webfakes::local_app_process(app)
  issuer <- srv$url()

  prov <- oauth_provider_oidc_discover(
    issuer = issuer,
    use_pkce = TRUE,
    pkce_method = "plain"
  )

  testthat::expect_identical(prov@pkce_method, "plain")
})

testthat::test_that("discovery does NOT auto-enable userinfo_signed_jwt_required from signing algs (capability != requirement)", {
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
          userinfo_endpoint = "https://127.0.0.1/userinfo",
          jwks_uri = "https://127.0.0.1/jwks",
          userinfo_signing_alg_values_supported = list("RS256", "ES256")
        ),
        auto_unbox = TRUE
      )
    )
  })
  srv <- webfakes::local_app_process(app)
  issuer <- srv$url()

  # userinfo_signing_alg_values_supported advertises provider *capability*,
  # not that every client receives signed JWTs. Discovery must not auto-enable.
  prov <- oauth_provider_oidc_discover(issuer = issuer)
  testthat::expect_false(prov@userinfo_signed_jwt_required)
})

testthat::test_that("discovery does NOT auto-enable userinfo_signed_jwt_required when no overlap", {
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
          userinfo_endpoint = "https://127.0.0.1/userinfo",
          jwks_uri = "https://127.0.0.1/jwks",
          userinfo_signing_alg_values_supported = list("none")
        ),
        auto_unbox = TRUE
      )
    )
  })
  srv <- webfakes::local_app_process(app)
  issuer <- srv$url()

  prov <- oauth_provider_oidc_discover(issuer = issuer)
  testthat::expect_false(prov@userinfo_signed_jwt_required)
})

testthat::test_that("discovery does NOT auto-enable when field absent", {
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
          userinfo_endpoint = "https://127.0.0.1/userinfo",
          jwks_uri = "https://127.0.0.1/jwks"
        ),
        auto_unbox = TRUE
      )
    )
  })
  srv <- webfakes::local_app_process(app)
  issuer <- srv$url()

  prov <- oauth_provider_oidc_discover(issuer = issuer)
  testthat::expect_false(prov@userinfo_signed_jwt_required)
})

testthat::test_that("discovery respects explicit userinfo_signed_jwt_required = TRUE override", {
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
          userinfo_endpoint = "https://127.0.0.1/userinfo",
          jwks_uri = "https://127.0.0.1/jwks",
          userinfo_signing_alg_values_supported = list("RS256")
        ),
        auto_unbox = TRUE
      )
    )
  })
  srv <- webfakes::local_app_process(app)
  issuer <- srv$url()

  prov <- oauth_provider_oidc_discover(
    issuer = issuer,
    userinfo_signed_jwt_required = TRUE
  )
  testthat::expect_true(prov@userinfo_signed_jwt_required)
})
