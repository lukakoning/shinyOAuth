testthat::test_that("discovery enforces absolute endpoints and host pinning; allows loopback HTTP via is_ok_host", {
  testthat::skip_if_not_installed("webfakes")
  testthat::skip_on_cran() # webfakes subprocess can timeout on slow CRAN machines
  app <- webfakes::new_app()

  app$get("/.well-known/openid-configuration", function(req, res) {
    # issuer host for this test is 127.0.0.1 (no need to match port; validation uses hostname)
    res$set_status(200)$set_type("application/json")$send(
      jsonlite::toJSON(
        list(
          authorization_endpoint = "https://127.0.0.1/auth",
          token_endpoint = "http://127.0.0.1/token"
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
    res$set_status(200)$set_type("application/json")$send(
      jsonlite::toJSON(
        list(
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
    res$set_status(200)$set_type("application/json")$send(
      jsonlite::toJSON(
        list(
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
    res$set_status(200)$set_type("application/json")$send(
      jsonlite::toJSON(
        list(
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

testthat::test_that("allowed_hosts option allows cross-host endpoints", {
  testthat::skip_if_not_installed("webfakes")
  testthat::skip_on_cran() # webfakes subprocess can timeout on slow CRAN machines
  app <- webfakes::new_app()
  app$get("/.well-known/openid-configuration", function(req, res) {
    res$set_status(200)$set_type("application/json")$send(
      jsonlite::toJSON(
        list(
          authorization_endpoint = "https://api.example.com/auth",
          token_endpoint = "https://api.example.com/token"
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

testthat::test_that("PKCE advisory does not block provider when S256 not advertised", {
  testthat::skip_if_not_installed("webfakes")
  testthat::skip_on_cran() # webfakes subprocess can timeout on slow CRAN machines
  app <- webfakes::new_app()
  app$get("/.well-known/openid-configuration", function(req, res) {
    res$set_status(200)$set_type("application/json")$send(
      jsonlite::toJSON(
        list(
          authorization_endpoint = "https://127.0.0.1/auth",
          token_endpoint = "https://127.0.0.1/token",
          code_challenge_methods_supported = list("plain")
        ),
        auto_unbox = TRUE
      )
    )
  })
  srv <- webfakes::local_app_process(app)
  issuer <- srv$url()

  testthat::expect_no_error(
    oauth_provider_oidc_discover(issuer = issuer, use_pkce = TRUE)
  )
})

testthat::test_that("discovery does NOT auto-enable userinfo_signed_jwt_required from signing algs (capability != requirement)", {
  testthat::skip_if_not_installed("webfakes")
  testthat::skip_on_cran()
  app <- webfakes::new_app()
  app$get("/.well-known/openid-configuration", function(req, res) {
    res$set_status(200)$set_type("application/json")$send(
      jsonlite::toJSON(
        list(
          authorization_endpoint = "https://127.0.0.1/auth",
          token_endpoint = "https://127.0.0.1/token",
          userinfo_endpoint = "https://127.0.0.1/userinfo",
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
    res$set_status(200)$set_type("application/json")$send(
      jsonlite::toJSON(
        list(
          authorization_endpoint = "https://127.0.0.1/auth",
          token_endpoint = "https://127.0.0.1/token",
          userinfo_endpoint = "https://127.0.0.1/userinfo",
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
    res$set_status(200)$set_type("application/json")$send(
      jsonlite::toJSON(
        list(
          authorization_endpoint = "https://127.0.0.1/auth",
          token_endpoint = "https://127.0.0.1/token",
          userinfo_endpoint = "https://127.0.0.1/userinfo"
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
    res$set_status(200)$set_type("application/json")$send(
      jsonlite::toJSON(
        list(
          authorization_endpoint = "https://127.0.0.1/auth",
          token_endpoint = "https://127.0.0.1/token",
          userinfo_endpoint = "https://127.0.0.1/userinfo",
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
