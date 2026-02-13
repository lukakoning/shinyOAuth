testthat::test_that("discovery selects conservative client auth methods (basic/post) and avoids JWT by default", {
  testthat::skip_if_not_installed("webfakes")
  testthat::skip_on_cran() # webfakes subprocess can timeout on slow CRAN machines
  app <- webfakes::new_app()
  app$get("/.well-known/openid-configuration", function(req, res) {
    res$set_status(200)$set_type("application/json")$send(
      jsonlite::toJSON(
        list(
          authorization_endpoint = "https://127.0.0.1/auth",
          token_endpoint = "https://127.0.0.1/token",
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
    res$set_status(200)$set_type("application/json")$send(
      jsonlite::toJSON(
        list(
          authorization_endpoint = "https://127.0.0.1/auth",
          token_endpoint = "https://127.0.0.1/token",
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


testthat::test_that("discovery with 'none' requires PKCE and uses body when enabled", {
  testthat::skip_if_not_installed("webfakes")
  testthat::skip_on_cran() # webfakes subprocess can timeout on slow CRAN machines
  app <- webfakes::new_app()
  app$get("/.well-known/openid-configuration", function(req, res) {
    res$set_status(200)$set_type("application/json")$send(
      jsonlite::toJSON(
        list(
          authorization_endpoint = "https://127.0.0.1/auth",
          token_endpoint = "https://127.0.0.1/token",
          token_endpoint_auth_methods_supported = list("none")
        ),
        auto_unbox = TRUE
      )
    )
  })
  srv <- webfakes::local_app_process(app)
  issuer <- srv$url()

  # With PKCE (default TRUE), we accept and use body
  prov <- oauth_provider_oidc_discover(issuer = issuer, use_pkce = TRUE)
  testthat::expect_identical(prov@token_auth_style, "body")

  # Without PKCE, configuration error
  testthat::expect_error(
    oauth_provider_oidc_discover(issuer = issuer, use_pkce = FALSE),
    class = "shinyOAuth_config_error"
  )
})


testthat::test_that("JWT-only advertisement requires explicit token_auth_style", {
  testthat::skip_if_not_installed("webfakes")
  testthat::skip_on_cran() # webfakes subprocess can timeout on slow CRAN machines
  app <- webfakes::new_app()
  app$get("/.well-known/openid-configuration", function(req, res) {
    res$set_status(200)$set_type("application/json")$send(
      jsonlite::toJSON(
        list(
          authorization_endpoint = "https://127.0.0.1/auth",
          token_endpoint = "https://127.0.0.1/token",
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


testthat::test_that("mixed none + client_secret_basic prefers confidential auth", {
  testthat::skip_if_not_installed("webfakes")
  testthat::skip_on_cran()
  app <- webfakes::new_app()
  app$get("/.well-known/openid-configuration", function(req, res) {
    res$set_status(200)$set_type("application/json")$send(
      jsonlite::toJSON(
        list(
          authorization_endpoint = "https://127.0.0.1/auth",
          token_endpoint = "https://127.0.0.1/token",
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
    res$set_status(200)$set_type("application/json")$send(
      jsonlite::toJSON(
        list(
          authorization_endpoint = "https://127.0.0.1/auth",
          token_endpoint = "https://127.0.0.1/token",
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
    res$set_status(200)$set_type("application/json")$send(
      jsonlite::toJSON(
        list(
          authorization_endpoint = "https://127.0.0.1/auth",
          token_endpoint = "https://127.0.0.1/token"
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
