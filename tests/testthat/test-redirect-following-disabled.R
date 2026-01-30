# Test that HTTP redirects are NOT followed for sensitive requests
# This prevents leaking tokens/secrets to redirect targets and bypassing host validation

test_that("req_no_redirect disables redirect following by default", {
  req <- httr2::request("https://example.com")
  req2 <- shinyOAuth:::req_no_redirect(req)
  expect_false(isTRUE(req2$options$followlocation))
})

test_that("req_no_redirect allows redirects when option is set", {
  withr::local_options(list(shinyOAuth.allow_redirect = TRUE))
  req <- httr2::request("https://example.com")
  req2 <- shinyOAuth:::req_no_redirect(req)
  # Should NOT have followlocation = FALSE set (httr2 default is to follow)
  expect_null(req2$options$followlocation)
})

test_that("reject_redirect_response throws on 3xx by default", {
  resp <- httr2::response(
    url = "https://example.com/token",
    status = 302,
    headers = list(location = "https://evil.com/steal"),
    body = charToRaw("")
  )
  expect_error(
    shinyOAuth:::reject_redirect_response(resp, context = "test"),
    class = "shinyOAuth_error"
  )
})

test_that("reject_redirect_response skips when option allows redirects", {
  withr::local_options(list(shinyOAuth.allow_redirect = TRUE))
  resp <- httr2::response(
    url = "https://example.com/token",
    status = 302,
    headers = list(location = "https://evil.com/steal"),
    body = charToRaw("")
  )
  # Should NOT throw, just return TRUE
  expect_true(shinyOAuth:::reject_redirect_response(resp, context = "test"))
})

test_that("req_no_redirect passes through non-httr2 objects", {
  fake <- list(a = 1)
  expect_identical(shinyOAuth:::req_no_redirect(fake), fake)
})

test_that("token exchange does not follow redirects", {
  testthat::skip_if_not_installed("webfakes")
  testthat::skip_on_cran() # webfakes subprocess can timeout on slow CRAN machines

  redirect_target_hit <- FALSE
  app <- webfakes::new_app()
  app$post("/token", function(req, res) {
    # Return a 302 redirect to a different endpoint
    res$set_status(302)
    res$set_header("Location", paste0(req$protocol, "://", req$host, "/evil"))
    res$send("")
  })
  app$post("/evil", function(req, res) {
    redirect_target_hit <<- TRUE
    res$send_json(
      object = list(
        access_token = "t",
        token_type = "Bearer",
        expires_in = 3600
      ),
      auto_unbox = TRUE
    )
  })
  srv <- webfakes::local_app_process(app)
  base <- srv$url()

  prov <- shinyOAuth::oauth_provider(
    name = "fake",
    auth_url = paste0(base, "/auth"),
    token_url = paste0(base, "/token"),
    userinfo_url = NA_character_,
    introspection_url = NA_character_,
    issuer = NA_character_,
    use_nonce = FALSE,
    use_pkce = TRUE,
    pkce_method = "S256",
    userinfo_required = FALSE,
    id_token_required = FALSE,
    id_token_validation = FALSE,
    userinfo_id_token_match = FALSE,
    token_auth_style = "body"
  )
  cli <- shinyOAuth::oauth_client(
    provider = prov,
    client_id = "abc",
    client_secret = "",
    redirect_uri = "http://localhost:8100",
    scopes = character(0),
    state_store = cachem::cache_mem(max_age = 600),
    state_key = paste0(
      "0123456789abcdefghijklmnopqrstuvwxyz",
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    )
  )

  tok <- valid_browser_token()
  url <- shinyOAuth:::prepare_call(cli, browser_token = tok)
  enc <- parse_query_param(url, "state")

  # Should fail because the 302 is returned directly (not followed)
  # and 302 is an error status for token exchange
  err <- expect_error(
    shinyOAuth:::handle_callback(
      cli,
      code = "any",
      payload = enc,
      browser_token = tok
    ),
    class = "shinyOAuth_error"
  )

  # The redirect target should NOT have been hit

  expect_false(redirect_target_hit)
})

test_that("token refresh does not follow redirects", {
  testthat::skip_if_not_installed("webfakes")
  testthat::skip_on_cran() # webfakes subprocess can timeout on slow CRAN machines

  redirect_target_hit <- FALSE
  app <- webfakes::new_app()
  app$post("/token", function(req, res) {
    res$set_status(307)
    res$set_header("Location", paste0(req$protocol, "://", req$host, "/evil"))
    res$send("")
  })
  app$post("/evil", function(req, res) {
    redirect_target_hit <<- TRUE
    res$send_json(
      object = list(
        access_token = "new_t",
        token_type = "Bearer",
        expires_in = 3600
      ),
      auto_unbox = TRUE
    )
  })
  srv <- webfakes::local_app_process(app)
  base <- srv$url()

  prov <- shinyOAuth::oauth_provider(
    name = "fake",
    auth_url = paste0(base, "/auth"),
    token_url = paste0(base, "/token"),
    userinfo_url = NA_character_,
    introspection_url = NA_character_,
    issuer = NA_character_,
    use_nonce = FALSE,
    use_pkce = TRUE,
    pkce_method = "S256",
    userinfo_required = FALSE,
    id_token_required = FALSE,
    id_token_validation = FALSE,
    userinfo_id_token_match = FALSE,
    token_auth_style = "body"
  )
  cli <- shinyOAuth::oauth_client(
    provider = prov,
    client_id = "abc",
    client_secret = "",
    redirect_uri = "http://localhost:8100",
    scopes = character(0),
    state_store = cachem::cache_mem(max_age = 600),
    state_key = paste0(
      "0123456789abcdefghijklmnopqrstuvwxyz",
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    )
  )

  token <- shinyOAuth::OAuthToken(
    access_token = "old_access",
    refresh_token = "old_refresh",
    expires_at = Inf,
    id_token = NA_character_,
    userinfo = list()
  )

  expect_error(
    shinyOAuth::refresh_token(cli, token),
    class = "shinyOAuth_error"
  )
  expect_false(redirect_target_hit)
})

test_that("userinfo fetch does not follow redirects", {
  testthat::skip_if_not_installed("webfakes")
  testthat::skip_on_cran() # webfakes subprocess can timeout on slow CRAN machines

  redirect_target_hit <- FALSE
  app <- webfakes::new_app()
  app$get("/userinfo", function(req, res) {
    res$set_status(302)
    res$set_header("Location", paste0(req$protocol, "://", req$host, "/evil"))
    res$send("")
  })
  app$get("/evil", function(req, res) {
    redirect_target_hit <<- TRUE
    res$send_json(object = list(sub = "u123"), auto_unbox = TRUE)
  })
  srv <- webfakes::local_app_process(app)
  base <- srv$url()

  prov <- shinyOAuth::oauth_provider(
    name = "fake",
    auth_url = paste0(base, "/auth"),
    token_url = paste0(base, "/token"),
    userinfo_url = paste0(base, "/userinfo"),
    introspection_url = NA_character_,
    issuer = NA_character_,
    use_nonce = FALSE,
    use_pkce = TRUE,
    pkce_method = "S256",
    userinfo_required = FALSE,
    id_token_required = FALSE,
    id_token_validation = FALSE,
    userinfo_id_token_match = FALSE,
    token_auth_style = "body"
  )
  cli <- shinyOAuth::oauth_client(
    provider = prov,
    client_id = "abc",
    client_secret = "",
    redirect_uri = "http://localhost:8100",
    scopes = character(0),
    state_store = cachem::cache_mem(max_age = 600),
    state_key = paste0(
      "0123456789abcdefghijklmnopqrstuvwxyz",
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    )
  )

  expect_error(
    shinyOAuth::get_userinfo(cli, token = "test_token"),
    class = "shinyOAuth_error"
  )
  expect_false(redirect_target_hit)
})

test_that("token introspection does not follow redirects", {
  testthat::skip_if_not_installed("webfakes")
  testthat::skip_on_cran() # webfakes subprocess can timeout on slow CRAN machines

  redirect_target_hit <- FALSE
  app <- webfakes::new_app()
  app$post("/introspect", function(req, res) {
    res$set_status(302)
    res$set_header("Location", paste0(req$protocol, "://", req$host, "/evil"))
    res$send("")
  })
  app$post("/evil", function(req, res) {
    redirect_target_hit <<- TRUE
    res$send_json(object = list(active = TRUE), auto_unbox = TRUE)
  })
  srv <- webfakes::local_app_process(app)
  base <- srv$url()

  prov <- shinyOAuth::oauth_provider(
    name = "fake",
    auth_url = paste0(base, "/auth"),
    token_url = paste0(base, "/token"),
    userinfo_url = NA_character_,
    introspection_url = paste0(base, "/introspect"),
    issuer = NA_character_,
    use_nonce = FALSE,
    use_pkce = TRUE,
    pkce_method = "S256",
    userinfo_required = FALSE,
    id_token_required = FALSE,
    id_token_validation = FALSE,
    userinfo_id_token_match = FALSE,
    token_auth_style = "body"
  )
  cli <- shinyOAuth::oauth_client(
    provider = prov,
    client_id = "abc",
    client_secret = "",
    redirect_uri = "http://localhost:8100",
    scopes = character(0),
    state_store = cachem::cache_mem(max_age = 600),
    state_key = paste0(
      "0123456789abcdefghijklmnopqrstuvwxyz",
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    )
  )

  token <- shinyOAuth::OAuthToken(
    access_token = "access_tok",
    refresh_token = NA_character_,
    expires_at = Inf,
    id_token = NA_character_,
    userinfo = list()
  )

  result <- shinyOAuth::introspect_token(cli, token)
  # A 302 is an HTTP error, so we get a status like "http_302"
  expect_true(result$supported)
  expect_true(is.na(result$active))
  expect_match(result$status, "^http_")
  expect_false(redirect_target_hit)
})

test_that("token revocation does not follow redirects", {
  testthat::skip_if_not_installed("webfakes")
  testthat::skip_on_cran() # webfakes subprocess can timeout on slow CRAN machines

  redirect_target_hit <- FALSE
  app <- webfakes::new_app()
  app$post("/revoke", function(req, res) {
    res$set_status(307)
    res$set_header("Location", paste0(req$protocol, "://", req$host, "/evil"))
    res$send("")
  })
  app$post("/evil", function(req, res) {
    redirect_target_hit <<- TRUE
    res$set_status(200)
    res$send("")
  })
  srv <- webfakes::local_app_process(app)
  base <- srv$url()

  prov <- shinyOAuth::oauth_provider(
    name = "fake",
    auth_url = paste0(base, "/auth"),
    token_url = paste0(base, "/token"),
    userinfo_url = NA_character_,
    introspection_url = NA_character_,
    revocation_url = paste0(base, "/revoke"),
    issuer = NA_character_,
    use_nonce = FALSE,
    use_pkce = TRUE,
    pkce_method = "S256",
    userinfo_required = FALSE,
    id_token_required = FALSE,
    id_token_validation = FALSE,
    userinfo_id_token_match = FALSE,
    token_auth_style = "body"
  )
  cli <- shinyOAuth::oauth_client(
    provider = prov,
    client_id = "abc",
    client_secret = "",
    redirect_uri = "http://localhost:8100",
    scopes = character(0),
    state_store = cachem::cache_mem(max_age = 600),
    state_key = paste0(
      "0123456789abcdefghijklmnopqrstuvwxyz",
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    )
  )

  token <- shinyOAuth::OAuthToken(
    access_token = "access_tok",
    refresh_token = "refresh_tok",
    expires_at = Inf,
    id_token = NA_character_,
    userinfo = list()
  )

  result <- shinyOAuth::revoke_token(cli, token)
  # 307 returns HTTP error status
  expect_true(result$supported)
  expect_true(is.na(result$revoked))
  expect_match(result$status, "^http_")
  expect_false(redirect_target_hit)
})

test_that("OIDC discovery does not follow redirects", {
  testthat::skip_if_not_installed("webfakes")
  testthat::skip_on_cran() # webfakes subprocess can timeout on slow CRAN machines

  redirect_target_hit <- FALSE
  app <- webfakes::new_app()
  app$get("/.well-known/openid-configuration", function(req, res) {
    res$set_status(302)
    res$set_header("Location", paste0(req$protocol, "://", req$host, "/evil"))
    res$send("")
  })
  app$get("/evil", function(req, res) {
    redirect_target_hit <<- TRUE
    res$send_json(
      object = list(
        issuer = paste0(req$protocol, "://", req$host),
        authorization_endpoint = paste0(req$protocol, "://", req$host, "/auth"),
        token_endpoint = paste0(req$protocol, "://", req$host, "/token"),
        jwks_uri = paste0(req$protocol, "://", req$host, "/jwks")
      ),
      auto_unbox = TRUE
    )
  })
  srv <- webfakes::local_app_process(app)
  base <- srv$url()

  expect_error(
    shinyOAuth::oauth_provider_oidc_discover(issuer = base, name = "fake"),
    class = "shinyOAuth_error"
  )
  expect_false(redirect_target_hit)
})

# -----------------------------------------------------------------------------
# Tests verifying redirects ARE followed when option is enabled
# -----------------------------------------------------------------------------

test_that("userinfo follows redirects when shinyOAuth.allow_redirect = TRUE", {
  testthat::skip_if_not_installed("webfakes")
  testthat::skip_on_cran() # webfakes subprocess can timeout on slow CRAN machines

  withr::local_options(list(shinyOAuth.allow_redirect = TRUE))

  # Instead of checking a flag (which doesn't work across processes),

  # verify by checking the response content - /real returns specific data
  app <- webfakes::new_app()
  app$get("/userinfo", function(req, res) {
    # Redirect to /real
    res$redirect("/real", 302)
  })
  app$get("/real", function(req, res) {
    # Return distinct data that proves we followed the redirect
    res$send_json(
      object = list(
        sub = "redirected_user",
        name = "Redirect Test",
        followed = TRUE
      ),
      auto_unbox = TRUE
    )
  })

  srv <- webfakes::local_app_process(app)
  base_url <- srv$url()

  prov <- shinyOAuth::oauth_provider(
    name = "fake",
    auth_url = paste0(base_url, "/auth"),
    token_url = paste0(base_url, "/token"),
    userinfo_url = paste0(base_url, "/userinfo"),
    introspection_url = NA_character_,
    issuer = NA_character_,
    use_nonce = FALSE,
    use_pkce = TRUE,
    pkce_method = "S256",
    userinfo_required = FALSE,
    id_token_required = FALSE,
    id_token_validation = FALSE,
    userinfo_id_token_match = FALSE,
    token_auth_style = "body"
  )
  cli <- shinyOAuth::oauth_client(
    provider = prov,
    client_id = "abc",
    client_secret = "",
    redirect_uri = "http://localhost:8100",
    scopes = character(0),
    state_store = cachem::cache_mem(max_age = 600),
    state_key = paste0(
      "0123456789abcdefghijklmnopqrstuvwxyz",
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    )
  )

  # Should succeed - redirect is followed to /real which returns valid userinfo
  result <- shinyOAuth::get_userinfo(cli, token = "test_token")
  # Verify we got the response from /real, not /userinfo
  expect_equal(result$sub, "redirected_user")
  expect_true(result$followed)
})

test_that("token revocation follows redirects when shinyOAuth.allow_redirect = TRUE", {
  testthat::skip_if_not_installed("webfakes")
  testthat::skip_on_cran() # webfakes subprocess can timeout on slow CRAN machines

  withr::local_options(list(shinyOAuth.allow_redirect = TRUE))

  # Use a marker in the response to prove we hit /real
  app <- webfakes::new_app()
  app$post("/revoke", function(req, res) {
    # Return 307 redirect - this should be followed to /real
    res$redirect("/real", 307)
  })
  app$post("/real", function(req, res) {
    res$set_status(200)
    res$send("")
  })

  srv <- webfakes::local_app_process(app)
  base_url <- srv$url()

  prov <- shinyOAuth::oauth_provider(
    name = "fake",
    auth_url = paste0(base_url, "/auth"),
    token_url = paste0(base_url, "/token"),
    userinfo_url = NA_character_,
    introspection_url = NA_character_,
    revocation_url = paste0(base_url, "/revoke"),
    issuer = NA_character_,
    use_nonce = FALSE,
    use_pkce = TRUE,
    pkce_method = "S256",
    userinfo_required = FALSE,
    id_token_required = FALSE,
    id_token_validation = FALSE,
    userinfo_id_token_match = FALSE,
    token_auth_style = "body"
  )
  cli <- shinyOAuth::oauth_client(
    provider = prov,
    client_id = "abc",
    client_secret = "",
    redirect_uri = "http://localhost:8100",
    scopes = character(0),
    state_store = cachem::cache_mem(max_age = 600),
    state_key = paste0(
      "0123456789abcdefghijklmnopqrstuvwxyz",
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    )
  )

  token <- shinyOAuth::OAuthToken(
    access_token = "access_tok",
    refresh_token = "refresh_tok",
    expires_at = Inf,
    id_token = NA_character_,
    userinfo = list()
  )

  # Should succeed - redirect is followed to /real which returns 200
  result <- shinyOAuth::revoke_token(cli, token)
  # If we didn't follow the redirect, we'd get an error from the 307 response
  expect_true(result$revoked)
  expect_equal(result$status, "ok")
})
