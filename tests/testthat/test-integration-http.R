test_that("token exchange HTTP error surfaces as shinyOAuth_http_error", {
  testthat::skip_if_not_installed("webfakes")

  app <- webfakes::new_app()
  app$post("/token", function(req, res) {
    res$status <- 400
    res$set_type("application/json")
    res$send(jsonlite::toJSON(list(error = "invalid_grant"), auto_unbox = TRUE))
  })
  srv <- webfakes::local_app_process(app)
  base <- srv$url()

  prov <- oauth_provider(
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
  cli <- oauth_client(
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

  expect_error(
    shinyOAuth:::handle_callback(
      cli,
      code = "any",
      payload = enc,
      browser_token = tok
    ),
    regexp = "Token exchange failed|access_token|HTTP|error"
  )
})

test_that("userinfo HTTP error surfaces as shinyOAuth_http_error when required", {
  testthat::skip_if_not_installed("webfakes")

  app <- webfakes::new_app()
  app$post("/token", function(req, res) {
    res$json(list(access_token = "t", expires_in = 3600))
  })
  app$get("/userinfo", function(req, res) {
    res$status <- 500
    res$set_type("application/json")
    res$send(jsonlite::toJSON(list(error = "boom"), auto_unbox = TRUE))
  })
  srv <- webfakes::local_app_process(app)
  base <- srv$url()

  prov <- oauth_provider(
    name = "fake",
    auth_url = paste0(base, "/auth"),
    token_url = paste0(base, "/token"),
    userinfo_url = paste0(base, "/userinfo"),
    introspection_url = NA_character_,
    issuer = NA_character_,
    use_nonce = FALSE,
    use_pkce = TRUE,
    pkce_method = "S256",
    userinfo_required = TRUE,
    id_token_required = FALSE,
    id_token_validation = FALSE,
    userinfo_id_token_match = FALSE,
    token_auth_style = "body"
  )
  cli <- oauth_client(
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

  expect_error(
    shinyOAuth:::handle_callback(
      cli,
      code = "ok",
      payload = enc,
      browser_token = tok
    ),
    regexp = "user info|userinfo|Failed to get user info|HTTP"
  )
})

test_that("userinfo success populates token userinfo when required", {
  testthat::skip_if_not_installed("webfakes")

  app <- webfakes::new_app()
  app$post("/token", function(req, res) {
    res$json(list(access_token = "t", expires_in = 60))
  })
  app$get("/userinfo", function(req, res) {
    res$json(list(sub = "u-1", name = "Test"))
  })
  srv <- webfakes::local_app_process(app)
  base <- srv$url()

  prov <- oauth_provider(
    name = "fake",
    auth_url = paste0(base, "/auth"),
    token_url = paste0(base, "/token"),
    userinfo_url = paste0(base, "/userinfo"),
    introspection_url = NA_character_,
    issuer = NA_character_,
    use_nonce = FALSE,
    use_pkce = TRUE,
    pkce_method = "S256",
    userinfo_required = TRUE,
    id_token_required = FALSE,
    id_token_validation = FALSE,
    userinfo_id_token_match = FALSE,
    token_auth_style = "body"
  )
  cli <- oauth_client(
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

  token <- testthat::with_mocked_bindings(
    swap_code_for_token_set = function(client, code, code_verifier) {
      list(access_token = "t", expires_in = 60)
    },
    get_userinfo = function(oauth_client, token) {
      list(sub = "u-1", name = "Test")
    },
    .package = "shinyOAuth",
    shinyOAuth:::handle_callback(
      cli,
      code = "ok",
      payload = enc,
      browser_token = tok
    )
  )
  expect_true(is.list(token@userinfo))
  expect_identical(token@userinfo$sub, "u-1")
})
