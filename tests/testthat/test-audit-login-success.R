testthat::test_that("audit_login_success marks unvalidated ID token subjects as unverified", {
  events <- list()
  withr::local_options(list(
    shinyOAuth.skip_id_sig = TRUE,
    shinyOAuth.audit_hook = function(event) {
      events[[length(events) + 1L]] <<- event
    }
  ))

  prov <- oauth_provider(
    name = "audit-test",
    auth_url = "https://example.com/auth",
    token_url = "https://example.com/token",
    userinfo_url = NA_character_,
    introspection_url = NA_character_,
    issuer = "https://issuer.example.com",
    use_nonce = FALSE,
    use_pkce = TRUE,
    pkce_method = "S256",
    userinfo_required = FALSE,
    id_token_required = TRUE,
    id_token_validation = TRUE,
    userinfo_id_token_match = FALSE,
    token_auth_style = "body"
  )

  cli <- oauth_client(
    provider = prov,
    client_id = "client-xyz",
    client_secret = "secret",
    redirect_uri = "http://localhost:8100",
    scopes = "openid",
    state_store = cachem::cache_mem(max_age = 600),
    state_key = paste0(
      "0123456789abcdefghijklmnopqrstuvwxyz",
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    )
  )

  now <- floor(as.numeric(Sys.time()))
  id_token <- build_dummy_jwt(list(
    iss = "https://issuer.example.com",
    aud = "client-xyz",
    sub = "user123",
    iat = now,
    exp = now + 3600
  ))

  browser_token <- valid_browser_token()
  payload <- parse_query_param(
    prepare_call(cli, browser_token = browser_token),
    "state"
  )

  token <- testthat::with_mocked_bindings(
    swap_code_for_token_set = function(client, code, code_verifier) {
      list(
        access_token = "at",
        token_type = "Bearer",
        id_token = id_token,
        scope = "openid",
        expires_in = 3600
      )
    },
    .package = "shinyOAuth",
    handle_callback(
      cli,
      code = "ok",
      payload = payload,
      browser_token = browser_token
    )
  )

  testthat::expect_false(token@id_token_validated)

  login_events <- Filter(
    function(event) identical(as.character(event$type), "audit_login_success"),
    events
  )
  testthat::expect_length(login_events, 1L)
  testthat::expect_identical(
    login_events[[1]]$sub_source,
    "id_token_unverified"
  )
})
