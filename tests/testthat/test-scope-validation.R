# Test scope_validation modes: "strict", "warn", "none"

test_that("scope_validation = 'strict' errors on missing scopes (default)", {
  prov <- oauth_provider(
    name = "fake",
    auth_url = "https://example.com/auth",
    token_url = "https://example.com/token",
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
    scopes = c("openid", "profile", "email"),
    state_store = cachem::cache_mem(max_age = 600),
    state_key = paste0(
      "0123456789abcdefghijklmnopqrstuvwxyz",
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    ),
    scope_validation = "strict"
  )

  tok <- valid_browser_token()
  url <- shinyOAuth:::prepare_call(cli, browser_token = tok)
  enc <- parse_query_param(url, "state")

  expect_error(
    testthat::with_mocked_bindings(
      swap_code_for_token_set = function(client, code, code_verifier) {
        list(
          access_token = "t",
          token_type = "Bearer",
          scope = "profile email", # missing "openid"
          expires_in = 3600
        )
      },
      .package = "shinyOAuth",
      shinyOAuth:::handle_callback(
        cli,
        code = "ok",
        payload = enc,
        browser_token = tok
      )
    ),
    regexp = "Granted scopes missing|scope_validation",
    class = "shinyOAuth_token_error"
  )
})

test_that("scope_validation = 'warn' warns but continues on missing scopes", {
  prov <- oauth_provider(
    name = "fake",
    auth_url = "https://example.com/auth",
    token_url = "https://example.com/token",
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
    scopes = c("openid", "profile", "email"),
    state_store = cachem::cache_mem(max_age = 600),
    state_key = paste0(
      "0123456789abcdefghijklmnopqrstuvwxyz",
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    ),
    scope_validation = "warn"
  )

  tok <- valid_browser_token()
  url <- shinyOAuth:::prepare_call(cli, browser_token = tok)
  enc <- parse_query_param(url, "state")

  # Should warn but not error, and return a token
  expect_warning(
    result <- testthat::with_mocked_bindings(
      swap_code_for_token_set = function(client, code, code_verifier) {
        list(
          access_token = "my_access_token",
          token_type = "Bearer",
          scope = "profile email", # missing "openid"
          expires_in = 3600
        )
      },
      .package = "shinyOAuth",
      shinyOAuth:::handle_callback(
        cli,
        code = "ok",
        payload = enc,
        browser_token = tok
      )
    ),
    regexp = "Granted scopes missing|scope_validation"
  )

  # Token should still be returned

  expect_true(S7::S7_inherits(result, OAuthToken))
  expect_equal(result@access_token, "my_access_token")
})

test_that("scope_validation = 'none' skips validation entirely", {
  prov <- oauth_provider(
    name = "fake",
    auth_url = "https://example.com/auth",
    token_url = "https://example.com/token",
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
    scopes = c("openid", "profile", "email"),
    state_store = cachem::cache_mem(max_age = 600),
    state_key = paste0(
      "0123456789abcdefghijklmnopqrstuvwxyz",
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    ),
    scope_validation = "none"
  )

  tok <- valid_browser_token()
  url <- shinyOAuth:::prepare_call(cli, browser_token = tok)
  enc <- parse_query_param(url, "state")

  # Should NOT warn or error, just return the token
  expect_no_warning(
    expect_no_error(
      result <- testthat::with_mocked_bindings(
        swap_code_for_token_set = function(client, code, code_verifier) {
          list(
            access_token = "my_access_token",
            token_type = "Bearer",
            scope = "profile email", # missing "openid"
            expires_in = 3600
          )
        },
        .package = "shinyOAuth",
        shinyOAuth:::handle_callback(
          cli,
          code = "ok",
          payload = enc,
          browser_token = tok
        )
      )
    )
  )

  # Token should be returned
  expect_true(S7::S7_inherits(result, OAuthToken))
  expect_equal(result@access_token, "my_access_token")
})

test_that("scope_validation defaults to 'strict'", {
  prov <- oauth_provider(
    name = "fake",
    auth_url = "https://example.com/auth",
    token_url = "https://example.com/token",
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
    scopes = c("openid", "profile"),
    state_store = cachem::cache_mem(max_age = 600),
    state_key = paste0(
      "0123456789abcdefghijklmnopqrstuvwxyz",
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    )
    # No scope_validation specified - should default to "strict"
  )

  expect_equal(cli@scope_validation, "strict")
})

test_that("invalid scope_validation value is rejected", {
  prov <- oauth_provider(
    name = "fake",
    auth_url = "https://example.com/auth",
    token_url = "https://example.com/token",
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

  # Using oauth_client() helper - should error via match.arg
  expect_error(
    oauth_client(
      provider = prov,
      client_id = "abc",
      client_secret = "",
      redirect_uri = "http://localhost:8100",
      scopes = c("openid"),
      state_store = cachem::cache_mem(max_age = 600),
      state_key = paste0(
        "0123456789abcdefghijklmnopqrstuvwxyz",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
      ),
      scope_validation = "invalid"
    ),
    regexp = "strict.*warn.*none"
  )

  # Using OAuthClient directly - should error via validator
  expect_error(
    OAuthClient(
      provider = prov,
      client_id = "abc",
      client_secret = "",
      redirect_uri = "http://localhost:8100",
      scopes = c("openid"),
      state_store = cachem::cache_mem(max_age = 600),
      state_key = paste0(
        "0123456789abcdefghijklmnopqrstuvwxyz",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
      ),
      scope_validation = "invalid"
    ),
    regexp = "scope_validation"
  )
})

test_that("scope_validation = 'strict' error message includes hint", {
  prov <- oauth_provider(
    name = "fake",
    auth_url = "https://example.com/auth",
    token_url = "https://example.com/token",
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
    scopes = c("openid", "profile"),
    state_store = cachem::cache_mem(max_age = 600),
    state_key = paste0(
      "0123456789abcdefghijklmnopqrstuvwxyz",
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    ),
    scope_validation = "strict"
  )

  tok <- valid_browser_token()
  url <- shinyOAuth:::prepare_call(cli, browser_token = tok)
  enc <- parse_query_param(url, "state")

  err <- expect_error(
    testthat::with_mocked_bindings(
      swap_code_for_token_set = function(client, code, code_verifier) {
        list(
          access_token = "t",
          token_type = "Bearer",
          scope = "profile", # missing "openid"
          expires_in = 3600
        )
      },
      .package = "shinyOAuth",
      shinyOAuth:::handle_callback(
        cli,
        code = "ok",
        payload = enc,
        browser_token = tok
      )
    ),
    class = "shinyOAuth_token_error"
  )

  # Error message should include hint about changing scope_validation
  expect_match(
    conditionMessage(err),
    "scope_validation.*warn.*none|warn.*none",
    ignore.case = TRUE
  )
})
