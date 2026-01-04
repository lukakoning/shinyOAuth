# Regression test: userinfo must be fetched AFTER ID token validation
# This ensures cryptographic validation occurs before making external calls
# or exposing PII via the userinfo endpoint.

test_that("login flow: get_userinfo is called after validate_id_token", {
  # Create a provider with OIDC features that require ID token validation
  # and userinfo fetch

  prov <- oauth_provider(
    name = "test",
    auth_url = "https://test.example.com/auth",
    token_url = "https://test.example.com/token",
    userinfo_url = "https://test.example.com/userinfo",
    issuer = "https://test.example.com",
    use_nonce = TRUE,
    use_pkce = TRUE,
    pkce_method = "S256",
    userinfo_required = TRUE,
    id_token_required = TRUE,
    id_token_validation = TRUE,
    userinfo_id_token_match = FALSE,
    token_auth_style = "body",
    jwks_cache = cachem::cache_mem(max_age = 60),
    allowed_algs = c("RS256"),
    allowed_token_types = c("Bearer")
  )

  cli <- oauth_client(
    provider = prov,
    client_id = "test-client",
    client_secret = "",
    redirect_uri = "http://localhost:8100",
    scopes = c("openid", "profile"),
    state_store = cachem::cache_mem(max_age = 600),
    state_key = paste0(
      "0123456789abcdefghijklmnopqrstuvwxyz",
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    )
  )

  tok <- valid_browser_token()
  url <- shinyOAuth:::prepare_call(cli, browser_token = tok)
  enc <- parse_query_param(url, "state")

  # Track call order
  call_order <- character()

  result <- testthat::with_mocked_bindings(
    swap_code_for_token_set = function(client, code, code_verifier) {
      list(
        access_token = "test-access-token",
        token_type = "Bearer",
        expires_in = 3600,
        id_token = "header.payload.signature",
        scope = "openid profile"
      )
    },
    validate_id_token = function(
      client,
      id_token,
      expected_nonce = NULL,
      expected_sub = NULL
    ) {
      call_order <<- c(call_order, "validate_id_token")
      invisible(list(sub = "user123", iss = "https://test.example.com"))
    },
    get_userinfo = function(oauth_client, token) {
      call_order <<- c(call_order, "get_userinfo")
      list(sub = "user123", name = "Test User")
    },
    .package = "shinyOAuth",
    {
      shinyOAuth:::handle_callback(
        cli,
        code = "auth-code",
        payload = enc,
        browser_token = tok
      )
    }
  )

  # Verify both functions were called

  expect_true("validate_id_token" %in% call_order)
  expect_true("get_userinfo" %in% call_order)

  # Verify ordering: validate_id_token MUST be called before get_userinfo
  validate_pos <- which(call_order == "validate_id_token")[1]
  userinfo_pos <- which(call_order == "get_userinfo")[1]
  expect_lt(
    validate_pos,
    userinfo_pos,
    label = "validate_id_token must be called before get_userinfo"
  )
})

test_that("login flow: get_userinfo not called when ID token validation fails", {
  # Ensure that if ID token validation fails, we never reach the userinfo call
  prov <- oauth_provider(
    name = "test",
    auth_url = "https://test.example.com/auth",
    token_url = "https://test.example.com/token",
    userinfo_url = "https://test.example.com/userinfo",
    issuer = "https://test.example.com",
    use_nonce = TRUE,
    use_pkce = TRUE,
    pkce_method = "S256",
    userinfo_required = TRUE,
    id_token_required = TRUE,
    id_token_validation = TRUE,
    userinfo_id_token_match = FALSE,
    token_auth_style = "body",
    jwks_cache = cachem::cache_mem(max_age = 60),
    allowed_algs = c("RS256"),
    allowed_token_types = c("Bearer")
  )

  cli <- oauth_client(
    provider = prov,
    client_id = "test-client",
    client_secret = "",
    redirect_uri = "http://localhost:8100",
    scopes = c("openid", "profile"),
    state_store = cachem::cache_mem(max_age = 600),
    state_key = paste0(
      "0123456789abcdefghijklmnopqrstuvwxyz",
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    )
  )

  tok <- valid_browser_token()
  url <- shinyOAuth:::prepare_call(cli, browser_token = tok)
  enc <- parse_query_param(url, "state")

  userinfo_called <- FALSE

  expect_error(
    testthat::with_mocked_bindings(
      swap_code_for_token_set = function(client, code, code_verifier) {
        list(
          access_token = "test-access-token",
          token_type = "Bearer",
          expires_in = 3600,
          id_token = "header.payload.signature",
          scope = "openid profile"
        )
      },
      validate_id_token = function(
        client,
        id_token,
        expected_nonce = NULL,
        expected_sub = NULL
      ) {
        shinyOAuth:::err_id_token("Simulated ID token validation failure")
      },
      get_userinfo = function(oauth_client, token) {
        userinfo_called <<- TRUE
        list(sub = "user123")
      },
      .package = "shinyOAuth",
      {
        shinyOAuth:::handle_callback(
          cli,
          code = "auth-code",
          payload = enc,
          browser_token = tok
        )
      }
    ),
    class = "shinyOAuth_id_token_error"
  )

  # userinfo should NOT have been called because ID token validation failed first

  expect_false(
    userinfo_called,
    label = "get_userinfo must not be called when ID token validation fails"
  )
})
