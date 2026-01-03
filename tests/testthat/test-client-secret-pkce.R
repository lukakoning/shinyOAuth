test_that("client_secret optional when body auth + PKCE", {
  prov <- oauth_provider(
    name = "example",
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
    extra_auth_params = list(),
    extra_token_params = list(),
    extra_token_headers = character(),
    token_auth_style = "body",
    jwks_cache = cachem::cache_mem(max_age = 60),
    jwks_pins = character(),
    jwks_pin_mode = "any",
    allowed_algs = c("RS256", "ES256"),
    leeway = 60
  )

  expect_silent({
    cl <- oauth_client(
      provider = prov,
      client_id = "abc",
      client_secret = "", # secretless public client
      redirect_uri = "http://localhost:8100",
      scopes = character(0)
    )
    cl
  })
})

test_that("client_secret required when body auth without PKCE", {
  prov <- oauth_provider(
    name = "example",
    auth_url = "https://example.com/auth",
    token_url = "https://example.com/token",
    userinfo_url = NA_character_,
    introspection_url = NA_character_,
    issuer = NA_character_,
    use_nonce = FALSE,
    use_pkce = FALSE,
    pkce_method = "S256",
    userinfo_required = FALSE,
    id_token_required = FALSE,
    id_token_validation = FALSE,
    userinfo_id_token_match = FALSE,
    extra_auth_params = list(),
    extra_token_params = list(),
    extra_token_headers = character(),
    token_auth_style = "body",
    jwks_cache = cachem::cache_mem(max_age = 60),
    jwks_pins = character(),
    jwks_pin_mode = "any",
    allowed_algs = c("RS256", "ES256"),
    leeway = 60
  )

  expect_error(
    oauth_client(
      provider = prov,
      client_id = "abc",
      client_secret = "",
      redirect_uri = "http://localhost:8100",
      scopes = character(0)
    ),
    "client_secret is required unless using PKCE"
  )
})

test_that("client_secret required when header auth", {
  prov <- oauth_provider(
    name = "example",
    auth_url = "https://example.com/auth",
    token_url = "https://example.com/token",
    userinfo_url = NA_character_,
    introspection_url = NA_character_,
    issuer = NA_character_,
    use_nonce = FALSE,
    use_pkce = TRUE, # even with PKCE, header auth should require secret
    pkce_method = "S256",
    userinfo_required = FALSE,
    id_token_required = FALSE,
    id_token_validation = FALSE,
    userinfo_id_token_match = FALSE,
    extra_auth_params = list(),
    extra_token_params = list(),
    extra_token_headers = character(),
    token_auth_style = "header",
    jwks_cache = cachem::cache_mem(max_age = 60),
    jwks_pins = character(),
    jwks_pin_mode = "any",
    allowed_algs = c("RS256", "ES256"),
    leeway = 60
  )

  expect_error(
    oauth_client(
      provider = prov,
      client_id = "abc",
      client_secret = "",
      redirect_uri = "http://localhost:8100",
      scopes = character(0)
    ),
    "client_secret is required when token_auth_style = 'header'"
  )
})

test_that("HS* allowed_algs + ID token validation fails fast without strong secret", {
  withr::local_options(list(shinyOAuth.allow_hs = TRUE))

  prov_validate <- oauth_provider(
    name = "example",
    auth_url = "https://example.com/auth",
    token_url = "https://example.com/token",
    userinfo_url = NA_character_,
    introspection_url = NA_character_,
    issuer = "https://issuer.example.com",
    use_nonce = FALSE,
    use_pkce = TRUE,
    pkce_method = "S256",
    userinfo_required = FALSE,
    id_token_required = FALSE,
    id_token_validation = TRUE,
    userinfo_id_token_match = FALSE,
    extra_auth_params = list(),
    extra_token_params = list(),
    extra_token_headers = character(),
    token_auth_style = "body",
    jwks_cache = cachem::cache_mem(max_age = 60),
    jwks_pins = character(),
    jwks_pin_mode = "any",
    allowed_algs = c("HS256"),
    leeway = 60
  )

  expect_error(
    oauth_client(
      provider = prov_validate,
      client_id = "abc",
      client_secret = "",
      redirect_uri = "http://localhost:8100",
      scopes = character(0)
    ),
    regexp = "HS\\*|HS256|client_secret",
    fixed = FALSE
  )

  expect_error(
    oauth_client(
      provider = prov_validate,
      client_id = "abc",
      client_secret = "short-secret",
      redirect_uri = "http://localhost:8100",
      scopes = character(0)
    ),
    regexp = "32 bytes",
    fixed = TRUE
  )

  expect_silent(
    oauth_client(
      provider = prov_validate,
      client_id = "abc",
      client_secret = paste(rep("a", 32), collapse = ""),
      redirect_uri = "http://localhost:8100",
      scopes = character(0)
    )
  )

  # If we are not going to validate ID tokens / nonce, allow secretless PKCE.
  prov_no_validate <- oauth_provider(
    name = "example",
    auth_url = "https://example.com/auth",
    token_url = "https://example.com/token",
    userinfo_url = NA_character_,
    introspection_url = NA_character_,
    issuer = "https://issuer.example.com",
    use_nonce = FALSE,
    use_pkce = TRUE,
    pkce_method = "S256",
    userinfo_required = FALSE,
    id_token_required = FALSE,
    id_token_validation = FALSE,
    userinfo_id_token_match = FALSE,
    extra_auth_params = list(),
    extra_token_params = list(),
    extra_token_headers = character(),
    token_auth_style = "body",
    jwks_cache = cachem::cache_mem(max_age = 60),
    jwks_pins = character(),
    jwks_pin_mode = "any",
    allowed_algs = c("HS256"),
    leeway = 60
  )

  expect_silent(
    oauth_client(
      provider = prov_no_validate,
      client_id = "abc",
      client_secret = "",
      redirect_uri = "http://localhost:8100",
      scopes = character(0)
    )
  )
})
