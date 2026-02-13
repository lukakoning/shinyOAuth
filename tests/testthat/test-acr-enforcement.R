# Tests for required_acr_values enforcement (OIDC Core §2, §3.1.2.1)
# Validates that when required_acr_values is configured on OAuthClient:
# 1. The OAuthClient validator requires OIDC provider configuration
# 2. The acr_values hint is added to authorization URLs
# 3. The returned ID token's acr claim is validated against the allowlist

# --- OAuthClient validator tests ----------------------------------------------

test_that("OAuthClient: required_acr_values must be a character vector", {
  expect_error(
    oauth_client(
      provider = oauth_provider(
        name = "test",
        auth_url = "https://example.com/auth",
        token_url = "https://example.com/token",
        issuer = "https://example.com",
        id_token_validation = TRUE,
        token_auth_style = "body",
        use_pkce = TRUE
      ),
      client_id = "abc",
      client_secret = "",
      redirect_uri = "http://localhost:8100",
      required_acr_values = 42
    ),
    "required_acr_values"
  )
})

test_that("OAuthClient: required_acr_values must not contain NA", {
  expect_error(
    oauth_client(
      provider = oauth_provider(
        name = "test",
        auth_url = "https://example.com/auth",
        token_url = "https://example.com/token",
        issuer = "https://example.com",
        id_token_validation = TRUE,
        token_auth_style = "body",
        use_pkce = TRUE
      ),
      client_id = "abc",
      client_secret = "",
      redirect_uri = "http://localhost:8100",
      required_acr_values = c("urn:something", NA_character_)
    ),
    "must not contain NA"
  )
})

test_that("OAuthClient: required_acr_values must not contain empty strings", {
  expect_error(
    oauth_client(
      provider = oauth_provider(
        name = "test",
        auth_url = "https://example.com/auth",
        token_url = "https://example.com/token",
        issuer = "https://example.com",
        id_token_validation = TRUE,
        token_auth_style = "body",
        use_pkce = TRUE
      ),
      client_id = "abc",
      client_secret = "",
      redirect_uri = "http://localhost:8100",
      required_acr_values = c("urn:something", "")
    ),
    "must not contain empty strings"
  )
})

test_that("OAuthClient: required_acr_values requires issuer", {
  expect_error(
    oauth_client(
      provider = oauth_provider(
        name = "test",
        auth_url = "https://example.com/auth",
        token_url = "https://example.com/token",
        # No issuer -> NA by default
        id_token_validation = FALSE,
        token_auth_style = "body",
        use_pkce = TRUE
      ),
      client_id = "abc",
      client_secret = "",
      redirect_uri = "http://localhost:8100",
      required_acr_values = c("urn:mace:incommon:iap:silver")
    ),
    "issuer"
  )
})

test_that("OAuthClient: required_acr_values requires id_token_validation", {
  expect_error(
    oauth_client(
      provider = oauth_provider(
        name = "test",
        auth_url = "https://example.com/auth",
        token_url = "https://example.com/token",
        issuer = "https://example.com",
        id_token_validation = FALSE,
        use_nonce = FALSE,
        id_token_required = FALSE,
        token_auth_style = "body",
        use_pkce = TRUE
      ),
      client_id = "abc",
      client_secret = "",
      redirect_uri = "http://localhost:8100",
      required_acr_values = c("urn:mace:incommon:iap:silver")
    ),
    "id_token_validation"
  )
})

test_that("OAuthClient: empty required_acr_values does not require OIDC", {
  # Default (empty) should always be fine regardless of provider capabilities
  cli <- oauth_client(
    provider = oauth_provider(
      name = "test",
      auth_url = "https://example.com/auth",
      token_url = "https://example.com/token",
      token_auth_style = "body",
      use_pkce = TRUE
    ),
    client_id = "abc",
    client_secret = "",
    redirect_uri = "http://localhost:8100",
    required_acr_values = character(0)
  )
  expect_equal(cli@required_acr_values, character(0))
})

test_that("OAuthClient: valid required_acr_values accepted with OIDC provider", {
  cli <- oauth_client(
    provider = oauth_provider(
      name = "test",
      auth_url = "https://example.com/auth",
      token_url = "https://example.com/token",
      issuer = "https://example.com",
      id_token_validation = TRUE,
      token_auth_style = "body",
      use_pkce = TRUE
    ),
    client_id = "abc",
    client_secret = "",
    redirect_uri = "http://localhost:8100",
    required_acr_values = c(
      "urn:mace:incommon:iap:silver",
      "urn:mace:incommon:iap:gold"
    )
  )
  expect_equal(
    cli@required_acr_values,
    c("urn:mace:incommon:iap:silver", "urn:mace:incommon:iap:gold")
  )
})

# --- Authorization URL tests -------------------------------------------------

test_that("build_auth_url: includes acr_values when required_acr_values is set", {
  prov <- oauth_provider(
    name = "test",
    auth_url = "https://example.com/auth",
    token_url = "https://example.com/token",
    issuer = "https://example.com",
    id_token_validation = TRUE,
    use_nonce = FALSE,
    use_pkce = TRUE,
    token_auth_style = "body"
  )

  cli <- oauth_client(
    provider = prov,
    client_id = "abc",
    client_secret = "",
    redirect_uri = "http://localhost:8100",
    scopes = c("openid"),
    required_acr_values = c(
      "urn:mace:incommon:iap:silver",
      "urn:mace:incommon:iap:gold"
    ),
    scope_validation = "none"
  )

  url <- shinyOAuth:::build_auth_url(
    cli,
    payload = "test-state-payload",
    pkce_code_challenge = "test-challenge",
    pkce_method = "S256",
    nonce = NULL
  )

  parsed <- httr2::url_parse(url)
  expect_true("acr_values" %in% names(parsed$query))
  expect_equal(
    parsed$query$acr_values,
    "urn:mace:incommon:iap:silver urn:mace:incommon:iap:gold"
  )
})

test_that("build_auth_url: no acr_values when required_acr_values is empty", {
  cli <- make_test_client(use_pkce = TRUE)

  url <- shinyOAuth:::build_auth_url(
    cli,
    payload = "test-state-payload",
    pkce_code_challenge = "test-challenge",
    pkce_method = "S256",
    nonce = NULL
  )

  parsed <- httr2::url_parse(url)
  expect_false("acr_values" %in% names(parsed$query))
})

# --- verify_token_set acr enforcement tests -----------------------------------

# Helper: creates an OIDC client with required_acr_values and a matching provider
make_acr_test_client <- function(
  required_acr_values = character(0)
) {
  prov <- oauth_provider(
    name = "test-acr",
    auth_url = "https://acr.example.com/auth",
    token_url = "https://acr.example.com/token",
    issuer = "https://acr.example.com",
    use_nonce = FALSE,
    use_pkce = FALSE,
    id_token_required = TRUE,
    id_token_validation = TRUE,
    token_auth_style = "body",
    allowed_token_types = c("Bearer"),
    jwks_cache = cachem::cache_mem(max_age = 60)
  )

  oauth_client(
    provider = prov,
    client_id = "test-client-acr",
    client_secret = "super-duper-secret-that-is-long-enough",
    redirect_uri = "http://localhost:8100",
    scopes = c("openid"),
    scope_validation = "none",
    required_acr_values = required_acr_values
  )
}

# Helper: build a fake ID token (three-segment dot-separated JWT, alg=none)
make_fake_id_token <- function(claims_list) {
  header <- shinyOAuth:::base64url_encode(charToRaw('{"alg":"none"}'))
  payload <- shinyOAuth:::base64url_encode(charToRaw(
    jsonlite::toJSON(claims_list, auto_unbox = TRUE)
  ))
  paste(header, payload, "", sep = ".")
}

test_that("verify_token_set: passes when acr matches allowlist", {
  cli <- make_acr_test_client(
    required_acr_values = c(
      "urn:mace:incommon:iap:silver",
      "urn:mace:incommon:iap:gold"
    )
  )

  id_token <- make_fake_id_token(list(
    iss = "https://acr.example.com",
    aud = "test-client-acr",
    sub = "user123",
    iat = as.numeric(Sys.time()) - 10,
    exp = as.numeric(Sys.time()) + 3600,
    acr = "urn:mace:incommon:iap:silver"
  ))

  token_set <- list(
    access_token = "test-at",
    token_type = "Bearer",
    expires_in = 3600,
    id_token = id_token,
    scope = "openid"
  )

  result <- testthat::with_mocked_bindings(
    validate_id_token = function(
      client,
      id_token,
      expected_nonce = NULL,
      expected_sub = NULL,
      expected_access_token = NULL,
      max_age = NULL
    ) {
      invisible(list(sub = "user123"))
    },
    .package = "shinyOAuth",
    {
      shinyOAuth:::verify_token_set(
        cli,
        token_set = token_set,
        nonce = NULL,
        is_refresh = FALSE
      )
    }
  )

  expect_identical(result[["access_token"]], "test-at")
})

test_that("verify_token_set: errors when acr claim is missing", {
  cli <- make_acr_test_client(
    required_acr_values = c("urn:mace:incommon:iap:silver")
  )

  id_token <- make_fake_id_token(list(
    iss = "https://acr.example.com",
    aud = "test-client-acr",
    sub = "user123",
    iat = as.numeric(Sys.time()) - 10,
    exp = as.numeric(Sys.time()) + 3600
    # No acr claim!
  ))

  token_set <- list(
    access_token = "test-at",
    token_type = "Bearer",
    expires_in = 3600,
    id_token = id_token,
    scope = "openid"
  )

  err <- tryCatch(
    testthat::with_mocked_bindings(
      validate_id_token = function(
        client,
        id_token,
        expected_nonce = NULL,
        expected_sub = NULL,
        expected_access_token = NULL,
        max_age = NULL
      ) {
        invisible(list(sub = "user123"))
      },
      .package = "shinyOAuth",
      {
        shinyOAuth:::verify_token_set(
          cli,
          token_set = token_set,
          nonce = NULL,
          is_refresh = FALSE
        )
      }
    ),
    error = function(e) e
  )

  expect_s3_class(err, "shinyOAuth_id_token_error")
  expect_match(conditionMessage(err), "acr")
  expect_match(conditionMessage(err), "missing")
})

test_that("verify_token_set: errors when acr claim not in allowlist", {
  cli <- make_acr_test_client(
    required_acr_values = c(
      "urn:mace:incommon:iap:silver",
      "urn:mace:incommon:iap:gold"
    )
  )

  id_token <- make_fake_id_token(list(
    iss = "https://acr.example.com",
    aud = "test-client-acr",
    sub = "user123",
    iat = as.numeric(Sys.time()) - 10,
    exp = as.numeric(Sys.time()) + 3600,
    acr = "urn:mace:incommon:iap:bronze" # Not in allowlist
  ))

  token_set <- list(
    access_token = "test-at",
    token_type = "Bearer",
    expires_in = 3600,
    id_token = id_token,
    scope = "openid"
  )

  err <- tryCatch(
    testthat::with_mocked_bindings(
      validate_id_token = function(
        client,
        id_token,
        expected_nonce = NULL,
        expected_sub = NULL,
        expected_access_token = NULL,
        max_age = NULL
      ) {
        invisible(list(sub = "user123"))
      },
      .package = "shinyOAuth",
      {
        shinyOAuth:::verify_token_set(
          cli,
          token_set = token_set,
          nonce = NULL,
          is_refresh = FALSE
        )
      }
    ),
    error = function(e) e
  )

  expect_s3_class(err, "shinyOAuth_id_token_error")
  expect_match(conditionMessage(err), "bronze")
  expect_match(conditionMessage(err), "allowlist")
})

test_that("verify_token_set: no acr enforcement when required_acr_values is empty", {
  cli <- make_acr_test_client(required_acr_values = character(0))

  # An ID token without acr should be fine when enforcement is off
  id_token <- make_fake_id_token(list(
    iss = "https://acr.example.com",
    aud = "test-client-acr",
    sub = "user123",
    iat = as.numeric(Sys.time()) - 10,
    exp = as.numeric(Sys.time()) + 3600
    # No acr claim
  ))

  token_set <- list(
    access_token = "test-at",
    token_type = "Bearer",
    expires_in = 3600,
    id_token = id_token,
    scope = "openid"
  )

  result <- testthat::with_mocked_bindings(
    validate_id_token = function(
      client,
      id_token,
      expected_nonce = NULL,
      expected_sub = NULL,
      expected_access_token = NULL,
      max_age = NULL
    ) {
      invisible(list(sub = "user123"))
    },
    .package = "shinyOAuth",
    {
      shinyOAuth:::verify_token_set(
        cli,
        token_set = token_set,
        nonce = NULL,
        is_refresh = FALSE
      )
    }
  )

  expect_identical(result[["access_token"]], "test-at")
})

test_that("verify_token_set: acr enforcement on refresh with new ID token", {
  cli <- make_acr_test_client(
    required_acr_values = c("urn:mace:incommon:iap:silver")
  )

  # Original ID token with matching acr
  original_id_token <- make_fake_id_token(list(
    iss = "https://acr.example.com",
    aud = "test-client-acr",
    sub = "user123",
    iat = as.numeric(Sys.time()) - 3600,
    exp = as.numeric(Sys.time()) + 3600,
    acr = "urn:mace:incommon:iap:silver"
  ))

  # New ID token from refresh with WRONG acr
  new_id_token <- make_fake_id_token(list(
    iss = "https://acr.example.com",
    aud = "test-client-acr",
    sub = "user123",
    iat = as.numeric(Sys.time()) - 10,
    exp = as.numeric(Sys.time()) + 3600,
    acr = "urn:mace:incommon:iap:bronze" # Not allowed
  ))

  token_set <- list(
    access_token = "refreshed-at",
    token_type = "Bearer",
    expires_in = 3600,
    id_token = new_id_token,
    scope = "openid"
  )

  err <- tryCatch(
    testthat::with_mocked_bindings(
      validate_id_token = function(
        client,
        id_token,
        expected_nonce = NULL,
        expected_sub = NULL,
        expected_access_token = NULL,
        max_age = NULL
      ) {
        invisible(list(sub = "user123"))
      },
      .package = "shinyOAuth",
      {
        shinyOAuth:::verify_token_set(
          cli,
          token_set = token_set,
          nonce = NULL,
          is_refresh = TRUE,
          original_id_token = original_id_token
        )
      }
    ),
    error = function(e) e
  )

  expect_s3_class(err, "shinyOAuth_id_token_error")
  expect_match(conditionMessage(err), "bronze")
  expect_match(conditionMessage(err), "allowlist")
})

test_that("verify_token_set: acr enforcement skipped on refresh without new ID token", {
  cli <- make_acr_test_client(
    required_acr_values = c("urn:mace:incommon:iap:silver")
  )

  # Refresh response without ID token — acr enforcement should not trigger

  token_set <- list(
    access_token = "refreshed-at",
    token_type = "Bearer",
    expires_in = 3600,
    scope = "openid"
    # No id_token
  )

  result <- testthat::with_mocked_bindings(
    validate_id_token = function(...) invisible(NULL),
    .package = "shinyOAuth",
    {
      shinyOAuth:::verify_token_set(
        cli,
        token_set = token_set,
        nonce = NULL,
        is_refresh = TRUE,
        original_id_token = NULL
      )
    }
  )

  expect_identical(result[["access_token"]], "refreshed-at")
})

test_that("verify_token_set: acr with single value works", {
  cli <- make_acr_test_client(
    required_acr_values = c(
      "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
    )
  )

  id_token <- make_fake_id_token(list(
    iss = "https://acr.example.com",
    aud = "test-client-acr",
    sub = "user123",
    iat = as.numeric(Sys.time()) - 10,
    exp = as.numeric(Sys.time()) + 3600,
    acr = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
  ))

  token_set <- list(
    access_token = "test-at",
    token_type = "Bearer",
    expires_in = 3600,
    id_token = id_token,
    scope = "openid"
  )

  result <- testthat::with_mocked_bindings(
    validate_id_token = function(
      client,
      id_token,
      expected_nonce = NULL,
      expected_sub = NULL,
      expected_access_token = NULL,
      max_age = NULL
    ) {
      invisible(list(sub = "user123"))
    },
    .package = "shinyOAuth",
    {
      shinyOAuth:::verify_token_set(
        cli,
        token_set = token_set,
        nonce = NULL,
        is_refresh = FALSE
      )
    }
  )

  expect_identical(result[["access_token"]], "test-at")
})
