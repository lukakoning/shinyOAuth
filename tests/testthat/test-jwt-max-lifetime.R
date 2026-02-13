# Tests for max_id_token_lifetime enforcement (OIDC Core §3.1.3.7 rule 9)
# Validates that ID tokens with exp - iat exceeding the configured cap are rejected.
# Configured via options(shinyOAuth.max_id_token_lifetime = <seconds>).

enc_b64url <- function(x) {
  b <- openssl::base64_encode(charToRaw(x))
  b <- gsub("=+$", "", b)
  chartr("+/", "-_", b)
}

build_jwt <- function(header, claims, sig = "") {
  paste(
    enc_b64url(jsonlite::toJSON(header, auto_unbox = TRUE)),
    enc_b64url(jsonlite::toJSON(claims, auto_unbox = TRUE)),
    sig,
    sep = "."
  )
}

mk_client <- function() {
  prov <- shinyOAuth::oauth_provider(
    name = "test",
    auth_url = "https://example.com/auth",
    token_url = "https://example.com/token",
    userinfo_url = NA_character_,
    userinfo_required = FALSE,
    userinfo_id_token_match = FALSE,
    issuer = "https://issuer.example.com",
    id_token_validation = TRUE,
    id_token_required = TRUE,
    allowed_algs = c("RS256", "ES256")
  )
  shinyOAuth::oauth_client(
    prov,
    client_id = "client-xyz",
    client_secret = "secret",
    redirect_uri = "http://localhost:8100"
  )
}

# --- validate_id_token lifetime enforcement ----------------------------------

test_that("validate_id_token rejects tokens exceeding max_id_token_lifetime", {
  client <- mk_client()

  now <- floor(as.numeric(Sys.time()))
  # Token with 2-hour lifetime (7200s) exceeds 1-hour cap (3600s)
  claims <- list(
    iss = client@provider@issuer,
    aud = client@client_id,
    sub = "user1",
    iat = now - 10,
    exp = now - 10 + 7200
  )
  jwt <- build_jwt(list(alg = "none"), claims)

  withr::with_options(
    list(
      shinyOAuth.skip_id_sig = TRUE,
      shinyOAuth.max_id_token_lifetime = 3600
    ),
    {
      expect_error(
        shinyOAuth:::validate_id_token(client, jwt),
        class = "shinyOAuth_id_token_error",
        regexp = "max_id_token_lifetime"
      )
    }
  )
})

test_that("validate_id_token accepts tokens within max_id_token_lifetime", {
  client <- mk_client()

  now <- floor(as.numeric(Sys.time()))
  # Token with 30-minute lifetime (1800s) is within 1-hour cap (3600s)
  claims <- list(
    iss = client@provider@issuer,
    aud = client@client_id,
    sub = "user1",
    iat = now - 10,
    exp = now - 10 + 1800
  )
  jwt <- build_jwt(list(alg = "none"), claims)

  withr::with_options(
    list(
      shinyOAuth.skip_id_sig = TRUE,
      shinyOAuth.max_id_token_lifetime = 3600
    ),
    {
      expect_silent(shinyOAuth:::validate_id_token(client, jwt))
    }
  )
})

test_that("validate_id_token accepts tokens at exactly max_id_token_lifetime", {
  client <- mk_client()

  now <- floor(as.numeric(Sys.time()))
  # Token with exactly 3600s lifetime should be accepted (boundary)
  claims <- list(
    iss = client@provider@issuer,
    aud = client@client_id,
    sub = "user1",
    iat = now - 10,
    exp = now - 10 + 3600
  )
  jwt <- build_jwt(list(alg = "none"), claims)

  withr::with_options(
    list(
      shinyOAuth.skip_id_sig = TRUE,
      shinyOAuth.max_id_token_lifetime = 3600
    ),
    {
      expect_silent(shinyOAuth:::validate_id_token(client, jwt))
    }
  )
})

test_that("validate_id_token rejects tokens at max_id_token_lifetime + 1", {
  client <- mk_client()

  now <- floor(as.numeric(Sys.time()))
  # Token with 3601s lifetime exceeds cap by 1 second
  claims <- list(
    iss = client@provider@issuer,
    aud = client@client_id,
    sub = "user1",
    iat = now - 10,
    exp = now - 10 + 3601
  )
  jwt <- build_jwt(list(alg = "none"), claims)

  withr::with_options(
    list(
      shinyOAuth.skip_id_sig = TRUE,
      shinyOAuth.max_id_token_lifetime = 3600
    ),
    {
      expect_error(
        shinyOAuth:::validate_id_token(client, jwt),
        class = "shinyOAuth_id_token_error",
        regexp = "max_id_token_lifetime"
      )
    }
  )
})

test_that("validate_id_token skips lifetime check when max_id_token_lifetime = Inf", {
  client <- mk_client()

  now <- floor(as.numeric(Sys.time()))
  # Token with 10-year lifetime should be accepted when cap is Inf
  claims <- list(
    iss = client@provider@issuer,
    aud = client@client_id,
    sub = "user1",
    iat = now - 10,
    exp = now - 10 + (365 * 24 * 3600 * 10)
  )
  jwt <- build_jwt(list(alg = "none"), claims)

  withr::with_options(
    list(shinyOAuth.skip_id_sig = TRUE, shinyOAuth.max_id_token_lifetime = Inf),
    {
      expect_silent(shinyOAuth:::validate_id_token(client, jwt))
    }
  )
})

test_that("validate_id_token default 86400s cap rejects 48h tokens", {
  client <- mk_client()

  now <- floor(as.numeric(Sys.time()))
  # 48-hour token (172800s) exceeds 24h default (86400s)
  claims <- list(
    iss = client@provider@issuer,
    aud = client@client_id,
    sub = "user1",
    iat = now - 10,
    exp = now - 10 + 172800
  )
  jwt <- build_jwt(list(alg = "none"), claims)

  # No option set — uses default 86400
  withr::with_options(
    list(
      shinyOAuth.skip_id_sig = TRUE,
      shinyOAuth.max_id_token_lifetime = NULL
    ),
    {
      expect_error(
        shinyOAuth:::validate_id_token(client, jwt),
        class = "shinyOAuth_id_token_error",
        regexp = "max_id_token_lifetime"
      )
    }
  )
})

test_that("validate_id_token default 86400s cap accepts 1h tokens", {
  client <- mk_client()

  now <- floor(as.numeric(Sys.time()))
  # 1-hour token (3600s) well within 24h default
  claims <- list(
    iss = client@provider@issuer,
    aud = client@client_id,
    sub = "user1",
    iat = now - 10,
    exp = now - 10 + 3600
  )
  jwt <- build_jwt(list(alg = "none"), claims)

  # No option set — uses default 86400
  withr::with_options(
    list(
      shinyOAuth.skip_id_sig = TRUE,
      shinyOAuth.max_id_token_lifetime = NULL
    ),
    {
      expect_silent(shinyOAuth:::validate_id_token(client, jwt))
    }
  )
})

test_that("validate_id_token lifetime error message includes diagnostics", {
  client <- mk_client()

  now <- floor(as.numeric(Sys.time()))
  claims <- list(
    iss = client@provider@issuer,
    aud = client@client_id,
    sub = "user1",
    iat = now - 10,
    exp = now - 10 + 7200
  )
  jwt <- build_jwt(list(alg = "none"), claims)

  withr::with_options(
    list(shinyOAuth.skip_id_sig = TRUE, shinyOAuth.max_id_token_lifetime = 600),
    {
      err <- expect_error(
        shinyOAuth:::validate_id_token(client, jwt),
        class = "shinyOAuth_id_token_error"
      )
      # Error message should contain diagnostic info
      msg <- conditionMessage(err)
      expect_match(msg, "lifetime=")
      expect_match(msg, "max_id_token_lifetime=600")
    }
  )
})
