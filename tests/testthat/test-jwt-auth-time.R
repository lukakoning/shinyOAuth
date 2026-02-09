# Tests for auth_time claim validation when max_age is requested
# (OIDC Core §3.1.2.1 / §2)

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

mk_client <- function(extra_auth_params = list()) {
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
    allowed_algs = c("RS256", "ES256"),
    leeway = 5,
    extra_auth_params = extra_auth_params
  )
  shinyOAuth::oauth_client(
    prov,
    client_id = "client-xyz",
    client_secret = "secret",
    redirect_uri = "http://localhost:8100"
  )
}


# --- validate_id_token: auth_time required when max_age is passed ---

test_that("validate_id_token requires auth_time when max_age is passed", {
  client <- mk_client()
  now <- floor(as.numeric(Sys.time()))

  # Valid ID token WITHOUT auth_time
  jwt <- build_jwt(
    list(alg = "none"),
    list(
      iss = "https://issuer.example.com",
      aud = "client-xyz",
      sub = "user-1",
      exp = now + 300,
      iat = now - 1
    )
  )

  withr::with_options(list(shinyOAuth.skip_id_sig = TRUE), {
    # Without max_age: should pass (auth_time not required)
    expect_silent(
      shinyOAuth:::validate_id_token(client, jwt)
    )

    # With max_age: should fail because auth_time is missing
    expect_error(
      shinyOAuth:::validate_id_token(client, jwt, max_age = 300),
      regexp = "auth_time"
    )
  })
})


test_that("validate_id_token accepts valid auth_time within max_age window", {
  client <- mk_client()
  now <- floor(as.numeric(Sys.time()))

  # auth_time 100 seconds ago, max_age 300 seconds => 100 <= 300 + 5 (leeway) => OK

  jwt <- build_jwt(
    list(alg = "none"),
    list(
      iss = "https://issuer.example.com",
      aud = "client-xyz",
      sub = "user-1",
      exp = now + 300,
      iat = now - 1,
      auth_time = now - 100
    )
  )

  withr::with_options(list(shinyOAuth.skip_id_sig = TRUE), {
    expect_silent(
      shinyOAuth:::validate_id_token(client, jwt, max_age = 300)
    )
  })
})


test_that("validate_id_token rejects auth_time exceeding max_age + leeway", {
  client <- mk_client()
  now <- floor(as.numeric(Sys.time()))

  # auth_time 400 seconds ago, max_age 300, leeway 5 => 400 > 305 => reject
  jwt <- build_jwt(
    list(alg = "none"),
    list(
      iss = "https://issuer.example.com",
      aud = "client-xyz",
      sub = "user-1",
      exp = now + 300,
      iat = now - 1,
      auth_time = now - 400
    )
  )

  withr::with_options(list(shinyOAuth.skip_id_sig = TRUE), {
    expect_error(
      shinyOAuth:::validate_id_token(client, jwt, max_age = 300),
      regexp = "auth_time exceeded max_age"
    )
  })
})


test_that("validate_id_token accepts auth_time at exact boundary (max_age + leeway)", {
  client <- mk_client()
  now <- floor(as.numeric(Sys.time()))

  # auth_time exactly max_age + leeway ago => elapsed == max_age + leeway => NOT exceeded
  jwt <- build_jwt(
    list(alg = "none"),
    list(
      iss = "https://issuer.example.com",
      aud = "client-xyz",
      sub = "user-1",
      exp = now + 300,
      iat = now - 1,
      auth_time = now - 305
    )
  )

  withr::with_options(list(shinyOAuth.skip_id_sig = TRUE), {
    expect_silent(
      shinyOAuth:::validate_id_token(client, jwt, max_age = 300)
    )
  })
})


test_that("validate_id_token rejects auth_time one second past boundary", {
  client <- mk_client()
  now <- floor(as.numeric(Sys.time()))

  # auth_time 306 seconds ago, max_age 300, leeway 5 => 306 > 305 => reject
  jwt <- build_jwt(
    list(alg = "none"),
    list(
      iss = "https://issuer.example.com",
      aud = "client-xyz",
      sub = "user-1",
      exp = now + 300,
      iat = now - 1,
      auth_time = now - 306
    )
  )

  withr::with_options(list(shinyOAuth.skip_id_sig = TRUE), {
    expect_error(
      shinyOAuth:::validate_id_token(client, jwt, max_age = 300),
      regexp = "auth_time exceeded max_age"
    )
  })
})


test_that("validate_id_token rejects non-numeric auth_time when max_age is requested", {
  client <- mk_client()
  now <- floor(as.numeric(Sys.time()))

  jwt <- build_jwt(
    list(alg = "none"),
    list(
      iss = "https://issuer.example.com",
      aud = "client-xyz",
      sub = "user-1",
      exp = now + 300,
      iat = now - 1,
      auth_time = "not-a-number"
    )
  )

  withr::with_options(list(shinyOAuth.skip_id_sig = TRUE), {
    expect_error(
      shinyOAuth:::validate_id_token(client, jwt, max_age = 300),
      regexp = "auth_time claim must be a single finite number"
    )
  })
})


test_that("validate_id_token works with max_age = 0 (equivalent to prompt=login)", {
  client <- mk_client()
  now <- floor(as.numeric(Sys.time()))

  # max_age = 0 means authentication must be right now; auth_time 10s ago => reject
  jwt_old <- build_jwt(
    list(alg = "none"),
    list(
      iss = "https://issuer.example.com",
      aud = "client-xyz",
      sub = "user-1",
      exp = now + 300,
      iat = now - 1,
      auth_time = now - 10
    )
  )

  # auth_time within leeway (5s) => accept
  jwt_fresh <- build_jwt(
    list(alg = "none"),
    list(
      iss = "https://issuer.example.com",
      aud = "client-xyz",
      sub = "user-1",
      exp = now + 300,
      iat = now - 1,
      auth_time = now - 3
    )
  )

  withr::with_options(list(shinyOAuth.skip_id_sig = TRUE), {
    expect_error(
      shinyOAuth:::validate_id_token(client, jwt_old, max_age = 0),
      regexp = "auth_time exceeded max_age"
    )
    expect_silent(
      shinyOAuth:::validate_id_token(client, jwt_fresh, max_age = 0)
    )
  })
})


test_that("validate_id_token ignores auth_time when max_age is not requested", {
  client <- mk_client()
  now <- floor(as.numeric(Sys.time()))

  # auth_time present but very old; without max_age, no validation occurs
  jwt <- build_jwt(
    list(alg = "none"),
    list(
      iss = "https://issuer.example.com",
      aud = "client-xyz",
      sub = "user-1",
      exp = now + 300,
      iat = now - 1,
      auth_time = now - 99999
    )
  )

  withr::with_options(list(shinyOAuth.skip_id_sig = TRUE), {
    expect_silent(
      shinyOAuth:::validate_id_token(client, jwt)
    )
  })
})


# --- verify_token_set: max_age propagation from extra_auth_params ---

test_that("verify_token_set passes max_age from extra_auth_params to validate_id_token", {
  now <- floor(as.numeric(Sys.time()))

  client <- mk_client(extra_auth_params = list(max_age = 300))

  # Token set with an ID token where auth_time is too old (400s ago)
  jwt <- build_jwt(
    list(alg = "none"),
    list(
      iss = "https://issuer.example.com",
      aud = "client-xyz",
      sub = "user-1",
      exp = now + 300,
      iat = now - 1,
      auth_time = now - 400
    )
  )

  token_set <- list(
    access_token = "at_123",
    token_type = "Bearer",
    id_token = jwt,
    scope = ""
  )

  withr::with_options(list(shinyOAuth.skip_id_sig = TRUE), {
    expect_error(
      shinyOAuth:::verify_token_set(
        client,
        token_set = token_set,
        nonce = NULL,
        is_refresh = FALSE
      ),
      regexp = "auth_time exceeded max_age"
    )
  })
})


test_that("verify_token_set does not pass max_age during refresh", {
  now <- floor(as.numeric(Sys.time()))

  client <- mk_client(extra_auth_params = list(max_age = 300))

  # Original ID token for sub match
  original_jwt <- build_jwt(
    list(alg = "none"),
    list(
      iss = "https://issuer.example.com",
      aud = "client-xyz",
      sub = "user-1",
      exp = now + 300,
      iat = now - 500,
      auth_time = now - 500
    )
  )

  # New ID token with old auth_time; during refresh, max_age should NOT be enforced
  new_jwt <- build_jwt(
    list(alg = "none"),
    list(
      iss = "https://issuer.example.com",
      aud = "client-xyz",
      sub = "user-1",
      exp = now + 300,
      iat = now - 1,
      auth_time = now - 500
    )
  )

  token_set <- list(
    access_token = "at_refresh",
    token_type = "Bearer",
    id_token = new_jwt,
    scope = ""
  )

  withr::with_options(list(shinyOAuth.skip_id_sig = TRUE), {
    # Should NOT fail on auth_time during refresh
    expect_silent(
      shinyOAuth:::verify_token_set(
        client,
        token_set = token_set,
        nonce = NULL,
        is_refresh = TRUE,
        original_id_token = original_jwt
      )
    )
  })
})


test_that("verify_token_set accepts token when auth_time is within max_age", {
  now <- floor(as.numeric(Sys.time()))

  client <- mk_client(extra_auth_params = list(max_age = 300))

  jwt <- build_jwt(
    list(alg = "none"),
    list(
      iss = "https://issuer.example.com",
      aud = "client-xyz",
      sub = "user-1",
      exp = now + 300,
      iat = now - 1,
      auth_time = now - 100
    )
  )

  token_set <- list(
    access_token = "at_ok",
    token_type = "Bearer",
    id_token = jwt,
    scope = ""
  )

  withr::with_options(list(shinyOAuth.skip_id_sig = TRUE), {
    expect_silent(
      shinyOAuth:::verify_token_set(
        client,
        token_set = token_set,
        nonce = NULL,
        is_refresh = FALSE
      )
    )
  })
})


test_that("verify_token_set rejects ID token missing auth_time when max_age requested", {
  now <- floor(as.numeric(Sys.time()))

  client <- mk_client(extra_auth_params = list(max_age = 300))

  # ID token WITHOUT auth_time claim
  jwt <- build_jwt(
    list(alg = "none"),
    list(
      iss = "https://issuer.example.com",
      aud = "client-xyz",
      sub = "user-1",
      exp = now + 300,
      iat = now - 1
    )
  )

  token_set <- list(
    access_token = "at_missing",
    token_type = "Bearer",
    id_token = jwt,
    scope = ""
  )

  withr::with_options(list(shinyOAuth.skip_id_sig = TRUE), {
    expect_error(
      shinyOAuth:::verify_token_set(
        client,
        token_set = token_set,
        nonce = NULL,
        is_refresh = FALSE
      ),
      regexp = "auth_time"
    )
  })
})
