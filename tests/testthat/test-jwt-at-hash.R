# Tests for at_hash (Access Token hash) validation
# OIDC Core §3.1.3.8 / §3.2.2.9

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

# Helper to compute the correct at_hash for a given access_token and alg
compute_expected_at_hash <- function(access_token, alg) {
  hash_fn <- if (grepl("256", alg, fixed = TRUE)) {
    openssl::sha256
  } else if (grepl("384", alg, fixed = TRUE)) {
    openssl::sha384
  } else if (grepl("512", alg, fixed = TRUE)) {
    openssl::sha512
  } else {
    openssl::sha512 # EdDSA fallback
  }
  full_hash <- hash_fn(charToRaw(access_token))
  hash_bytes <- as.raw(full_hash)
  left_half <- hash_bytes[seq_len(length(hash_bytes) %/% 2L)]
  shinyOAuth:::base64url_encode(left_half)
}

test_that("at_hash: valid at_hash passes silently", {
  client <- mk_client()
  now <- floor(as.numeric(Sys.time()))
  access_token <- "test-access-token-12345"
  at_hash <- compute_expected_at_hash(access_token, "RS256")

  claims <- list(
    iss = client@provider@issuer,
    aud = client@client_id,
    sub = "user-1",
    exp = now + 300,
    iat = now - 1,
    at_hash = at_hash
  )
  jwt <- build_jwt(list(alg = "RS256"), claims)

  withr::with_options(list(shinyOAuth.skip_id_sig = TRUE), {
    expect_silent(
      shinyOAuth:::validate_id_token(
        client,
        jwt,
        expected_access_token = access_token
      )
    )
  })
})

test_that("at_hash: mismatched at_hash raises id_token error", {
  client <- mk_client()
  now <- floor(as.numeric(Sys.time()))
  access_token <- "correct-access-token"
  wrong_at_hash <- compute_expected_at_hash("wrong-access-token", "RS256")

  claims <- list(
    iss = client@provider@issuer,
    aud = client@client_id,
    sub = "user-1",
    exp = now + 300,
    iat = now - 1,
    at_hash = wrong_at_hash
  )
  jwt <- build_jwt(list(alg = "RS256"), claims)

  withr::with_options(list(shinyOAuth.skip_id_sig = TRUE), {
    expect_error(
      shinyOAuth:::validate_id_token(
        client,
        jwt,
        expected_access_token = access_token
      ),
      class = "shinyOAuth_id_token_error",
      regexp = "at_hash"
    )
  })
})

test_that("at_hash: present in ID token but no access_token provided raises error", {
  client <- mk_client()
  now <- floor(as.numeric(Sys.time()))
  at_hash <- compute_expected_at_hash("some-token", "RS256")

  claims <- list(
    iss = client@provider@issuer,
    aud = client@client_id,
    sub = "user-1",
    exp = now + 300,
    iat = now - 1,
    at_hash = at_hash
  )
  jwt <- build_jwt(list(alg = "RS256"), claims)

  withr::with_options(list(shinyOAuth.skip_id_sig = TRUE), {
    # No expected_access_token supplied (NULL)
    expect_error(
      shinyOAuth:::validate_id_token(client, jwt),
      class = "shinyOAuth_id_token_error",
      regexp = "no access token was provided"
    )
  })
})

test_that("at_hash: absent from ID token - no validation performed", {
  client <- mk_client()
  now <- floor(as.numeric(Sys.time()))

  # No at_hash claim in the token at all
  claims <- list(
    iss = client@provider@issuer,
    aud = client@client_id,
    sub = "user-1",
    exp = now + 300,
    iat = now - 1
  )
  jwt <- build_jwt(list(alg = "RS256"), claims)

  withr::with_options(list(shinyOAuth.skip_id_sig = TRUE), {
    # Should pass fine regardless of whether access_token is supplied
    expect_silent(
      shinyOAuth:::validate_id_token(client, jwt)
    )
    expect_silent(
      shinyOAuth:::validate_id_token(
        client,
        jwt,
        expected_access_token = "any-token"
      )
    )
  })
})

test_that("at_hash: valid at_hash with ES384 alg (SHA-384)", {
  client <- mk_client()
  client@provider@allowed_algs <- c("ES384")
  now <- floor(as.numeric(Sys.time()))
  access_token <- "es384-access-token"
  at_hash <- compute_expected_at_hash(access_token, "ES384")

  claims <- list(
    iss = client@provider@issuer,
    aud = client@client_id,
    sub = "user-1",
    exp = now + 300,
    iat = now - 1,
    at_hash = at_hash
  )
  jwt <- build_jwt(list(alg = "ES384"), claims)

  withr::with_options(list(shinyOAuth.skip_id_sig = TRUE), {
    expect_silent(
      shinyOAuth:::validate_id_token(
        client,
        jwt,
        expected_access_token = access_token
      )
    )
  })
})

test_that("at_hash: valid at_hash with PS512 alg (SHA-512)", {
  client <- mk_client()
  client@provider@allowed_algs <- c("PS512")
  now <- floor(as.numeric(Sys.time()))
  access_token <- "ps512-access-token"
  at_hash <- compute_expected_at_hash(access_token, "PS512")

  claims <- list(
    iss = client@provider@issuer,
    aud = client@client_id,
    sub = "user-1",
    exp = now + 300,
    iat = now - 1,
    at_hash = at_hash
  )
  jwt <- build_jwt(list(alg = "PS512"), claims)

  withr::with_options(list(shinyOAuth.skip_id_sig = TRUE), {
    expect_silent(
      shinyOAuth:::validate_id_token(
        client,
        jwt,
        expected_access_token = access_token
      )
    )
  })
})

test_that("compute_at_hash produces correct hash for known inputs", {
  # Known test vector: SHA-256 of ASCII "test" is well-known;
  # at_hash should be the base64url of the left 16 bytes of that hash
  access_token <- "test"
  result <- shinyOAuth:::compute_at_hash(access_token, "RS256")
  # Verify manually: SHA-256("test") = 9f86d081884c7d659a2feaa0c55ad015...
  full_hash <- openssl::sha256(charToRaw(access_token))
  hash_bytes <- as.raw(full_hash)
  left_half <- hash_bytes[1:16]
  expected <- shinyOAuth:::base64url_encode(left_half)
  expect_identical(result, expected)
})

# --- id_token_at_hash_required tests -----------------------------------------

mk_client_at_hash_required <- function() {
  prov <- shinyOAuth::oauth_provider(
    name = "test-require",
    auth_url = "https://example.com/auth",
    token_url = "https://example.com/token",
    userinfo_url = NA_character_,
    userinfo_required = FALSE,
    userinfo_id_token_match = FALSE,
    issuer = "https://issuer.example.com",
    id_token_validation = TRUE,
    id_token_required = TRUE,
    allowed_algs = c("RS256", "ES256"),
    id_token_at_hash_required = TRUE
  )
  shinyOAuth::oauth_client(
    prov,
    client_id = "client-xyz",
    client_secret = "secret",
    redirect_uri = "http://localhost:8100"
  )
}

test_that("id_token_at_hash_required = TRUE: missing at_hash raises error", {
  client <- mk_client_at_hash_required()
  now <- floor(as.numeric(Sys.time()))

  claims <- list(
    iss = client@provider@issuer,
    aud = client@client_id,
    sub = "user-1",
    exp = now + 300,
    iat = now - 1
    # No at_hash claim
  )
  jwt <- build_jwt(list(alg = "RS256"), claims)

  withr::with_options(list(shinyOAuth.skip_id_sig = TRUE), {
    expect_error(
      shinyOAuth:::validate_id_token(
        client,
        jwt,
        expected_access_token = "some-token"
      ),
      class = "shinyOAuth_id_token_error",
      regexp = "missing required at_hash"
    )
  })
})

test_that("id_token_at_hash_required = TRUE: valid at_hash passes", {
  client <- mk_client_at_hash_required()
  now <- floor(as.numeric(Sys.time()))
  access_token <- "require-test-token"
  at_hash <- compute_expected_at_hash(access_token, "RS256")

  claims <- list(
    iss = client@provider@issuer,
    aud = client@client_id,
    sub = "user-1",
    exp = now + 300,
    iat = now - 1,
    at_hash = at_hash
  )
  jwt <- build_jwt(list(alg = "RS256"), claims)

  withr::with_options(list(shinyOAuth.skip_id_sig = TRUE), {
    expect_silent(
      shinyOAuth:::validate_id_token(
        client,
        jwt,
        expected_access_token = access_token
      )
    )
  })
})

test_that("id_token_at_hash_required = TRUE: invalid at_hash raises error", {
  client <- mk_client_at_hash_required()
  now <- floor(as.numeric(Sys.time()))
  wrong_at_hash <- compute_expected_at_hash("wrong-token", "RS256")

  claims <- list(
    iss = client@provider@issuer,
    aud = client@client_id,
    sub = "user-1",
    exp = now + 300,
    iat = now - 1,
    at_hash = wrong_at_hash
  )
  jwt <- build_jwt(list(alg = "RS256"), claims)

  withr::with_options(list(shinyOAuth.skip_id_sig = TRUE), {
    expect_error(
      shinyOAuth:::validate_id_token(
        client,
        jwt,
        expected_access_token = "correct-token"
      ),
      class = "shinyOAuth_id_token_error",
      regexp = "at_hash claim does not match"
    )
  })
})

test_that("id_token_at_hash_required = FALSE (default): missing at_hash is fine", {
  client <- mk_client() # default: id_token_at_hash_required = FALSE
  now <- floor(as.numeric(Sys.time()))

  claims <- list(
    iss = client@provider@issuer,
    aud = client@client_id,
    sub = "user-1",
    exp = now + 300,
    iat = now - 1
  )
  jwt <- build_jwt(list(alg = "RS256"), claims)

  withr::with_options(list(shinyOAuth.skip_id_sig = TRUE), {
    expect_silent(
      shinyOAuth:::validate_id_token(client, jwt)
    )
  })
})

test_that("id_token_at_hash_required = TRUE requires id_token_validation = TRUE", {
  expect_error(
    shinyOAuth::oauth_provider(
      name = "bad",
      auth_url = "https://example.com/auth",
      token_url = "https://example.com/token",
      issuer = "https://issuer.example.com",
      id_token_validation = FALSE,
      id_token_at_hash_required = TRUE
    ),
    regexp = "id_token_at_hash_required.*id_token_validation"
  )
})
