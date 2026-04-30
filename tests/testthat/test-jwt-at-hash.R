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
compute_expected_at_hash <- function(access_token, alg, eddsa_curve = NULL) {
  alg <- toupper(alg)

  hash_fn <- if (grepl("256", alg, fixed = TRUE)) {
    openssl::sha256
  } else if (grepl("384", alg, fixed = TRUE)) {
    openssl::sha384
  } else if (grepl("512", alg, fixed = TRUE)) {
    openssl::sha512
  } else if (identical(alg, "EDDSA")) {
    if (identical(toupper(eddsa_curve %||% ""), "ED25519")) {
      openssl::sha512
    } else {
      stop("unsupported EdDSA test curve", call. = FALSE)
    }
  } else {
    stop("unsupported test alg", call. = FALSE)
  }
  full_hash <- hash_fn(charToRaw(access_token))
  hash_bytes <- as.raw(full_hash)
  left_half <- hash_bytes[seq_len(length(hash_bytes) %/% 2L)]
  shinyOAuth:::base64url_encode(left_half)
}

make_ed25519_keypair <- function() {
  testthat::skip_if_not_installed("sodium")

  exports <- getNamespaceExports("sodium")
  kp <- if ("signature_keygen" %in% exports) {
    try(sodium::signature_keygen(), silent = TRUE)
  } else if ("signature_keypair" %in% exports) {
    try(sodium::signature_keypair(), silent = TRUE)
  } else {
    NULL
  }

  if (inherits(kp, "try-error") || is.null(kp)) {
    testthat::skip("Ed25519 key generation not supported on this platform")
  }

  list(
    pubkey = kp$pubkey,
    secret = if (!is.null(kp$key)) kp$key else kp$secretkey
  )
}

sign_ed25519_jwt <- function(header, claims, secret) {
  header_json <- jsonlite::toJSON(header, auto_unbox = TRUE, null = "null")
  claims_json <- jsonlite::toJSON(claims, auto_unbox = TRUE, null = "null")
  signing_input <- paste0(
    shinyOAuth:::base64url_encode(charToRaw(as.character(header_json))),
    ".",
    shinyOAuth:::base64url_encode(charToRaw(as.character(claims_json)))
  )
  sig <- sodium::signature(charToRaw(signing_input), secret)

  paste0(signing_input, ".", shinyOAuth:::base64url_encode(sig))
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

test_that("at_hash: valid at_hash with RS512 alg (SHA-512)", {
  client <- mk_client()
  client@provider@allowed_algs <- c("RS512")
  now <- floor(as.numeric(Sys.time()))
  access_token <- "rs512-access-token"
  at_hash <- compute_expected_at_hash(access_token, "RS512")

  claims <- list(
    iss = client@provider@issuer,
    aud = client@client_id,
    sub = "user-1",
    exp = now + 300,
    iat = now - 1,
    at_hash = at_hash
  )
  jwt <- build_jwt(list(alg = "RS512"), claims)

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

test_that("compute_at_hash uses the Ed25519 mapping for EdDSA", {
  access_token <- "test-access-token"
  result <- shinyOAuth:::compute_at_hash(
    access_token,
    "EdDSA",
    eddsa_curve = "Ed25519"
  )
  full_hash <- openssl::sha512(charToRaw(access_token))
  expected <- shinyOAuth:::base64url_encode(
    as.raw(full_hash)[seq_len(length(full_hash) %/% 2L)]
  )

  expect_identical(result, expected)
})

test_that("compute_at_hash requires a resolved EdDSA curve", {
  expect_error(
    shinyOAuth:::compute_at_hash("test-access-token", "EdDSA"),
    class = "shinyOAuth_id_token_error",
    regexp = "resolved verified curve"
  )
})

test_that("compute_at_hash rejects unsupported Ed448 mapping", {
  expect_error(
    shinyOAuth:::compute_at_hash(
      "test-access-token",
      "EdDSA",
      eddsa_curve = "Ed448"
    ),
    class = "shinyOAuth_id_token_error",
    regexp = "Ed448"
  )
})

test_that("at_hash validation rejects EdDSA tokens when signature verification is skipped", {
  client <- mk_client()
  client@provider@allowed_algs <- c("EdDSA")
  now <- floor(as.numeric(Sys.time()))
  access_token <- "access-token"

  jwt <- build_jwt(
    list(alg = "EdDSA"),
    list(
      iss = client@provider@issuer,
      aud = client@client_id,
      sub = "user-1",
      exp = now + 300,
      iat = now - 1,
      at_hash = compute_expected_at_hash(
        access_token,
        "EdDSA",
        eddsa_curve = "Ed25519"
      )
    )
  )

  withr::with_options(list(shinyOAuth.skip_id_sig = TRUE), {
    expect_error(
      shinyOAuth:::validate_id_token(
        client,
        jwt,
        expected_access_token = access_token
      ),
      class = "shinyOAuth_id_token_error",
      regexp = "signature verification is skipped"
    )
  })
})

test_that("at_hash validation accepts Ed25519 tokens after verified curve resolution", {
  keypair <- make_ed25519_keypair()
  client <- mk_client()
  client@provider@allowed_algs <- c("EdDSA")
  now <- floor(as.numeric(Sys.time()))
  access_token <- "access-token"
  pub_jwk <- list(
    kty = "OKP",
    crv = "Ed25519",
    x = shinyOAuth:::base64url_encode(keypair$pubkey),
    kid = "ed25519-at-hash"
  )

  jwt <- sign_ed25519_jwt(
    list(alg = "EdDSA", kid = pub_jwk$kid, typ = "JWT"),
    list(
      iss = client@provider@issuer,
      aud = client@client_id,
      sub = "user-1",
      exp = now + 300,
      iat = now - 1,
      at_hash = compute_expected_at_hash(
        access_token,
        "EdDSA",
        eddsa_curve = "Ed25519"
      )
    ),
    secret = keypair$secret
  )

  expect_silent(testthat::with_mocked_bindings(
    fetch_jwks = function(
      issuer,
      jwks_cache,
      force_refresh = FALSE,
      pins = NULL,
      pin_mode = c("any", "all"),
      provider = NULL
    ) {
      list(keys = list(pub_jwk))
    },
    .package = "shinyOAuth",
    shinyOAuth:::validate_id_token(
      client,
      jwt,
      expected_access_token = access_token
    )
  ))
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
