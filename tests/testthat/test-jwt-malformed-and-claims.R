enc_b64url <- function(x) {
  b <- openssl::base64_encode(charToRaw(x))
  b <- gsub("=+$", "", b)
  chartr("+/", "-_", b)
}

enc_raw_b64url <- function(x) {
  b <- openssl::base64_encode(x, linebreak = FALSE)
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

test_that("Malformed JWTs are rejected with parse errors", {
  client <- mk_client()

  # Construct with two segments but header is not JSON
  bad1 <- paste(enc_b64url("not-json"), enc_b64url("{}"), "", sep = ".")
  # Ensure jsonlite::fromJSON sees a string (not a path) and fails to parse JSON
  bad2 <- paste(enc_b64url("{not json}"), enc_b64url("{}"), "", sep = ".")
  bad3 <- paste(enc_b64url("{}"), enc_b64url("not-json"), "", sep = ".")

  withr::with_options(list(shinyOAuth.skip_id_sig = TRUE), {
    # Accept either package-level parse errors or jsonlite parse errors
    expect_error(
      shinyOAuth:::validate_id_token(client, bad1),
      regexp = "Invalid JWT format|parse|lexical error"
    )
    expect_error(
      shinyOAuth:::validate_id_token(client, bad2),
      regexp = "parse|Failed|invalid"
    )
    expect_error(
      shinyOAuth:::validate_id_token(client, bad3),
      regexp = "parse|Failed|invalid|missing alg"
    )
  })
})

test_that("JWT parsing rejects padded, invalid, and empty compact segments", {
  header <- enc_b64url('{"alg":"none"}')
  payload <- enc_b64url('{"sub":"u"}')

  expect_error(
    shinyOAuth:::parse_jwt_header(paste0(header, "=.", payload, ".")),
    class = "shinyOAuth_parse_error",
    regexp = "strict base64url alphabet"
  )

  expect_error(
    shinyOAuth:::parse_jwt_payload(paste0(header, ".bad*payload.")),
    class = "shinyOAuth_parse_error",
    regexp = "strict base64url alphabet"
  )

  expect_error(
    shinyOAuth:::parse_jwt_header(paste0(".", payload, ".")),
    class = "shinyOAuth_parse_error",
    regexp = "header segment must not be empty"
  )

  expect_error(
    shinyOAuth:::parse_jwt_payload(paste0(header, "..")),
    class = "shinyOAuth_parse_error",
    regexp = "payload segment must not be empty"
  )

  expect_error(
    shinyOAuth:::jwt_verification_parts(paste0(header, ".", payload, ".AA=")),
    class = "shinyOAuth_parse_error",
    regexp = "strict base64url alphabet"
  )

  parts <- shinyOAuth:::jwt_verification_parts(paste0(
    header,
    ".",
    payload,
    "."
  ))
  expect_true(is.raw(parts$data))
  expect_true(is.raw(parts$sig))
  expect_length(parts$sig, 0)
})

test_that("JWT parsing rejects embedded NUL and invalid UTF-8 JSON text", {
  valid_header <- enc_b64url('{"alg":"none"}')
  valid_payload <- enc_b64url('{"sub":"u"}')

  nul_header <- enc_raw_b64url(c(
    charToRaw('{"alg":"none","x":"'),
    as.raw(0),
    charToRaw('"}')
  ))
  nul_payload <- enc_raw_b64url(c(
    charToRaw('{"sub":"'),
    as.raw(0),
    charToRaw('"}')
  ))
  invalid_header <- enc_raw_b64url(as.raw(c(0xff, 0xfe)))
  invalid_payload <- enc_raw_b64url(as.raw(c(0xff, 0xfe)))

  expect_error(
    shinyOAuth:::parse_jwt_header(paste0(nul_header, ".", valid_payload, ".")),
    class = "shinyOAuth_parse_error",
    regexp = "embedded NUL"
  )
  expect_error(
    shinyOAuth:::parse_jwt_header(paste0(
      invalid_header,
      ".",
      valid_payload,
      "."
    )),
    class = "shinyOAuth_parse_error",
    regexp = "valid UTF-8|decode JWT header JSON text"
  )
  expect_error(
    shinyOAuth:::parse_jwt_payload(paste0(valid_header, ".", nul_payload, ".")),
    class = "shinyOAuth_parse_error",
    regexp = "embedded NUL"
  )
  expect_error(
    shinyOAuth:::parse_jwt_payload(paste0(
      valid_header,
      ".",
      invalid_payload,
      "."
    )),
    class = "shinyOAuth_parse_error",
    regexp = "valid UTF-8|decode JWT payload JSON text"
  )
})

test_that("exp/iat/nbf boundary conditions respect leeway", {
  client <- mk_client()
  client@provider@leeway <- 5

  now <- floor(as.numeric(Sys.time()))
  base_claims <- list(
    iss = client@provider@issuer,
    aud = client@client_id,
    sub = "u",
    iat = now - 1
  )

  # exp at just inside the window (now - leeway + 1) should be valid
  c1 <- modifyList(base_claims, list(exp = now - 5 + 1))
  jwt1 <- build_jwt(list(alg = "none"), c1)
  withr::with_options(list(shinyOAuth.skip_id_sig = TRUE), {
    expect_silent(shinyOAuth:::validate_id_token(client, jwt1))
  })

  # exp just below window -> expired
  c2 <- modifyList(base_claims, list(exp = now - 6))
  jwt2 <- build_jwt(list(alg = "none"), c2)
  withr::with_options(list(shinyOAuth.skip_id_sig = TRUE), {
    expect_error(
      shinyOAuth:::validate_id_token(client, jwt2),
      class = "shinyOAuth_id_token_error",
      regexp = "expired"
    )
  })

  # iat in future beyond leeway -> reject (use +10 to avoid timing flakiness)
  c3 <- modifyList(base_claims, list(exp = now + 60, iat = now + 10))
  jwt3 <- build_jwt(list(alg = "none"), c3)
  withr::with_options(list(shinyOAuth.skip_id_sig = TRUE), {
    expect_error(
      shinyOAuth:::validate_id_token(client, jwt3),
      class = "shinyOAuth_id_token_error",
      regexp = "issued in the future"
    )
  })

  # nbf in future beyond leeway -> reject (use +10 to avoid timing flakiness)
  c4 <- modifyList(base_claims, list(exp = now + 60, nbf = now + 10))
  jwt4 <- build_jwt(list(alg = "none"), c4)
  withr::with_options(list(shinyOAuth.skip_id_sig = TRUE), {
    expect_error(
      shinyOAuth:::validate_id_token(client, jwt4),
      class = "shinyOAuth_id_token_error",
      regexp = "not yet valid"
    )
  })

  # iat exactly at leeway boundary (now + leeway) -> should be accepted
  c5 <- modifyList(base_claims, list(exp = now + 60, iat = now + 5))
  jwt5 <- build_jwt(list(alg = "none"), c5)
  withr::with_options(list(shinyOAuth.skip_id_sig = TRUE), {
    expect_silent(shinyOAuth:::validate_id_token(client, jwt5))
  })

  # nbf exactly at leeway boundary (now + leeway) -> should be accepted
  c6 <- modifyList(base_claims, list(exp = now + 60, nbf = now + 5))
  jwt6 <- build_jwt(list(alg = "none"), c6)
  withr::with_options(list(shinyOAuth.skip_id_sig = TRUE), {
    expect_silent(shinyOAuth:::validate_id_token(client, jwt6))
  })
})

test_that("signed RS256 temporal boundaries respect package leeway", {
  testthat::skip_if_not_installed("jose")

  client <- mk_client()
  client@provider@leeway <- 120

  now <- floor(as.numeric(Sys.time()))
  base_claims <- list(
    iss = client@provider@issuer,
    aud = client@client_id,
    sub = "u",
    iat = now - 1,
    exp = now + 60
  )

  rsa <- openssl::rsa_keygen(bits = 2048)
  jwk <- jsonlite::fromJSON(jose::write_jwk(rsa), simplifyVector = TRUE)
  jwks <- list(
    keys = list(list(
      kty = jwk$kty,
      n = jwk$n,
      e = jwk$e,
      kid = "k1",
      use = "sig",
      alg = "RS256"
    ))
  )

  sign_rs256 <- function(claims) {
    jose::jwt_encode_sig(
      do.call(jose::jwt_claim, claims),
      key = rsa,
      header = list(alg = "RS256", kid = "k1", typ = "JWT")
    )
  }

  validate_signed <- function(jwt) {
    testthat::with_mocked_bindings(
      fetch_jwks = function(...) jwks,
      .package = "shinyOAuth",
      shinyOAuth:::validate_id_token(client, jwt)
    )
  }

  jwt1 <- sign_rs256(modifyList(base_claims, list(exp = now - 61)))
  testthat::expect_silent(validate_signed(jwt1))

  jwt2 <- sign_rs256(modifyList(base_claims, list(nbf = now + 61)))
  testthat::expect_silent(validate_signed(jwt2))

  jwt3 <- sign_rs256(modifyList(base_claims, list(exp = now - 121)))
  testthat::expect_error(
    validate_signed(jwt3),
    class = "shinyOAuth_id_token_error",
    regexp = "expired"
  )

  jwt4 <- sign_rs256(modifyList(base_claims, list(nbf = now + 130)))
  testthat::expect_error(
    validate_signed(jwt4),
    class = "shinyOAuth_id_token_error",
    regexp = "not yet valid"
  )

  jwt5 <- sign_rs256(modifyList(base_claims, list(iat = now + 130)))
  testthat::expect_error(
    validate_signed(jwt5),
    class = "shinyOAuth_id_token_error",
    regexp = "issued in the future"
  )
})

test_that("signed HS256 exp boundary respects package leeway", {
  testthat::skip_if_not_installed("jose")

  withr::local_options(list(shinyOAuth.allow_hs = TRUE))

  secret <- paste(rep("s", 32), collapse = "")
  prov <- shinyOAuth::oauth_provider(
    name = "test-hs",
    auth_url = "https://example.com/auth",
    token_url = "https://example.com/token",
    userinfo_url = NA_character_,
    userinfo_required = FALSE,
    userinfo_id_token_match = FALSE,
    issuer = "https://issuer.example.com",
    id_token_validation = TRUE,
    id_token_required = TRUE,
    allowed_algs = c("HS256"),
    leeway = 120
  )
  client <- shinyOAuth::oauth_client(
    prov,
    client_id = "client-hs",
    client_secret = secret,
    redirect_uri = "http://localhost:8100"
  )

  now <- floor(as.numeric(Sys.time()))
  base_claims <- list(
    iss = client@provider@issuer,
    aud = client@client_id,
    sub = "u",
    iat = now - 1,
    exp = now + 60
  )

  sign_hs256 <- function(claims) {
    jose::jwt_encode_hmac(
      do.call(jose::jwt_claim, claims),
      client@client_secret,
      header = list(alg = "HS256", typ = "JWT")
    )
  }

  jwt1 <- sign_hs256(modifyList(base_claims, list(exp = now - 61)))
  testthat::expect_silent(shinyOAuth:::validate_id_token(client, jwt1))

  jwt2 <- sign_hs256(modifyList(base_claims, list(exp = now - 121)))
  testthat::expect_error(
    shinyOAuth:::validate_id_token(client, jwt2),
    class = "shinyOAuth_id_token_error",
    regexp = "expired"
  )
})

test_that("verify_hmac_jws_signature_no_time accepts valid HS256 and rejects tampering", {
  testthat::skip_if_not_installed("jose")

  secret <- paste(rep("s", 32L), collapse = "")
  now <- floor(as.numeric(Sys.time()))
  jwt <- jose::jwt_encode_hmac(
    jose::jwt_claim(
      iss = "https://issuer.example.com",
      aud = "client-hs",
      sub = "u",
      iat = now - 1,
      exp = now + 60
    ),
    secret,
    header = list(alg = "HS256", typ = "JWT")
  )

  expect_true(shinyOAuth:::verify_hmac_jws_signature_no_time(
    jwt,
    secret,
    "HS256"
  ))

  parts <- strsplit(jwt, ".", fixed = TRUE)[[1]]
  sig <- shinyOAuth:::base64url_decode_raw(parts[3])
  sig[1] <- as.raw(bitwXor(as.integer(sig[1]), 1L))
  parts[3] <- shinyOAuth:::base64url_encode(sig)
  tampered_jwt <- paste(parts, collapse = ".")

  expect_false(shinyOAuth:::verify_hmac_jws_signature_no_time(
    tampered_jwt,
    secret,
    "HS256"
  ))
})

test_that("verify_jws_signature_no_time enforces exact JOSE ECDSA signature widths", {
  testthat::skip_if_not_installed("jose")

  alg_cases <- list(
    list(alg = "ES256", curve = "P-256", width = 64L),
    list(alg = "ES384", curve = "P-384", width = 96L),
    list(alg = "ES512", curve = "P-521", width = 132L)
  )
  now <- floor(as.numeric(Sys.time()))

  for (case in alg_cases) {
    key <- try(openssl::ec_keygen(curve = case$curve), silent = TRUE)
    if (inherits(key, "try-error")) {
      testthat::skip(paste("EC key generation not supported for", case$curve))
    }

    jwt <- jose::jwt_encode_sig(
      jose::jwt_claim(
        iss = "https://issuer.example.com",
        aud = "client-es",
        sub = paste0("user-", tolower(case$alg)),
        iat = now - 1,
        exp = now + 60
      ),
      key = key,
      header = list(alg = case$alg, typ = "JWT")
    )

    expect_true(shinyOAuth:::verify_jws_signature_no_time(
      jwt,
      key$pubkey,
      case$alg
    ))

    parts <- strsplit(jwt, ".", fixed = TRUE)[[1]]
    sig <- shinyOAuth:::base64url_decode_raw(parts[3])
    expect_length(sig, case$width)

    short_sig <- sig[-seq_len(2L)]
    parts[3] <- shinyOAuth:::base64url_encode(short_sig)
    expect_false(shinyOAuth:::verify_jws_signature_no_time(
      paste(parts, collapse = "."),
      key$pubkey,
      case$alg
    ))

    long_sig <- c(sig, as.raw(c(0L, 0L)))
    parts[3] <- shinyOAuth:::base64url_encode(long_sig)
    expect_false(shinyOAuth:::verify_jws_signature_no_time(
      paste(parts, collapse = "."),
      key$pubkey,
      case$alg
    ))
  }
})

test_that("validate_id_token accepts HS256 tokens with non-ASCII client_secret", {
  withr::local_options(list(shinyOAuth.allow_hs = TRUE))

  secret <- paste(rep(intToUtf8(0x00E9), 20L), collapse = "")
  prov <- shinyOAuth::oauth_provider(
    name = "test-hs-utf8",
    auth_url = "https://example.com/auth",
    token_url = "https://example.com/token",
    userinfo_url = NA_character_,
    userinfo_required = FALSE,
    userinfo_id_token_match = FALSE,
    issuer = "https://issuer.example.com",
    id_token_validation = TRUE,
    id_token_required = TRUE,
    allowed_algs = c("HS256")
  )
  client <- shinyOAuth::oauth_client(
    prov,
    client_id = "client-hs-utf8",
    client_secret = secret,
    redirect_uri = "http://localhost:8100"
  )

  now <- floor(as.numeric(Sys.time()))
  jwt <- shinyOAuth:::encode_hmac_jwt_with_header(
    claims = list(
      iss = client@provider@issuer,
      aud = client@client_id,
      sub = "u",
      iat = now - 1,
      exp = now + 60
    ),
    secret = client@client_secret,
    header = list(alg = "HS256", typ = "JWT"),
    size = 256,
    alg = "HS256"
  )

  expect_silent(shinyOAuth:::validate_id_token(client, jwt))
})

test_that("temporal claims must be single finite numeric", {
  client <- mk_client()

  now <- floor(as.numeric(Sys.time()))
  base_claims <- list(
    iss = client@provider@issuer,
    aud = client@client_id,
    sub = "u",
    iat = now - 1
  )

  withr::with_options(list(shinyOAuth.skip_id_sig = TRUE), {
    # exp as a string -> reject
    c1 <- modifyList(base_claims, list(exp = ""))
    jwt1 <- build_jwt(list(alg = "none"), c1)
    expect_error(
      shinyOAuth:::validate_id_token(client, jwt1),
      class = "shinyOAuth_id_token_error",
      regexp = "exp claim must be a single finite number|missing exp"
    )

    # exp as vector (non-scalar) -> reject
    c2 <- modifyList(base_claims, list(exp = c(now + 10, now + 20)))
    jwt2 <- build_jwt(list(alg = "none"), c2)
    expect_error(
      shinyOAuth:::validate_id_token(client, jwt2),
      class = "shinyOAuth_id_token_error",
      regexp = "exp claim must be a single finite number|missing exp"
    )

    # iat present but as string -> reject with iat-specific message
    c3 <- modifyList(base_claims, list(exp = now + 60, iat = "oops"))
    jwt3 <- build_jwt(list(alg = "none"), c3)
    expect_error(
      shinyOAuth:::validate_id_token(client, jwt3),
      class = "shinyOAuth_id_token_error",
      regexp = "iat claim must be a single finite number"
    )

    # nbf present but as string -> reject with nbf-specific message
    c4 <- modifyList(base_claims, list(exp = now + 60, nbf = "oops"))
    jwt4 <- build_jwt(list(alg = "none"), c4)
    expect_error(
      shinyOAuth:::validate_id_token(client, jwt4),
      class = "shinyOAuth_id_token_error",
      regexp = "nbf claim must be a single finite number"
    )
  })
})

test_that("missing iat is rejected per OIDC Core", {
  client <- mk_client()
  now <- floor(as.numeric(Sys.time()))
  base_claims <- list(
    iss = client@provider@issuer,
    aud = client@client_id,
    sub = "u",
    exp = now + 60
  )
  jwt <- build_jwt(list(alg = "none"), base_claims)
  withr::with_options(list(shinyOAuth.skip_id_sig = TRUE), {
    expect_error(
      shinyOAuth:::validate_id_token(client, jwt),
      class = "shinyOAuth_id_token_error",
      regexp = "missing iat"
    )
  })
})

test_that("parse_jwt_payload rejects non-3-part inputs", {
  # 2-part string (missing signature segment)
  two_part <- paste(enc_b64url('{"alg":"none"}'), enc_b64url("{}"), sep = ".")
  expect_error(
    shinyOAuth:::parse_jwt_payload(two_part),
    class = "shinyOAuth_parse_error",
    regexp = "3 dot-separated parts"
  )

  # 4-part string (too many segments)
  four_part <- paste(
    enc_b64url('{"alg":"none"}'),
    enc_b64url("{}"),
    "",
    "extra",
    sep = "."
  )
  expect_error(
    shinyOAuth:::parse_jwt_payload(four_part),
    class = "shinyOAuth_parse_error",
    regexp = "3 dot-separated parts"
  )

  # 1-part string
  expect_error(
    shinyOAuth:::parse_jwt_payload("single-segment"),
    class = "shinyOAuth_parse_error",
    regexp = "3 dot-separated parts"
  )
})

test_that("parse_jwt_header rejects non-3-part inputs", {
  # 2-part string (missing signature segment)
  two_part <- paste(enc_b64url('{"alg":"none"}'), enc_b64url("{}"), sep = ".")
  expect_error(
    shinyOAuth:::parse_jwt_header(two_part),
    class = "shinyOAuth_parse_error",
    regexp = "3 dot-separated parts"
  )

  # 4-part string (too many segments)
  four_part <- paste(
    enc_b64url('{"alg":"none"}'),
    enc_b64url("{}"),
    "",
    "extra",
    sep = "."
  )
  expect_error(
    shinyOAuth:::parse_jwt_header(four_part),
    class = "shinyOAuth_parse_error",
    regexp = "3 dot-separated parts"
  )
})
