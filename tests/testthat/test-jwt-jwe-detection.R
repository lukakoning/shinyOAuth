test_that("validate_id_token rejects JWE compact serialization (5 segments)", {
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  # Give the provider an issuer + allowed_algs so validation would normally proceed
  cli@provider@issuer <- "https://issuer.example.com"
  cli@provider@allowed_algs <- c("RS256")

  # JWE compact serialization has 5 dot-separated Base64url parts:
  # header.encrypted_key.iv.ciphertext.tag
  jwe_token <- paste(
    rep("eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ", 5),
    collapse = "."
  )

  expect_error(
    shinyOAuth:::validate_id_token(cli, jwe_token),
    class = "shinyOAuth_id_token_error",
    regexp = "encrypted JWT.*JWE|JWE.*not supported"
  )
})

test_that("validate_id_token still accepts valid JWS tokens (3 segments)", {
  testthat::skip_if_not_installed("jose")

  base <- "http://localhost"
  now <- as.numeric(Sys.time())

  rsa <- openssl::rsa_keygen(bits = 2048)
  priv_jwk_json <- jose::write_jwk(rsa)
  priv_jwk <- jsonlite::fromJSON(priv_jwk_json, simplifyVector = TRUE)
  pub_jwk <- list(kty = priv_jwk$kty, n = priv_jwk$n, e = priv_jwk$e)
  pub_jwk$kid <- "rsa-jwe-test"

  prov <- oauth_provider(
    name = "local-jwe",
    auth_url = paste0(base, "/auth"),
    token_url = paste0(base, "/token"),
    issuer = base,
    allowed_algs = c("RS256")
  )
  cli <- oauth_client(
    provider = prov,
    client_id = "client-jwe",
    client_secret = "ignore",
    redirect_uri = paste0(base, "/cb")
  )

  claims <- jose::jwt_claim(
    iss = base,
    aud = "client-jwe",
    sub = "user-jwe",
    exp = now + 120,
    iat = now - 1
  )

  id_token <- jose::jwt_encode_sig(claims, key = rsa)

  # A valid 3-segment JWS should pass the JWE check and proceed normally
  result <- testthat::with_mocked_bindings(
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
    shinyOAuth:::validate_id_token(cli, id_token)
  )

  expect_equal(result$sub, "user-jwe")
})

test_that("validate_id_token rejects JWE even when header looks like a valid JWT", {
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  cli@provider@issuer <- "https://issuer.example.com"
  cli@provider@allowed_algs <- c("RS256")

  # Craft a JWE-like token where the first segment decodes to a JWE header

  # containing typ = "JWT" (which is valid for JWE per RFC 7516 §4.1.11)
  jwe_header <- jsonlite::toJSON(
    list(alg = "RSA-OAEP", enc = "A256GCM", typ = "JWT"),
    auto_unbox = TRUE
  )
  jwe_header_b64 <- shinyOAuth:::base64url_encode(charToRaw(jwe_header))

  # 5 segments: header + 4 dummy parts
  jwe_token <- paste(
    jwe_header_b64,
    "dummykey",
    "dummyiv",
    "dummycipher",
    "dummytag",
    sep = "."
  )

  # Should be caught at the 5-segment check, not at typ/alg checks
  expect_error(
    shinyOAuth:::validate_id_token(cli, jwe_token),
    class = "shinyOAuth_id_token_error",
    regexp = "encrypted JWT.*JWE|JWE.*not supported"
  )
})
