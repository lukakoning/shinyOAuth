test_that("Ed25519 verifies ID tokens, UserInfo, and JARM with exact key policy", {
  key <- openssl::ed25519_keygen()
  jwk <- list(
    kty = "OKP",
    crv = "Ed25519",
    alg = "Ed25519",
    kid = "explicit-ed",
    x = base64url_encode(as.list(key$pubkey)$data)
  )
  client <- make_test_client(use_nonce = FALSE)
  client@provider@issuer <- "https://example.com"
  client@provider@userinfo_url <- "https://example.com/userinfo"
  client@provider@allowed_algs <- "Ed25519"
  client@provider@userinfo_allowed_algs <- "Ed25519"
  client@response_mode <- "query.jwt"
  client@jarm_signed_response_alg <- "Ed25519"
  access <- "synthetic-access-token"
  expected_hash <- base64url_encode(as.raw(openssl::sha512(charToRaw(access)))[
    1:32
  ])
  expect_identical(compute_at_hash(access, "Ed25519"), expected_hash)
  claims <- list(
    iss = client@provider@issuer,
    aud = client@client_id,
    sub = "user",
    iat = as.numeric(Sys.time()),
    exp = as.numeric(Sys.time()) + 60,
    at_hash = expected_hash,
    code = "code",
    state = "state"
  )
  jwt <- encode_asymmetric_jwt_with_header(
    claims,
    key,
    list(alg = "Ed25519", kid = jwk$kid)
  )
  local_mocked_bindings(
    fetch_jwks = function(...) list(keys = list(jwk)),
    req_with_retry = function(...) {
      httr2::response(
        status_code = 200L,
        headers = list(`Content-Type` = "application/jwt"),
        body = charToRaw(jwt)
      )
    },
    .package = "shinyOAuth"
  )
  expect_identical(
    validate_id_token(client, jwt, expected_access_token = access)$sub,
    "user"
  )
  expect_identical(get_userinfo(client, access)$sub, "user")
  expect_identical(validate_jarm_response(client, jwt)$code, "code")
  expect_error(
    validate_id_token(client, jwt, expected_access_token = "different"),
    "at_hash"
  )
  wrong_curve <- jwk
  wrong_curve$crv <- "Ed448"
  expect_false(jwk_is_compatible_with_alg(wrong_curve, "Ed25519"))
  expect_length(filter_jwks_for_alg(list(jwk), "EdDSA"), 0L)
  jwk$alg <- "EdDSA"
  expect_error(validate_id_token(client, jwt, expected_access_token = access))
  expect_length(filter_jwks_for_alg(list(jwk), "Ed25519"), 0L)
})
