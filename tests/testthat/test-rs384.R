test_that("RS384 client assertions use SHA-384 and preserve registered headers and claims", {
  key <- openssl::rsa_keygen(2048)
  provider <- make_test_provider()
  provider@token_auth_style <- "private_key_jwt"
  provider@token_endpoint_auth_signing_alg_values_supported <- "RS384"
  client <- oauth_client(
    provider,
    client_id = "synthetic-client",
    redirect_uri = "https://app.example/callback",
    client_assertion_private_key = key,
    client_assertion_private_key_kid = "registered-key",
    client_assertion_alg = "RS384"
  )
  jwt <- shinyOAuth:::build_client_assertion(client, provider@token_url)
  parts <- strsplit(jwt, ".", fixed = TRUE)[[1]]
  header <- shinyOAuth:::parse_jwt_header(jwt)
  claims <- jsonlite::fromJSON(rawToChar(jose::base64url_decode(parts[[2]])))
  expect_identical(
    header,
    list(typ = "JWT", alg = "RS384", kid = "registered-key")
  )
  expect_identical(claims$iss, client@client_id)
  expect_identical(claims$sub, client@client_id)
  expect_identical(claims$aud, provider@token_url)
  expect_lte(claims$exp - claims$iat, 300)
  expect_true(nzchar(claims$jti))
  public <- openssl::read_pubkey(openssl::write_pem(key))
  input <- charToRaw(paste(parts[1:2], collapse = "."))
  # Verify independently of jose's encoder and the package JWT parser.
  expect_true(openssl::signature_verify(
    input,
    jose::base64url_decode(parts[[3]]),
    hash = openssl::sha384,
    pubkey = public
  ))
  expect_error(openssl::signature_verify(
    input,
    jose::base64url_decode(parts[[3]]),
    hash = openssl::sha256,
    pubkey = public
  ))
  expect_error(
    oauth_client(
      provider,
      client_id = "synthetic-client",
      redirect_uri = "https://app.example/callback",
      client_assertion_private_key = key
    ),
    "RS256"
  )
})

test_that("RS384 rejects incompatible and weak keys without changing defaults", {
  strong <- openssl::rsa_keygen(2048)
  weak <- openssl::rsa_keygen(1024)
  ec <- openssl::ec_keygen("P-384")
  expect_true(shinyOAuth:::private_key_can_sign_jws_alg(strong, "RS384"))
  expect_false(shinyOAuth:::private_key_can_sign_jws_alg(weak, "RS384"))
  expect_false(shinyOAuth:::private_key_can_sign_jws_alg(ec, "RS384"))
  expect_identical(
    shinyOAuth:::choose_default_alg_for_private_key(strong),
    "RS256"
  )
  expect_error(
    shinyOAuth:::encode_asymmetric_jwt_with_header(
      jose::jwt_claim(sub = "synthetic"),
      key = ec,
      header = list(typ = "JWT", alg = "RS384")
    ),
    "incompatible"
  )
})
