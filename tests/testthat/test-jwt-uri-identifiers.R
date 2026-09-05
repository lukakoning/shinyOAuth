test_that("client assertions and JAR preserve URI identifiers", {
  for (style in c("client_secret_jwt", "private_key_jwt")) {
    client <- make_test_client(use_nonce = FALSE)
    client@client_id <- "urn:example:client"
    client@client_secret <- strrep("s", 64)
    client@client_assertion_private_key <- openssl::rsa_keygen()
    client@provider@token_auth_style <- style
    client@client_assertion_audience <- "urn:example:audience"
    jwt <- build_client_assertion(client, client@client_assertion_audience)
    claims <- if (style == "client_secret_jwt") {
      jose::jwt_decode_hmac(jwt, secret = client@client_secret)
    } else {
      jose::jwt_decode_sig(
        jwt,
        pubkey = as.list(client@client_assertion_private_key)$pubkey
      )
    }
    expect_identical(claims$iss, client@client_id)
    expect_identical(claims$sub, client@client_id)
    expect_identical(claims$aud, client@client_assertion_audience)
    client@request_object_audience <- "urn:example:authorization"
    client@request_object_mode <- "request"
    client@request_object_signing_alg <- if (style == "client_secret_jwt") {
      "HS256"
    } else {
      "RS256"
    }
    jar <- build_authorization_request_object(
      client,
      list(
        client_id = client@client_id,
        response_type = "code",
        redirect_uri = client@redirect_uri,
        state = "state"
      )
    )
    expect_identical(parse_jwt_payload(jar)$iss, client@client_id)
    expect_identical(parse_jwt_payload(jar)$aud, "urn:example:authorization")
  }
  for (bad in c("bad:has space", "1scheme:value", "urn:bad%xx")) {
    expect_error(outbound_jwt_claim(list(iss = bad)), "Invalid URI")
  }
})
