test_that("public JWKS rejects symmetric secrets even beside usable public keys", {
  key <- openssl::rsa_keygen(bits = 2048)
  public <- jsonlite::fromJSON(
    write_test_jwk(key$pubkey),
    simplifyVector = FALSE
  )
  expect_silent(validate_jwks(list(keys = list(public))))
  for (secret in list(
    list(kty = "oct", k = "c2VjcmV0"),
    list(kty = "oct"),
    c(public, list(k = "c2VjcmV0"))
  )) {
    expect_error(
      validate_jwks(list(keys = list(public, secret))),
      "private key material"
    )
  }
})
