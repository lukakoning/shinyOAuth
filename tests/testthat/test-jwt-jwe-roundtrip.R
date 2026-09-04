# 1. compact JWE helpers ------------------------------------------------------

test_that("compact JWE helpers round-trip a nested JWT", {
  rsa_key <- openssl::rsa_keygen()
  inner_jwt <- paste(
    c(
      "eyJhbGciOiJSUzI1NiIsInR5cCI6Im9hdXRoLWF1dGh6LXJlcStqd3QifQ",
      "eyJpc3MiOiJzaGlueU9BdXRoIiwic3ViIjoidGVzdC1jbGllbnQifQ",
      "c2lnbmF0dXJl"
    ),
    collapse = "."
  )

  compact_jwe <- shinyOAuth:::jwe_compact_encrypt(
    plaintext = inner_jwt,
    public_key = rsa_key$pubkey,
    alg = "RSA-OAEP",
    enc = "A256CBC-HS512",
    kid = "test-kid",
    typ = "oauth-authz-req+jwt",
    cty = "JWT"
  )

  expect_length(strsplit(compact_jwe, ".", fixed = TRUE)[[1]], 5L)

  decrypted <- shinyOAuth:::jwe_compact_decrypt(compact_jwe, rsa_key)

  expect_identical(decrypted$header$alg, "RSA-OAEP")
  expect_identical(decrypted$header$enc, "A256CBC-HS512")
  expect_identical(decrypted$header$kid, "test-kid")
  expect_identical(decrypted$header$typ, "oauth-authz-req+jwt")
  expect_identical(decrypted$header$cty, "JWT")
  expect_identical(decrypted$plaintext, inner_jwt)
})

test_that("compact JWE helpers reject RSA keys smaller than 2048 bits", {
  weak_key <- openssl::rsa_keygen(bits = 1024)
  strong_key <- openssl::rsa_keygen(bits = 2048)

  expect_error(
    shinyOAuth:::jwe_compact_encrypt(
      plaintext = "header.payload.signature",
      public_key = weak_key$pubkey,
      alg = "RSA-OAEP",
      enc = "A128CBC-HS256"
    ),
    class = "shinyOAuth_config_error",
    regexp = "RSA modulus must be at least 2048 bits"
  )

  compact_jwe <- shinyOAuth:::jwe_compact_encrypt(
    plaintext = "header.payload.signature",
    public_key = strong_key$pubkey,
    alg = "RSA-OAEP",
    enc = "A128CBC-HS256"
  )
  expect_error(
    shinyOAuth:::jwe_compact_decrypt(compact_jwe, weak_key),
    class = "shinyOAuth_config_error",
    regexp = "RSA modulus must be at least 2048 bits"
  )
})


# 2. compact JWE integrity failures -------------------------------------------

test_that("compact JWE helpers collapse authenticated decryption failures", {
  rsa_key <- openssl::rsa_keygen()
  compact_jwe <- shinyOAuth:::jwe_compact_encrypt(
    plaintext = "header.payload.signature",
    public_key = rsa_key$pubkey,
    alg = "RSA-OAEP",
    enc = "A256CBC-HS512",
    cty = "JWT"
  )

  for (part_index in c(2L, 4L, 5L)) {
    parts <- strsplit(compact_jwe, ".", fixed = TRUE)[[1]]
    tampered_part <- shinyOAuth:::base64url_decode_raw(parts[[part_index]])
    tampered_part[1] <- as.raw(bitwXor(as.integer(tampered_part[1]), 1L))
    parts[[part_index]] <- shinyOAuth:::base64url_encode(tampered_part)

    expect_error(
      shinyOAuth:::jwe_compact_decrypt(paste(parts, collapse = "."), rsa_key),
      "Compact JWE decryption failed"
    )
  }
})
