test_that("public JWK extensions do not alter RSA or EC key import", {
  for (key in list(openssl::rsa_keygen(), openssl::ec_keygen())) {
    original <- jsonlite::fromJSON(
      write_test_jwk(key$pubkey),
      simplifyVector = FALSE
    )
    alg <- if (original[["kty"]] == "RSA") "RS256" else "ES256"
    jwt <- jose::jwt_encode_sig(
      jose::jwt_claim(sub = "test-subject"),
      key = key,
      header = list(alg = alg, kid = "public-key")
    )
    for (field in c("description", "display_name", "custom_metadata")) {
      jwk <- original
      jwk[["kid"]] <- "public-key"
      jwk[[field]] <- "A public signing key"
      expect_silent(validate_jwks(list(keys = list(jwk))))
      imported <- jwk_to_pubkey(jwk)
      expect_s3_class(imported, "pubkey")
      expect_identical(
        openssl::write_der(imported),
        openssl::write_der(key$pubkey)
      )
      verified <- verify_jwt_with_jwks(jwt, list(jwk), alg)
      expect_identical(verified[["jwk"]], jwk)
      expect_identical(
        compute_jwk_thumbprint(jwk),
        compute_jwk_thumbprint(original)
      )
    }
  }
})
