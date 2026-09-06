test_that("discovery never repairs case-sensitive JOSE algorithm identifiers", {
  fields <- c("id_token_signing_alg_values_supported", "userinfo_signing_alg_values_supported",
    "request_object_signing_alg_values_supported", "request_object_encryption_alg_values_supported",
    "request_object_encryption_enc_values_supported", "authorization_signing_alg_values_supported",
    "token_endpoint_auth_signing_alg_values_supported", "dpop_signing_alg_values_supported")
  for (field in fields) {
    for (alg in c("rs256", "eddsa", "EDDSA", "rsa-oaep", "a256gcm", "DIR")) {
      expect_error(.discover_validate_jose_metadata(setNames(list(c("RS256", alg)), field)),
                   "invalid case")
    }
    expect_silent(.discover_validate_jose_metadata(setNames(list(c("RS256", "EdDSA", "dir")), field)))
  }
  expect_error(.discover_negotiate_algs("RS256", list(id_token_signing_alg_values_supported = "rs256"),
                                       "https://example.test"), "invalid case")
  expect_identical(.discover_negotiate_algs("EdDSA", list(id_token_signing_alg_values_supported = "EdDSA"),
                                           "https://example.test"), "EDDSA")
})
