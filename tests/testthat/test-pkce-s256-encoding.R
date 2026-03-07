test_that("S256 PKCE challenge matches RFC 7636 Appendix B test vector", {
  # RFC 7636 Appendix B test vector
  verifier <- "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
  expected_challenge <- "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

  sha256 <- openssl::sha256(charToRaw(verifier))
  challenge <- base64url_encode(sha256)

  expect_equal(challenge, expected_challenge)
})
