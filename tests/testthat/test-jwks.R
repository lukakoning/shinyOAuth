test_that("validate_jwks enforces structure and pins", {
  # Minimal RSA JWK
  rsa_jwk <- list(
    kty = "RSA",
    n = "sXch2LwS8wKk7Lw7W2jvH8o7J3H_8cRkS6PZs5x8d6E5pESm7Yv2V7h0C2Xv4v5c", # fake b64url
    e = "AQAB",
    kid = "k1"
  )
  # Minimal EC JWK
  ec_jwk <- list(
    kty = "EC",
    crv = "P-256",
    x = "f83OJ3D2xF4G4Z4Qf83OJ3D2xF4G4Z4Qf83OJ3D2xF4",
    y = "x_FEzRu9H7Wqkz2fYVb6x_FEzRu9H7Wqkz2fYVb6x_FE",
    kid = "k2"
  )
  jwks <- list(keys = list(rsa_jwk, ec_jwk))

  # Should not error without pins
  expect_silent(shinyOAuth:::validate_jwks(jwks))

  # Compute pins from our helper and enforce any/all
  tp_rsa <- shinyOAuth:::compute_jwk_thumbprint(rsa_jwk)
  tp_ec <- shinyOAuth:::compute_jwk_thumbprint(ec_jwk)
  expect_true(is.character(tp_rsa) && nzchar(tp_rsa))
  expect_true(is.character(tp_ec) && nzchar(tp_ec))

  expect_silent(shinyOAuth:::validate_jwks(
    jwks,
    pins = c(tp_rsa),
    pin_mode = "any"
  ))
  # any but non-matching should fail
  expect_error(
    shinyOAuth:::validate_jwks(jwks, pins = c("not_a_pin"), pin_mode = "any"),
    class = "shinyOAuth_parse_error"
  )
  # all requires all supported keys pinned
  expect_error(
    shinyOAuth:::validate_jwks(jwks, pins = c(tp_rsa), pin_mode = "all"),
    class = "shinyOAuth_parse_error"
  )
  expect_silent(
    shinyOAuth:::validate_jwks(jwks, pins = c(tp_rsa, tp_ec), pin_mode = "all")
  )

  # Excessive key count should error
  many <- replicate(101, rsa_jwk, simplify = FALSE)
  expect_error(
    shinyOAuth:::validate_jwks(list(keys = many)),
    class = "shinyOAuth_parse_error"
  )

  # Private parameters should be rejected
  bad_rsa <- rsa_jwk
  bad_rsa$d <- "secret"
  expect_error(
    shinyOAuth:::validate_jwks(list(keys = list(bad_rsa))),
    class = "shinyOAuth_parse_error"
  )
})

test_that("select_candidate_jwks honors key_ops field", {
  # Minimal RSA JWK for signing/verification
  rsa_verify <- list(
    kty = "RSA",
    n = "sXch2LwS8wKk7Lw7W2jvH8o7J3H_8cRkS6PZs5x8d6E5pESm7Yv2V7h0C2Xv4v5c",
    e = "AQAB",
    kid = "verify-key"
  )

  # Key with key_ops = "verify" should be kept
  rsa_ops_verify <- rsa_verify
  rsa_ops_verify$kid <- "ops-verify"
  rsa_ops_verify$key_ops <- c("verify")

  # Key with key_ops = "encrypt" only should be excluded
  rsa_ops_encrypt <- rsa_verify
  rsa_ops_encrypt$kid <- "ops-encrypt"
  rsa_ops_encrypt$key_ops <- c("encrypt", "decrypt")

  # Key with key_ops missing should be kept
  rsa_no_ops <- rsa_verify
  rsa_no_ops$kid <- "no-ops"

  jwks <- list(keys = list(rsa_ops_verify, rsa_ops_encrypt, rsa_no_ops))

  # Should filter out the encrypt-only key
  result <- shinyOAuth:::select_candidate_jwks(jwks)
  kids <- vapply(result, function(k) k$kid, character(1))
  expect_true("ops-verify" %in% kids)
  expect_true("no-ops" %in% kids)
  expect_false("ops-encrypt" %in% kids)
  expect_length(result, 2)

  # Key with both sign and verify should be kept
  rsa_ops_both <- rsa_verify
  rsa_ops_both$kid <- "ops-both"
  rsa_ops_both$key_ops <- c("sign", "verify")

  jwks2 <- list(keys = list(rsa_ops_both, rsa_ops_encrypt))
  result2 <- shinyOAuth:::select_candidate_jwks(jwks2)
  kids2 <- vapply(result2, function(k) k$kid, character(1))
  expect_true("ops-both" %in% kids2)
  expect_false("ops-encrypt" %in% kids2)
  expect_length(result2, 1)

  # Case insensitivity: "VERIFY" should work
  rsa_ops_upper <- rsa_verify
  rsa_ops_upper$kid <- "ops-upper"
  rsa_ops_upper$key_ops <- c("VERIFY")

  jwks3 <- list(keys = list(rsa_ops_upper))
  result3 <- shinyOAuth:::select_candidate_jwks(jwks3)
  expect_length(result3, 1)
})

test_that("select_candidate_jwks filters by pins when provided", {
  # Minimal RSA JWK
  rsa1 <- list(
    kty = "RSA",
    n = "sXch2LwS8wKk7Lw7W2jvH8o7J3H_8cRkS6PZs5x8d6E5pESm7Yv2V7h0C2Xv4v5c",
    e = "AQAB",
    kid = "rsa1"
  )
  rsa2 <- list(
    kty = "RSA",
    n = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtV",
    e = "AQAB",
    kid = "rsa2"
  )
  ec1 <- list(
    kty = "EC",
    crv = "P-256",
    x = "f83OJ3D2xF4G4Z4Qf83OJ3D2xF4G4Z4Qf83OJ3D2xF4",
    y = "x_FEzRu9H7Wqkz2fYVb6x_FEzRu9H7Wqkz2fYVb6x_FE",
    kid = "ec1"
  )
  jwks <- list(keys = list(rsa1, rsa2, ec1))

  # Compute thumbprints

  tp_rsa1 <- shinyOAuth:::compute_jwk_thumbprint(rsa1)
  tp_rsa2 <- shinyOAuth:::compute_jwk_thumbprint(rsa2)
  tp_ec1 <- shinyOAuth:::compute_jwk_thumbprint(ec1)

  # Without pins, all 3 keys are returned
  result_no_pins <- shinyOAuth:::select_candidate_jwks(jwks)
  expect_length(result_no_pins, 3)

  # With pins = only rsa1, only rsa1 is returned
  result_pin_rsa1 <- shinyOAuth:::select_candidate_jwks(jwks, pins = tp_rsa1)
  kids_pin_rsa1 <- vapply(result_pin_rsa1, function(k) k$kid, character(1))
  expect_length(result_pin_rsa1, 1)
  expect_equal(kids_pin_rsa1, "rsa1")

  # With pins = rsa1 and ec1, only those two are returned
  result_pin_two <- shinyOAuth:::select_candidate_jwks(
    jwks,
    pins = c(tp_rsa1, tp_ec1)
  )
  kids_pin_two <- vapply(result_pin_two, function(k) k$kid, character(1))
  expect_length(result_pin_two, 2)
  expect_true("rsa1" %in% kids_pin_two)
  expect_true("ec1" %in% kids_pin_two)
  expect_false("rsa2" %in% kids_pin_two)

  # With pins = non-matching, empty list is returned
  result_no_match <- shinyOAuth:::select_candidate_jwks(
    jwks,
    pins = c("nonexistent_thumbprint")
  )
  expect_length(result_no_match, 0)

  # Pins filtering works in combination with kid filter
  result_kid_pinned <- shinyOAuth:::select_candidate_jwks(
    jwks,
    kid = "rsa1",
    pins = tp_rsa1
  )
  expect_length(result_kid_pinned, 1)
  expect_equal(result_kid_pinned[[1]]$kid, "rsa1")

  # If kid matches but pin doesn't, no keys returned
  result_kid_unpinned <- shinyOAuth:::select_candidate_jwks(
    jwks,
    kid = "rsa2",
    pins = tp_rsa1
  )
  expect_length(result_kid_unpinned, 0)
})
