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
