rsa_validation_public_jwk <- function() {
  key <- openssl::rsa_keygen(bits = 2048)
  jsonlite::fromJSON(write_test_jwk(key$pubkey), simplifyVector = FALSE)
}

expect_rsa_jwk_rejected <- function(jwk, regexp) {
  expect_error(
    shinyOAuth:::validate_jwks(list(keys = list(jwk))),
    class = "shinyOAuth_parse_error",
    regexp = regexp
  )
  expect_error(
    shinyOAuth:::jwk_to_pubkey(jwk),
    class = "shinyOAuth_parse_error",
    regexp = regexp
  )
}

test_that("direct RSA thumbprints require canonical unsigned integers", {
  original <- rsa_validation_public_jwk()
  expect_type(compute_jwk_thumbprint(original), "character")
  for (field in c("n", "e")) {
    jwk <- original
    jwk[[field]] <- base64url_encode(c(as.raw(0), base64url_decode_raw(jwk[[field]])))
    expect_error(compute_jwk_thumbprint(jwk), "minimal base64urlUInt")
    for (value in c("Ax", "AQF", "AQAB=")) {
      jwk[[field]] <- value
      expect_error(compute_jwk_thumbprint(jwk), "base64urlUInt")
    }
  }
})

test_that("locally serialized RSA keys publish canonical unsigned integers", {
  jwk <- dpop_public_jwk(openssl::rsa_keygen(bits = 2048))
  expect_silent(validate_jwks(list(keys = list(jwk))))
  expect_type(compute_jwk_thumbprint(jwk), "character")
})

test_that("RSA JWK validation rejects invalid public exponents", {
  jwk <- rsa_validation_public_jwk()
  for (exponent in list(0, 1, 2, 4, c(1, 0), c(1, 0, 2))) {
    jwk$e <- shinyOAuth:::base64url_encode(as.raw(exponent))
    expect_rsa_jwk_rejected(jwk, "exponent must be odd and satisfy 3 <= e < n")
  }

  jwk$e <- jwk$n
  expect_rsa_jwk_rejected(jwk, "3 <= e < n")
})

test_that("RSA exponent bounds compare the full unsigned integer", {
  # Adjacent large integers would compare equal after conversion to doubles.
  modulus <- as.raw(c(128, rep(0, 254), 253))
  jwk <- list(
    kty = "RSA",
    n = shinyOAuth:::base64url_encode(modulus),
    e = "AQAB"
  )
  for (last in c(251, 253, 255)) {
    exponent <- modulus
    exponent[[256]] <- as.raw(last)
    jwk$e <- shinyOAuth:::base64url_encode(exponent)
    if (last < 253) {
      expect_silent(shinyOAuth:::validate_jwks(list(keys = list(jwk))))
    } else {
      expect_rsa_jwk_rejected(jwk, "3 <= e < n")
    }
  }

  jwk$e <- shinyOAuth:::base64url_encode(c(as.raw(1), modulus))
  expect_rsa_jwk_rejected(jwk, "3 <= e < n")

  for (exponent in list(3, 17, c(1, 0, 1), c(32, rep(0, 5), 1))) {
    jwk$e <- shinyOAuth:::base64url_encode(as.raw(exponent))
    expect_silent(shinyOAuth:::validate_jwks(list(keys = list(jwk))))
  }
})

test_that("RSA JWK validation rejects zero, short, and even moduli", {
  jwk <- rsa_validation_public_jwk()
  for (modulus in list(0, 1, 2, 3, c(127, rep(255, 255)))) {
    jwk$n <- shinyOAuth:::base64url_encode(as.raw(modulus))
    expect_rsa_jwk_rejected(jwk, "2048 bits")
  }

  jwk$n <- shinyOAuth:::base64url_encode(as.raw(c(128, rep(0, 255))))
  expect_rsa_jwk_rejected(jwk, "modulus must be odd")
})

test_that("RSA integers require canonical minimal Base64urlUInt encodings", {
  original <- rsa_validation_public_jwk()
  for (field in c("n", "e")) {
    decoded <- shinyOAuth:::base64url_decode_raw(original[[field]])
    jwk <- original
    jwk[[field]] <- shinyOAuth:::base64url_encode(c(as.raw(0), decoded))
    expect_rsa_jwk_rejected(jwk, "minimal base64urlUInt")

    for (value in list(
      "",
      NA_character_,
      character(),
      c("AQAB", "AQAB"),
      "A",
      "AQABA",
      "AQAB=",
      "AQAB\n",
      "AQ+B",
      "AQ/B"
    )) {
      jwk[[field]] <- value
      expect_rsa_jwk_rejected(jwk, "base64urlUInt")
    }
  }

  # These encode the same bytes as Aw and AQE, but have nonzero unused bits.
  for (value in c("Ax", "AQF")) {
    jwk <- original
    jwk$e <- value
    expect_rsa_jwk_rejected(jwk, "canonical base64urlUInt")
  }

  # A 2048-bit modulus has four unused bits in its final base64url character.
  alphabet <- strsplit(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
    "",
    fixed = TRUE
  )[[1]]
  jwk <- original
  final <- nchar(jwk$n)
  index <- match(substr(jwk$n, final, final), alphabet)
  substr(jwk$n, final, final) <- alphabet[[index + 1L]]
  expect_rsa_jwk_rejected(jwk, "canonical base64urlUInt")
})

test_that("fixed-width EC and OKP bytes retain leading zeros", {
  for (curve in c("P-256", "P-384", "P-521")) {
    width <- switch(curve, "P-256" = 32L, "P-384" = 48L, "P-521" = 66L)
    coordinate <- as.raw(c(0, rep(1, width - 1L)))
    encoded <- shinyOAuth:::base64url_encode(coordinate)
    expect_identical(
      shinyOAuth:::strict_decode_jwk_ec_coordinate(encoded, "EC JWK x", curve),
      coordinate
    )
    expect_silent(shinyOAuth:::validate_jwks(list(
      keys = list(
        list(kty = "EC", crv = curve, x = encoded, y = encoded)
      )
    )))
  }

  public_bytes <- as.raw(c(0, rep(1, 31)))
  jwk <- list(
    kty = "OKP",
    crv = "Ed25519",
    x = shinyOAuth:::base64url_encode(public_bytes)
  )
  expect_silent(shinyOAuth:::validate_jwks(list(keys = list(jwk))))
  expect_s3_class(shinyOAuth:::jwk_to_pubkey(jwk), "pubkey")
})

test_that("an e=1 candidate never reaches the signature verifier", {
  valid <- rsa_validation_public_jwk()
  invalid <- valid
  invalid$e <- "AQ"
  calls <- 0L
  testthat::local_mocked_bindings(
    verify_jws_signature_no_time = function(...) {
      calls <<- calls + 1L
      TRUE
    },
    .package = "shinyOAuth"
  )

  for (alg in c("RS256", "RS384", "RS512")) {
    calls <- 0L
    expect_null(shinyOAuth:::verify_jwt_with_jwks("unused", list(invalid), alg))
    expect_identical(calls, 0L)
    result <- shinyOAuth:::verify_jwt_with_jwks(
      "unused",
      list(invalid, valid),
      alg
    )
    expect_identical(result$jwk, valid)
    expect_identical(calls, 1L)
  }
})

test_that("valid RSA keys still verify normally signed JWTs", {
  for (bits in c(2048L, 3072L)) {
    key <- openssl::rsa_keygen(bits = bits)
    jwk <- jsonlite::fromJSON(
      write_test_jwk(key$pubkey),
      simplifyVector = FALSE
    )
    jwt <- jose::jwt_encode_sig(
      jose::jwt_claim(sub = "rsa-validation-test"),
      key
    )

    expect_silent(shinyOAuth:::validate_jwks(list(keys = list(jwk))))
    result <- shinyOAuth:::verify_jwt_with_jwks(jwt, list(jwk), "RS256")
    expect_identical(result$jwk, jwk)
    expect_s3_class(result$key, "pubkey")
  }
})
