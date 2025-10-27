test_that("jwks_cache_key changes with pins and mode; validate_jwks used to evict incompatible entries", {
  # Build a minimal JWKS and two pins
  rsa_jwk <- list(kty = "RSA", n = "n", e = "AQAB", kid = "k1")
  jwks <- list(keys = list(rsa_jwk))

  # Compute actual pin for our key using helper; if it errors, skip
  tp <- try(shinyOAuth:::compute_jwk_thumbprint(rsa_jwk), silent = TRUE)
  if (inherits(tp, "try-error")) {
    skip("thumbprint not available")
  }

  cache <- cachem::cache_mem(max_age = 3600)
  issuer <- "https://issuer.example.com"

  # Derive keys
  k_any_none <- shinyOAuth:::jwks_cache_key(
    issuer,
    pins = NULL,
    pin_mode = "any"
  )
  k_any_pin <- shinyOAuth:::jwks_cache_key(issuer, pins = tp, pin_mode = "any")
  k_all_pin <- shinyOAuth:::jwks_cache_key(issuer, pins = tp, pin_mode = "all")
  expect_false(identical(k_any_none, k_any_pin))
  expect_false(identical(k_any_pin, k_all_pin))

  # Manually set an entry under k_any_pin
  cache$set(k_any_pin, list(jwks = jwks, fetched_at = as.numeric(Sys.time())))

  # Now attempt to fetch under a different policy -> validate_jwks should be called and mismatch should evict
  # We simulate fetch_jwks validate eviction by directly calling validate_jwks with a non-matching pins list
  expect_error(
    shinyOAuth:::validate_jwks(jwks, pins = c("not-a-pin"), pin_mode = "any"),
    class = "shinyOAuth_parse_error"
  )

  # Storing under one policy does not satisfy 'all' with an extra fake key
  jwks2 <- list(
    keys = list(
      rsa_jwk,
      list(kty = "EC", crv = "P-256", x = "x", y = "y", kid = "k2")
    )
  )
  cache$set(k_any_pin, list(jwks = jwks2, fetched_at = as.numeric(Sys.time())))
  expect_error(
    shinyOAuth:::validate_jwks(jwks2, pins = c(tp), pin_mode = "all"),
    class = "shinyOAuth_parse_error"
  )
})
