test_that("provider_fingerprint avoids delimiter collisions", {
  # Construct a minimal S7 object with the fields provider_fingerprint uses.
  # This keeps the test focused on fingerprint serialization, independent of
  # URL/host validation rules in oauth_provider().
  DummyProvider <- S7::new_class(
    "DummyProvider",
    properties = list(
      issuer = S7::class_character,
      auth_url = S7::class_character,
      token_url = S7::class_character,
      userinfo_url = S7::new_property(
        S7::class_character,
        default = NA_character_
      ),
      introspection_url = S7::new_property(
        S7::class_character,
        default = NA_character_
      )
    )
  )

  prov1 <- DummyProvider(
    issuer = "a|au=b",
    auth_url = "c",
    token_url = "d"
  )

  prov2 <- DummyProvider(
    issuer = "a",
    auth_url = "b|au=c",
    token_url = "d"
  )

  # The old implementation (key=value fields with | delimiters) can collide when
  # values contain the delimiter tokens.
  old_fp <- function(p) {
    paste0(
      "iss=",
      p@issuer,
      "|au=",
      p@auth_url,
      "|tu=",
      p@token_url
    )
  }

  expect_identical(old_fp(prov1), old_fp(prov2))

  # The new implementation must not collide.
  fp1 <- shinyOAuth:::provider_fingerprint(prov1)
  fp2 <- shinyOAuth:::provider_fingerprint(prov2)

  expect_true(startsWith(fp1, "sha256:"))
  expect_true(startsWith(fp2, "sha256:"))
  expect_false(identical(fp1, fp2))
})
