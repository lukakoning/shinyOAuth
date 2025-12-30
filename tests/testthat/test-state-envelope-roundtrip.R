test_that("state_encrypt_gcm <-> state_decrypt_gcm roundtrip and properties", {
  # Fixed, deterministic payload so IV randomness is the only non-determinism
  payload <- list(
    state = "s-fixed",
    client_id = "cid",
    redirect_uri = "http://localhost/cb",
    scopes = c("openid"),
    provider = "prov-fp",
    issued_at = 1234567890
  )

  key <- strrep("k", 64)

  # Encrypt twice: should yield different tokens due to random IV
  enc1 <- shinyOAuth:::state_encrypt_gcm(payload, key = key)
  enc2 <- shinyOAuth:::state_encrypt_gcm(payload, key = key)
  expect_true(is.character(enc1) && nzchar(enc1))
  expect_true(is.character(enc2) && nzchar(enc2))
  expect_false(identical(enc1, enc2))

  # Tokens should be base64url-encoded JSON wrappers (restricted charset)
  expect_match(enc1, "^[A-Za-z0-9_\\-]+=*$")
  expect_match(enc2, "^[A-Za-z0-9_\\-]+=*$")

  # Decrypt with the correct key and verify fields round-trip
  dec <- shinyOAuth:::state_decrypt_gcm(enc1, key = key)
  expect_true(is.list(dec))
  # Validate expected fields present
  expect_true(all(names(payload) %in% names(dec)))
  expect_identical(dec$state, payload$state)
  expect_identical(dec$client_id, payload$client_id)
  expect_identical(dec$redirect_uri, payload$redirect_uri)
  # Scopes should round-trip as character vector
  expect_true(is.character(dec$scopes))
  expect_identical(dec$scopes, payload$scopes)
  expect_identical(dec$provider, payload$provider)
  # Numeric may become integer; compare numerically
  expect_equal(as.numeric(dec$issued_at), as.numeric(payload$issued_at))

  # Decrypt with a wrong key must fail GCM authentication
  wrong_key <- strrep("x", 64)
  expect_error(
    shinyOAuth:::state_decrypt_gcm(enc1, key = wrong_key),
    "state key/secret",
    class = "shinyOAuth_state_error"
  )
})
