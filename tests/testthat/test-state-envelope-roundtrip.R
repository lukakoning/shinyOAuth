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
  expect_identical(dec[["state"]], payload[["state"]])
  expect_identical(dec[["client_id"]], payload[["client_id"]])
  expect_identical(dec[["redirect_uri"]], payload[["redirect_uri"]])
  # Scopes should round-trip as character vector
  expect_true(is.character(dec[["scopes"]]))
  expect_identical(dec[["scopes"]], payload[["scopes"]])
  expect_identical(dec[["provider"]], payload[["provider"]])
  # Numeric may become integer; compare numerically
  expect_equal(
    as.numeric(dec[["issued_at"]]),
    as.numeric(payload[["issued_at"]])
  )

  # Decrypt with a wrong key must fail GCM authentication
  wrong_key <- strrep("x", 64)
  expect_error(
    shinyOAuth:::state_decrypt_gcm(enc1, key = wrong_key),
    "state key/secret",
    class = "shinyOAuth_state_error"
  )
})

test_that("Unicode state roundtrips under the C locale", {
  payload <- list(
    state = "s-unicode",
    provider = paste0("provider-", intToUtf8(c(0xE9, 0x1F30D))),
    scopes = c("openid", paste0("scope:", intToUtf8(0xE9))),
    extras = setNames(
      list(list(label = intToUtf8(c(0x4E2D, 0x1F600)))),
      intToUtf8(0xE9)
    )
  )
  key <- strrep("k", 64)
  token <- shinyOAuth:::state_encrypt_gcm(payload, key)

  withr::local_locale(c(LC_CTYPE = "C"))
  expect_identical(shinyOAuth:::state_decrypt_gcm(token, key), payload)
})

test_that("decrypted state rejects malformed UTF-8 without parser warnings", {
  withr::local_locale(c(LC_CTYPE = "C"))
  withr::local_options(shinyOAuth.state_fail_delay_ms = 0)
  key <- strrep("k", 64)
  token <- shinyOAuth:::state_encrypt_gcm(list(state = "valid"), key)
  decrypted <- raw()
  testthat::local_mocked_bindings(
    aes_gcm_decrypt = function(...) decrypted,
    .package = "openssl"
  )

  for (bytes in list(0x80, 0xFF, c(0xC3, 0x28), c(0xED, 0xA0, 0x80))) {
    decrypted <- c(
      charToRaw('{"state":"'), as.raw(bytes), charToRaw('"}')
    )
    expect_warning(expect_error(
      shinyOAuth:::state_decrypt_gcm(token, key),
      class = "shinyOAuth_state_error"
    ), NA)
  }
})
