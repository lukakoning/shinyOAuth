test_that("state_decrypt_gcm rejects invalid token shapes and types", {
  # Disable random delay to keep tests snappy
  old <- options(shinyOAuth.state_fail_delay_ms = 0)
  on.exit(options(old), add = TRUE)

  key <- strrep("k", 64)

  # Non-string token types
  expect_error(
    shinyOAuth:::state_decrypt_gcm(NULL, key = key),
    "token must be a non-empty single string",
    class = "shinyOAuth_state_error"
  )
  expect_error(
    shinyOAuth:::state_decrypt_gcm(NA_character_, key = key),
    "token must be a non-empty single string",
    class = "shinyOAuth_state_error"
  )
  expect_error(
    shinyOAuth:::state_decrypt_gcm("", key = key),
    "token must be a non-empty single string",
    class = "shinyOAuth_state_error"
  )
  expect_error(
    shinyOAuth:::state_decrypt_gcm(c("a", "b"), key = key),
    "token must be a non-empty single string",
    class = "shinyOAuth_state_error"
  )
  expect_error(
    shinyOAuth:::state_decrypt_gcm(123, key = key),
    "token must be a non-empty single string",
    class = "shinyOAuth_state_error"
  )

  # Helper to build a valid minimal wrapper we can then mutate
  build_valid_token <- function() {
    payload <- list(state = "s", issued_at = 1)
    shinyOAuth:::state_encrypt_gcm(payload, key = key)
  }

  tok <- build_valid_token()
  wrapper <- jsonlite::fromJSON(rawToChar(shinyOAuth:::b64url_decode(tok)))

  # Version mismatch
  w <- wrapper
  w$v <- 2L
  t2 <- shinyOAuth:::b64url_encode(charToRaw(jsonlite::toJSON(
    w,
    auto_unbox = TRUE
  )))
  expect_error(
    shinyOAuth:::state_decrypt_gcm(t2, key = key, expected_version = 1L),
    "state token version mismatch",
    class = "shinyOAuth_state_error"
  )

  # IV missing/invalid base64/invalid length
  w <- wrapper
  w$iv <- NULL
  t3 <- shinyOAuth:::b64url_encode(charToRaw(jsonlite::toJSON(
    w,
    auto_unbox = TRUE
  )))
  expect_error(
    shinyOAuth:::state_decrypt_gcm(t3, key = key),
    "state token missing IV",
    class = "shinyOAuth_state_error"
  )

  w <- wrapper
  w$iv <- "***"
  t4 <- shinyOAuth:::b64url_encode(charToRaw(jsonlite::toJSON(
    w,
    auto_unbox = TRUE
  )))
  expect_error(
    shinyOAuth:::state_decrypt_gcm(t4, key = key),
    "invalid GCM IV length",
    class = "shinyOAuth_state_error"
  )

  w <- wrapper
  w$iv <- shinyOAuth:::b64url_encode(as.raw(1:8))
  t5 <- shinyOAuth:::b64url_encode(charToRaw(jsonlite::toJSON(
    w,
    auto_unbox = TRUE
  )))
  expect_error(
    shinyOAuth:::state_decrypt_gcm(t5, key = key),
    "invalid GCM IV length",
    class = "shinyOAuth_state_error"
  )

  # Tag missing/invalid base64/invalid length
  w <- wrapper
  w$tg <- NULL
  t6 <- shinyOAuth:::b64url_encode(charToRaw(jsonlite::toJSON(
    w,
    auto_unbox = TRUE
  )))
  expect_error(
    shinyOAuth:::state_decrypt_gcm(t6, key = key),
    "state token missing tag",
    class = "shinyOAuth_state_error"
  )

  w <- wrapper
  w$tg <- "@@@"
  t7 <- shinyOAuth:::b64url_encode(charToRaw(jsonlite::toJSON(
    w,
    auto_unbox = TRUE
  )))
  expect_error(
    shinyOAuth:::state_decrypt_gcm(t7, key = key),
    "invalid GCM tag length",
    class = "shinyOAuth_state_error"
  )

  w <- wrapper
  w$tg <- shinyOAuth:::b64url_encode(as.raw(1:8))
  t8 <- shinyOAuth:::b64url_encode(charToRaw(jsonlite::toJSON(
    w,
    auto_unbox = TRUE
  )))
  expect_error(
    shinyOAuth:::state_decrypt_gcm(t8, key = key),
    "invalid GCM tag length",
    class = "shinyOAuth_state_error"
  )

  # Ciphertext missing/invalid base64/empty
  w <- wrapper
  w$ct <- NULL
  t9 <- shinyOAuth:::b64url_encode(charToRaw(jsonlite::toJSON(
    w,
    auto_unbox = TRUE
  )))
  expect_error(
    shinyOAuth:::state_decrypt_gcm(t9, key = key),
    "state token missing ciphertext",
    class = "shinyOAuth_state_error"
  )

  w <- wrapper
  w$ct <- "??"
  t10 <- shinyOAuth:::b64url_encode(charToRaw(jsonlite::toJSON(
    w,
    auto_unbox = TRUE
  )))
  expect_error(
    shinyOAuth:::state_decrypt_gcm(t10, key = key),
    "empty ciphertext",
    class = "shinyOAuth_state_error"
  )

  w <- wrapper
  w$ct <- shinyOAuth:::b64url_encode(raw(0))
  t11 <- shinyOAuth:::b64url_encode(charToRaw(jsonlite::toJSON(
    w,
    auto_unbox = TRUE
  )))
  expect_error(
    shinyOAuth:::state_decrypt_gcm(t11, key = key),
    "state token missing ciphertext",
    class = "shinyOAuth_state_error"
  )

  # Bad UTF-8 in wrapper payload (after base64 decode, before JSON parse)
  bad_utf8 <- as.raw(c(0xff, 0xfe, 0xfd))
  t_utf8 <- shinyOAuth:::b64url_encode(bad_utf8)
  expect_error(
    shinyOAuth:::state_decrypt_gcm(t_utf8, key = key),
    "state token payload is not valid JSON",
    class = "shinyOAuth_state_error"
  )
})

test_that("state_encrypt_gcm validates inputs and decrypt fails on tamper", {
  key <- strrep("k", 64)

  # Encrypt rejects NULL payload
  expect_error(
    shinyOAuth:::state_encrypt_gcm(NULL, key = key),
    "payload is NULL",
    class = "shinyOAuth_input_error"
  )

  # Happy path roundtrip then tamper tag (flip one byte) -> GCM auth fail
  payload <- list(state = "ok", issued_at = 1)
  tok <- shinyOAuth:::state_encrypt_gcm(payload, key = key)
  wrapper <- jsonlite::fromJSON(rawToChar(shinyOAuth:::b64url_decode(tok)))
  tg_raw <- shinyOAuth:::b64url_decode(wrapper$tg)
  tg_raw[1] <- as.raw(bitwXor(as.integer(tg_raw[1]), 0x01))
  wrapper$tg <- shinyOAuth:::b64url_encode(tg_raw)
  tampered <- shinyOAuth:::b64url_encode(charToRaw(jsonlite::toJSON(
    wrapper,
    auto_unbox = TRUE
  )))
  expect_error(
    shinyOAuth:::state_decrypt_gcm(tampered, key = key),
    "state token decrypted payload is not valid JSON",
    class = "shinyOAuth_state_error"
  )
})

test_that("normalize_key32 error paths bubble through decrypt", {
  tok <- shinyOAuth:::state_encrypt_gcm(
    list(state = "s", issued_at = 1),
    key = strrep("k", 64)
  )

  # Bad key types/lengths should raise config errors (not state errors)
  expect_error(
    shinyOAuth:::state_decrypt_gcm(tok, key = NULL),
    "state key is NULL",
    class = "shinyOAuth_config_error"
  )
  expect_error(
    shinyOAuth:::state_decrypt_gcm(tok, key = raw(16)),
    "raw state key must be at least 32 bytes; got 16",
    class = "shinyOAuth_config_error"
  )
  expect_error(
    shinyOAuth:::state_decrypt_gcm(tok, key = "short"),
    "state key must be at least 32 characters; got 5",
    class = "shinyOAuth_config_error"
  )
})

test_that("state_decrypt_gcm includes state-key mismatch hints", {
  # Disable random delay to keep tests snappy and deterministic
  old <- options(shinyOAuth.state_fail_delay_ms = 0)
  on.exit(options(old), add = TRUE)

  key <- strrep("k", 64)
  tok <- shinyOAuth:::state_encrypt_gcm(
    list(state = "ok", issued_at = 1),
    key = key
  )

  # 1) Force GCM auth failure branch
  testthat::local_mocked_bindings(
    aes_gcm_decrypt = function(...) stop("auth failed"),
    .package = "openssl"
  )
  e1 <- tryCatch(
    shinyOAuth:::state_decrypt_gcm(tok, key = key),
    error = function(e) e
  )
  expect_s3_class(e1, "shinyOAuth_state_error")
  m1 <- conditionMessage(e1)
  expect_match(m1, "GCM authentication failed", fixed = TRUE)
  expect_match(m1, "state key/secret", fixed = TRUE)
  expect_match(m1, "OAuthClient created inside a Shiny session", fixed = TRUE)

  # 2) Force decrypted JSON invalid branch
  testthat::local_mocked_bindings(
    aes_gcm_decrypt = function(...) charToRaw("not-json"),
    .package = "openssl"
  )
  e2 <- tryCatch(
    shinyOAuth:::state_decrypt_gcm(tok, key = key),
    error = function(e) e
  )
  expect_s3_class(e2, "shinyOAuth_state_error")
  m2 <- conditionMessage(e2)
  expect_match(
    m2,
    "state token decrypted payload is not valid JSON",
    fixed = TRUE
  )
  expect_match(m2, "state key/secret", fixed = TRUE)
  expect_match(m2, "OAuthClient created inside a Shiny session", fixed = TRUE)
})
