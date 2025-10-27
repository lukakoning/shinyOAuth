test_that("state_decrypt_gcm enforces size caps and is configurable", {
  key <- strrep("k", 64)

  # Disable random delay to speed up tests
  old <- options(
    shinyOAuth.state_fail_delay_ms = 0,
    shinyOAuth.state_max_token_chars = 128, # very small for testing
    shinyOAuth.state_max_wrapper_bytes = 256,
    shinyOAuth.state_max_ct_b64_chars = 128,
    shinyOAuth.state_max_ct_bytes = 128
  )
  on.exit(options(old), add = TRUE)

  # Build a minimal valid token first
  payload <- list(state = "s", issued_at = 1)
  tok <- shinyOAuth:::state_encrypt_gcm(payload, key = key)

  # Sanity: decrypt ok under limits
  dec <- shinyOAuth:::state_decrypt_gcm(tok, key = key)
  expect_identical(dec$state, payload$state)

  # 1) Oversized base64url token string
  too_big_token <- paste0(tok, strrep("A", 200))
  expect_error(
    shinyOAuth:::state_decrypt_gcm(too_big_token, key = key),
    class = "shinyOAuth_state_error"
  )

  # 2) Oversized wrapper JSON (inflate by adding large junk field before encoding)
  wrapper <- jsonlite::fromJSON(rawToChar(shinyOAuth:::b64url_decode(tok)))
  wrapper$j <- paste(rep("x", 300), collapse = "")
  big_wrapper_raw <- charToRaw(jsonlite::toJSON(wrapper, auto_unbox = TRUE))
  big_tok <- shinyOAuth:::b64url_encode(big_wrapper_raw)
  expect_error(
    shinyOAuth:::state_decrypt_gcm(big_tok, key = key),
    class = "shinyOAuth_state_error"
  )

  # 3) Oversized ciphertext base64 length
  wrapper2 <- jsonlite::fromJSON(rawToChar(shinyOAuth:::b64url_decode(tok)))
  wrapper2$ct <- paste0(wrapper2$ct, strrep("A", 200))
  big_ct_b64_tok <- shinyOAuth:::b64url_encode(charToRaw(jsonlite::toJSON(
    wrapper2,
    auto_unbox = TRUE
  )))
  expect_error(
    shinyOAuth:::state_decrypt_gcm(big_ct_b64_tok, key = key),
    class = "shinyOAuth_state_error"
  )

  # 4) Oversized ciphertext raw bytes
  wrapper3 <- jsonlite::fromJSON(rawToChar(shinyOAuth:::b64url_decode(tok)))
  ct_raw <- shinyOAuth:::b64url_decode(wrapper3$ct)
  ct_raw <- c(ct_raw, as.raw(rep(0x00, 200)))
  wrapper3$ct <- shinyOAuth:::b64url_encode(ct_raw)
  big_ct_raw_tok <- shinyOAuth:::b64url_encode(charToRaw(jsonlite::toJSON(
    wrapper3,
    auto_unbox = TRUE
  )))
  expect_error(
    shinyOAuth:::state_decrypt_gcm(big_ct_raw_tok, key = key),
    class = "shinyOAuth_state_error"
  )
})
