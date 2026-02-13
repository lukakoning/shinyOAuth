test_that("canonical b64url roundtrips raw and is URL-safe", {
  set.seed(123)
  bytes <- as.raw(sample.int(256, size = 64, replace = TRUE) - 1L)

  enc <- shinyOAuth:::b64url_encode(bytes)
  dec <- shinyOAuth:::b64url_decode(enc)

  # round-trip
  expect_true(is.character(enc) && length(enc) == 1L)
  expect_true(is.raw(dec))
  expect_identical(dec, bytes)

  # URL-safe alphabet and no padding
  expect_false(grepl("[+/=]", enc))
})

test_that("wrappers mirror canonical helpers", {
  # Use bytes that will need padding in standard base64 to test both paths
  bytes1 <- charToRaw("f") # 'Zg==' -> 'Zg'
  bytes2 <- charToRaw("fo") # 'Zm8=' -> 'Zm8'
  bytes3 <- charToRaw("foobar") # multiples of 3, no padding

  for (b in list(bytes1, bytes2, bytes3)) {
    enc_canon <- shinyOAuth:::b64url_encode(b)
    enc_wrap <- shinyOAuth:::base64url_encode(b)
    expect_identical(enc_wrap, enc_canon)

    # Raw decode
    dec_raw_wrap <- shinyOAuth:::base64url_decode_raw(enc_canon)
    dec_raw_canon <- shinyOAuth:::b64url_decode(enc_canon)
    expect_identical(dec_raw_wrap, dec_raw_canon)

    # Text decode (for JSON parts); ensure it matches original text when valid UTF-8
    txt <- rawToChar(b)
    dec_txt_wrap <- shinyOAuth:::base64url_decode(enc_canon)
    expect_identical(dec_txt_wrap, txt)
  }
})

test_that("decode accepts missing or present padding equivalently", {
  # Choose input that requires padding in base64 to ensure stripped form is shorter
  b <- charToRaw("fo")
  enc <- shinyOAuth:::b64url_encode(b) # e.g., 'Zm8'

  # Manually add required '=' padding to create a padded variant
  missing <- (4 - (nchar(enc) %% 4)) %% 4
  enc_padded <- if (missing > 0) paste0(enc, strrep("=", missing)) else enc

  dec1 <- shinyOAuth:::b64url_decode(enc)
  dec2 <- shinyOAuth:::b64url_decode(enc_padded)
  expect_identical(dec1, dec2)
})

test_that("unicode text roundtrips via wrappers", {
  txt <- "héllø 🌍"
  raw <- charToRaw(txt) # UTF-8
  enc <- shinyOAuth:::base64url_encode(raw)
  out <- shinyOAuth:::base64url_decode(enc)
  expect_identical(out, txt)
})

test_that("invalid input yields empty decode without error", {
  r1 <- shinyOAuth:::b64url_decode("!@#")
  expect_true(is.raw(r1))
  expect_length(r1, 0)

  t1 <- shinyOAuth:::base64url_decode("!@#")
  expect_identical(t1, "")

  r2 <- shinyOAuth:::base64url_decode_raw("!@#")
  expect_true(is.raw(r2))
  expect_length(r2, 0)
})

test_that("base64url_decode rejects embedded NUL bytes", {
  # Encode a raw vector containing a NUL byte
  raw_with_nul <- as.raw(c(0x68, 0x65, 0x00, 0x6c, 0x6c, 0x6f)) # "he\0llo"
  encoded <- shinyOAuth:::b64url_encode(raw_with_nul)

  # Raw decode should still work (no NUL guard there)
  expect_identical(shinyOAuth:::base64url_decode_raw(encoded), raw_with_nul)

  # Text decode must reject embedded NUL

  expect_error(
    shinyOAuth:::base64url_decode(encoded),
    class = "shinyOAuth_parse_error",
    regexp = "embedded NUL"
  )
})
