# Backend-shape checks and exhaustive input matrices stay in the full suite.
skip_on_cran()

test_that("state always uses authenticated GCM with a separate tag", {
  expect_true(utils::packageVersion("openssl") >= "2.6.0")
  key <- strrep("k", 64)
  payload <- list(state = "valid", issued_at = 1)
  token <- state_encrypt_gcm(payload, key)
  wrapper <- state_test_unwrap(token)
  expect_identical(wrapper[["v"]], 2L)
  expect_length(base64url_decode_raw(wrapper[["iv"]]), 12L)
  expect_length(base64url_decode_raw(wrapper[["tg"]]), 16L)
  expect_length(base64url_decode_raw(wrapper[["ct"]]), 31L)
  expect_identical(
    openssl::aes_gcm_decrypt(
      data = base64url_decode_raw(wrapper[["ct"]]),
      tag = base64url_decode_raw(wrapper[["tg"]]),
      key = normalize_key32(key), iv = base64url_decode_raw(wrapper[["iv"]])
    ),
    charToRaw(jsonlite::toJSON(payload, auto_unbox = TRUE))
  )
  # Catch ciphertext/tag concatenation and failure to pass the tag explicitly.
  decrypt <- openssl::aes_gcm_decrypt
  calls <- 0L
  local_mocked_bindings(
    aes_gcm_decrypt = function(data, key, iv, tag) {
      calls <<- calls + 1L
      expect_identical(data, base64url_decode_raw(wrapper[["ct"]]))
      expect_identical(tag, base64url_decode_raw(wrapper[["tg"]]))
      decrypt(data, key = key, iv = iv, tag = tag)
    },
    .package = "openssl"
  )
  expect_equal(state_decrypt_gcm(token, key), payload)
  expect_identical(calls, 1L)
})

test_that("GCM output must contain an explicit full-length raw authentication tag", {
  payload <- list(state = "valid")
  size <- nchar(jsonlite::toJSON(payload, auto_unbox = TRUE), type = "bytes")
  returned <- raw(size)
  local_mocked_bindings(aes_gcm_encrypt = function(...) returned, .package = "openssl")
  for (tag in list(NULL, raw(0), raw(1), raw(15), raw(17), strrep("x", 16))) {
    returned <- structure(raw(size), tag = tag)
    expect_error(
      state_encrypt_gcm(payload, strrep("k", 64)),
      "requires a 16-byte authentication tag", class = "shinyOAuth_config_error"
    )
  }
  for (invalid in list(raw(0), raw(size - 1L), raw(size + 16L), list(data = raw(size)), "invalid")) {
    returned <- structure(invalid, tag = raw(16))
    expect_error(
      state_encrypt_gcm(payload, strrep("k", 64)),
      "Unexpected ciphertext", class = "shinyOAuth_config_error"
    )
  }
})

test_that("truncated and oversized nonces and tags never reach native decryption", {
  local_options(shinyOAuth.state_fail_delay_ms = 0)
  fixture <- state_test_gcm_fixture()
  calls <- 0L
  local_mocked_bindings(
    aes_gcm_decrypt = function(...) { calls <<- calls + 1L; stop("must not decrypt") },
    .package = "openssl"
  )
  for (field in c("iv", "tg")) {
    required <- if (field == "iv") 12L else 16L
    for (size in setdiff(0:32, required)) {
      wrapper <- fixture[["wrapper"]]
      wrapper[[field]] <- base64url_encode(raw(size))
      expect_error(
        state_decrypt_gcm(state_test_wrap(wrapper), fixture[["key"]]),
        class = "shinyOAuth_state_error", info = paste(field, size)
      )
    }
  }
  expect_identical(calls, 0L)
})

test_that("short, block-boundary and Unicode payloads preserve all plaintext bytes", {
  for (size in c(0L, 1L, 15L, 16L, 17L, 31L, 32L, 33L, 1024L)) {
    payload <- list(state = strrep("s", size), label = intToUtf8(c(0xE9, 0x1F30D)))
    plaintext <- charToRaw(jsonlite::toJSON(payload, auto_unbox = TRUE))
    key <- as.raw(0:31)
    token <- state_encrypt_gcm(payload, key)
    wrapper <- state_test_unwrap(token)
    expect_length(base64url_decode_raw(wrapper[["ct"]]), length(plaintext))
    expect_identical(state_decrypt_gcm(token, key), payload)
  }
})
