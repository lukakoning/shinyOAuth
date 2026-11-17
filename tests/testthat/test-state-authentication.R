test_that("an independent GCM fixture decrypts correctly", {
  fixture <- state_test_gcm_fixture()
  expect_equal(
    state_decrypt_gcm(state_test_wrap(fixture[["wrapper"]]), fixture[["key"]]),
    list(state = "valid", issued_at = 1)
  )
})

test_that("GCM encryption and decryption match an independent known answer", {
  # Byte-for-byte JSON and backend checks run in the full suite.
  skip_on_cran()
  fixture <- state_test_gcm_fixture()
  expected <- fixture[["wrapper"]]
  payload <- list(state = "valid", issued_at = 1)
  local_mocked_bindings(
    rand_bytes = function(n) {
      stopifnot(n == 12L)
      as.raw(0:11)
    },
    .package = "openssl"
  )
  actual <- state_test_unwrap(state_encrypt_gcm(payload, fixture[["key"]]))
  expect_identical(actual[["v"]], 2L)
  for (field in c("iv", "ct", "tg")) {
    expect_identical(actual[[field]], expected[[field]], info = field)
  }
  # Decrypt the independent fixture, rather than only our own encryption.
  expect_equal(
    state_decrypt_gcm(state_test_wrap(expected), fixture[["key"]]), payload
  )
})

test_that("GCM rejects ciphertext changes that would produce valid JSON", {
  local_options(shinyOAuth.state_fail_delay_ms = 0)
  fixture <- state_test_gcm_fixture()
  original <- fixture[["wrapper"]]
  plaintext <- fixture[["plaintext"]]
  ciphertext <- base64url_decode_raw(original[["ct"]])
  for (forged_json in c(
    '{"state":"walid","issued_at":1}',
    '{"state":"valid","issued_at":2}'
  )) {
    forged_plaintext <- charToRaw(forged_json)
    difference <- bitwXor(as.integer(plaintext), as.integer(forged_plaintext))
    forged_ct <- as.raw(bitwXor(as.integer(ciphertext), difference))
    # GCM with a 96-bit nonce starts encryption at nonce || 00000002.
    # CTR demonstrates the intended plaintext without bypassing GCM's tag API.
    expect_identical(
      openssl::aes_ctr_decrypt(
        forged_ct, key = fixture[["key"]], iv = c(as.raw(0:11), as.raw(c(0, 0, 0, 2)))
      ),
      forged_plaintext
    )
    expect_true(jsonlite::validate(forged_json))
    forged <- original
    forged[["ct"]] <- base64url_encode(forged_ct)
    expect_error(
      state_decrypt_gcm(state_test_wrap(forged), fixture[["key"]]),
      "State authentication failed", class = "shinyOAuth_state_error"
    )
  }
})

test_that("GCM authenticates every bit of the ciphertext, tag and IV", {
  skip_on_cran()
  local_options(shinyOAuth.state_fail_delay_ms = 0)
  fixture <- state_test_gcm_fixture()
  wrapper <- fixture[["wrapper"]]
  for (field in c("ct", "tg", "iv")) {
    original <- base64url_decode_raw(wrapper[[field]])
    for (position in seq_along(original)) {
      for (bit in 0:7) {
        altered <- wrapper
        altered[[field]] <- base64url_encode(state_test_flip_byte(original, position, bit))
        expect_error(
          state_decrypt_gcm(state_test_wrap(altered), fixture[["key"]]),
          "State authentication failed", class = "shinyOAuth_state_error",
          info = paste(field, "byte", position, "bit", bit)
        )
      }
    }
  }
})

test_that("GCM rejects substituted fields, wrong keys and ciphertext resizing", {
  skip_on_cran()
  local_options(shinyOAuth.state_fail_delay_ms = 0)
  fixture <- state_test_gcm_fixture()
  wrapper <- fixture[["wrapper"]]
  ct <- base64url_decode_raw(wrapper[["ct"]])
  for (changed_ct in list(head(ct, -1L), c(ct, as.raw(0)), c(ct, ct))) {
    altered <- wrapper
    altered[["ct"]] <- base64url_encode(changed_ct)
    expect_error(
      state_decrypt_gcm(state_test_wrap(altered), fixture[["key"]]),
      "State authentication failed", class = "shinyOAuth_state_error"
    )
  }
  other <- state_test_unwrap(state_encrypt_gcm(
    list(state = "other", issued_at = 1), fixture[["key"]]
  ))
  for (field in c("ct", "tg", "iv")) {
    altered <- wrapper
    altered[[field]] <- other[[field]]
    expect_error(
      state_decrypt_gcm(state_test_wrap(altered), fixture[["key"]]),
      "State authentication failed", class = "shinyOAuth_state_error"
    )
  }
  for (position in seq_along(fixture[["key"]])) {
    expect_error(
      state_decrypt_gcm(
        state_test_wrap(wrapper), state_test_flip_byte(fixture[["key"]], position)
      ),
      "State authentication failed", class = "shinyOAuth_state_error"
    )
  }
})

test_that("legacy envelopes cannot be accepted by changing the expected version", {
  skip_on_cran()
  local_options(shinyOAuth.state_fail_delay_ms = 0)
  fixture <- state_test_gcm_fixture()
  wrapper <- fixture[["wrapper"]]
  calls <- 0L
  local_mocked_bindings(
    aes_gcm_decrypt = function(...) { calls <<- calls + 1L; stop("must not decrypt") },
    .package = "openssl"
  )
  for (version in list(0L, 1L, 3L, 4L, -1, 2.5, "2", NULL, TRUE, list(2L))) {
    altered <- wrapper
    altered[["v"]] <- version
    expect_error(
      state_decrypt_gcm(state_test_wrap(altered), fixture[["key"]]),
      "state token version mismatch", class = "shinyOAuth_state_error"
    )
    expect_error(
      state_decrypt_gcm(
        state_test_wrap(altered), fixture[["key"]], expected_version = version
      ),
      "state token version mismatch", class = "shinyOAuth_state_error"
    )
    expect_error(
      state_encrypt_gcm(list(state = "valid"), fixture[["key"]], version = version),
      "must use version 2", class = "shinyOAuth_input_error"
    )
  }
  expect_identical(calls, 0L)
})

test_that("relabeling original unauthenticated state cannot restore it", {
  local_options(shinyOAuth.state_fail_delay_ms = 0)
  fixture <- state_test_gcm_fixture()
  ciphertext <- base64url_decode_raw(fixture[["wrapper"]][["ct"]])
  # Version 1 split ciphertext into ct and a false tag, without authenticating it.
  legacy <- list(
    v = 1L, iv = fixture[["wrapper"]][["iv"]],
    ct = base64url_encode(head(ciphertext, -16L)),
    tg = base64url_encode(tail(ciphertext, 16L))
  )
  expect_error(
    state_decrypt_gcm(state_test_wrap(legacy), fixture[["key"]]),
    "state token version mismatch", class = "shinyOAuth_state_error"
  )
  legacy[["v"]] <- 2L
  expect_error(
    state_decrypt_gcm(state_test_wrap(legacy), fixture[["key"]]),
    "State authentication failed", class = "shinyOAuth_state_error"
  )
})

test_that("authentication failures are audited without secrets or plaintext", {
  skip_on_cran()
  fixture <- state_test_gcm_fixture()
  wrapper <- fixture[["wrapper"]]
  wrapper[["tg"]] <- base64url_encode(raw(16L))
  token <- state_test_wrap(wrapper)
  events <- list()
  local_options(
    shinyOAuth.state_fail_delay_ms = 0,
    shinyOAuth.audit_hook = function(event) {
      events[[length(events) + 1L]] <<- event
    }
  )
  expect_error(
    state_decrypt_gcm(token, fixture[["key"]]),
    "State authentication failed", class = "shinyOAuth_state_error"
  )
  reasons <- vapply(events, function(event) event[["reason"]] %||% "", character(1))
  expect_true("state_auth_failed" %in% reasons)
  serialized <- jsonlite::toJSON(events, auto_unbox = TRUE)
  for (secret in c(token, "valid", wrapper[["ct"]], wrapper[["tg"]])) {
    expect_false(grepl(secret, serialized, fixed = TRUE))
  }
})
