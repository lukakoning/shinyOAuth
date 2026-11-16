test_that("state envelopes contain independently verifiable GCM ciphertext and tag", {
  key <- strrep("k", 64)
  for (payload in list(list(x = "s"), list(state = strrep("s", 128)))) {
    json <- jsonlite::toJSON(payload, auto_unbox = TRUE, digits = NA, null = "null")
    token <- state_encrypt_gcm(payload, key)
    wrapper <- jsonlite::fromJSON(rawToChar(base64url_decode_raw(token)))
    ct <- base64url_decode_raw(wrapper[["ct"]])
    tag <- base64url_decode_raw(wrapper[["tg"]])

    expect_identical(wrapper[["v"]], 2L)
    expect_length(ct, nchar(json, type = "bytes"))
    expect_length(tag, 16L)
    expect_identical(
      openssl::aes_gcm_decrypt(
        data = ct,
        tag = tag,
        key = normalize_key32(key),
        iv = base64url_decode_raw(wrapper[["iv"]])
      ),
      charToRaw(json)
    )
    expect_identical(state_decrypt_gcm(token, key), payload)
  }
})

test_that("encryption rejects missing, malformed and unsupported tag output", {
  returned <- raw(32)
  testthat::local_mocked_bindings(
    aes_gcm_encrypt = function(...) returned,
    .package = "openssl"
  )

  for (tag in list(NULL, raw(0), raw(15), raw(17), strrep("x", 16))) {
    returned <- structure(raw(32), tag = tag)
    expect_error(
      state_encrypt_gcm(list(state = "valid"), strrep("k", 64)),
      "requires a 16-byte authentication tag",
      class = "shinyOAuth_config_error"
    )
  }
  returned <- list(data = raw(32), tag = raw(16))
  expect_error(
    state_encrypt_gcm(list(state = "valid"), strrep("k", 64)),
    "Unexpected return type",
    class = "shinyOAuth_config_error"
  )
})

test_that("GCM rejects ciphertext changes that would preserve valid JSON", {
  key <- strrep("k", 64)
  payload <- list(state = "valid", issued_at = 1)
  json <- charToRaw(jsonlite::toJSON(payload, auto_unbox = TRUE))
  token <- state_encrypt_gcm(payload, key)
  wrapper <- jsonlite::fromJSON(rawToChar(base64url_decode_raw(token)))
  ct <- base64url_decode_raw(wrapper[["ct"]])

  # GCM uses CTR encryption: XORing the plaintext difference into ciphertext
  # would produce these valid JSON objects if authentication were skipped.
  for (changed in list(
    list(state = "walid", issued_at = 1),
    list(state = "valid", issued_at = 2)
  )) {
    changed_json <- charToRaw(jsonlite::toJSON(changed, auto_unbox = TRUE))
    expect_length(changed_json, length(json))
    difference <- bitwXor(as.integer(json), as.integer(changed_json))
    wrapper[["ct"]] <- base64url_encode(as.raw(bitwXor(
      as.integer(ct), difference
    )))
    tampered <- base64url_encode(charToRaw(jsonlite::toJSON(
      wrapper, auto_unbox = TRUE
    )))
    expect_error(
      state_decrypt_gcm(tampered, key),
      "GCM authentication failed",
      class = "shinyOAuth_state_error"
    )
  }
})

test_that("GCM authenticates every tag and IV byte", {
  key <- strrep("k", 64)
  token <- state_encrypt_gcm(list(state = "valid", issued_at = 1), key)
  wrapper <- jsonlite::fromJSON(rawToChar(base64url_decode_raw(token)))

  for (field in c("tg", "iv")) {
    original <- base64url_decode_raw(wrapper[[field]])
    for (i in seq_along(original)) {
      changed <- original
      changed[i] <- as.raw(bitwXor(as.integer(changed[i]), 1L))
      altered <- wrapper
      altered[[field]] <- base64url_encode(changed)
      tampered <- base64url_encode(charToRaw(jsonlite::toJSON(
        altered, auto_unbox = TRUE
      )))
      expect_error(
        state_decrypt_gcm(tampered, key),
        "GCM authentication failed",
        class = "shinyOAuth_state_error"
      )
    }
  }
})

test_that("legacy unauthenticated envelopes cannot be resumed or relabelled", {
  key <- strrep("k", 64)
  iv <- as.raw(seq_len(12))
  json <- charToRaw(jsonlite::toJSON(
    list(state = "valid", issued_at = 1), auto_unbox = TRUE
  ))
  ciphertext <- as.raw(openssl::aes_gcm_encrypt(
    json, key = normalize_key32(key), iv = iv
  ))
  # Older openssl returned only ciphertext; the old fallback split its final
  # 16 bytes into tg without ever obtaining an authentication tag.
  legacy <- list(
    v = 1L,
    iv = base64url_encode(iv),
    tg = base64url_encode(tail(ciphertext, 16L)),
    ct = base64url_encode(head(ciphertext, -16L))
  )
  token <- base64url_encode(charToRaw(jsonlite::toJSON(legacy, auto_unbox = TRUE)))
  expect_error(
    state_decrypt_gcm(token, key),
    "state token version mismatch",
    class = "shinyOAuth_state_error"
  )

  legacy[["v"]] <- 2L
  relabelled <- base64url_encode(charToRaw(jsonlite::toJSON(
    legacy, auto_unbox = TRUE
  )))
  expect_error(
    state_decrypt_gcm(relabelled, key),
    "GCM authentication failed",
    class = "shinyOAuth_state_error"
  )
})
