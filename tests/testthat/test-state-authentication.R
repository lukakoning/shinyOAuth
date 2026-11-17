test_that("version 3 state matches an independent CBC-HMAC fixture", {
  # Generated independently with Python cryptography AES-CBC/PKCS7 and
  # stdlib hmac/hashlib, using the RFC 7518 section 5.2 construction.
  hex <- function(x) as.raw(strtoi(substring(
    x, seq.int(1L, nchar(x), 2L), seq.int(2L, nchar(x), 2L)
  ), 16L))
  key <- as.raw(0:31)
  iv <- as.raw(0:15)
  payload <- list(state = "valid", issued_at = 1)
  testthat::local_mocked_bindings(
    rand_bytes = function(n) { stopifnot(n == 16L); iv },
    .package = "openssl"
  )
  token <- state_encrypt_gcm(payload, key)
  wrapper <- jsonlite::fromJSON(rawToChar(base64url_decode_raw(token)))
  expect_identical(wrapper[["v"]], 3L)
  expect_identical(base64url_decode_raw(wrapper[["iv"]]), iv)
  expect_identical(base64url_decode_raw(wrapper[["ct"]]), hex(
    "184baf91f1ebc3753356c04ca4b42fc512e21d36b67d99de789e0102ac168630"
  ))
  expect_identical(base64url_decode_raw(wrapper[["tg"]]), hex(
    "133a278b3ba993b601b188f06163485651f7435177f47bd27b26679ef4d8ccab"
  ))
  expect_equal(state_decrypt_gcm(token, key), payload)
})

test_that("short state payloads roundtrip without relying on GCM APIs", {
  testthat::local_mocked_bindings(
    aes_gcm_encrypt = function(...) stop("GCM must not be used"),
    aes_gcm_decrypt = function(...) stop("GCM must not be used"),
    .package = "openssl"
  )
  key <- strrep("k", 64)
  for (payload in list(list(x = "s"), list(state = strrep("s", 128)))) {
    expect_identical(state_decrypt_gcm(state_encrypt_gcm(payload, key), key), payload)
  }
  expect_error(state_encrypt_gcm(list(x = "s"), key, version = 1L), "version 3")
})

test_that("encryption rejects malformed CBC backend output", {
  returned <- raw(0)
  testthat::local_mocked_bindings(
    aes_cbc_encrypt = function(...) returned,
    .package = "openssl"
  )
  for (value in list(raw(0), raw(15), raw(17), list(data = raw(32)), "invalid")) {
    returned <- value
    expect_error(
      state_encrypt_gcm(list(state = "valid"), strrep("k", 64)),
      "Unexpected ciphertext",
      class = "shinyOAuth_config_error"
    )
  }
})

test_that("CBC rejects IV changes that would preserve valid JSON", {
  key <- strrep("k", 64)
  payload <- list(state = "valid", issued_at = 1)
  changed <- list(state = "walid", issued_at = 1)
  json <- charToRaw(jsonlite::toJSON(payload, auto_unbox = TRUE))
  changed_json <- charToRaw(jsonlite::toJSON(changed, auto_unbox = TRUE))
  token <- state_encrypt_gcm(payload, key)
  wrapper <- jsonlite::fromJSON(rawToChar(base64url_decode_raw(token)))
  iv <- base64url_decode_raw(wrapper[["iv"]])
  difference <- bitwXor(as.integer(json[1:16]), as.integer(changed_json[1:16]))
  changed_iv <- as.raw(bitwXor(as.integer(iv), difference))
  keys <- state_cbc_hmac_keys(normalize_key32(key))
  expect_identical(
    openssl::aes_cbc_decrypt(
      base64url_decode_raw(wrapper[["ct"]]), key = keys[["enc_key"]], iv = changed_iv
    ),
    changed_json
  )
  wrapper[["iv"]] <- base64url_encode(changed_iv)
  tampered <- base64url_encode(charToRaw(jsonlite::toJSON(wrapper, auto_unbox = TRUE)))
  expect_error(
    state_decrypt_gcm(tampered, key), "State authentication failed",
    class = "shinyOAuth_state_error"
  )
})

test_that("every ciphertext, tag and IV byte is verified before decryption", {
  key <- strrep("k", 64)
  token <- state_encrypt_gcm(list(state = "valid", issued_at = 1), key)
  wrapper <- jsonlite::fromJSON(rawToChar(base64url_decode_raw(token)))
  calls <- 0L
  testthat::local_mocked_bindings(
    aes_cbc_decrypt = function(...) { calls <<- calls + 1L; stop("must not decrypt") },
    .package = "openssl"
  )
  for (field in c("ct", "tg", "iv")) {
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
        state_decrypt_gcm(tampered, key), "State authentication failed",
        class = "shinyOAuth_state_error"
      )
    }
  }
  expect_error(
    state_decrypt_gcm(token, strrep("x", 64)), "State authentication failed",
    class = "shinyOAuth_state_error"
  )
  expect_identical(calls, 0L)
})

test_that("version 2 GCM records require an API that verifies tags", {
  # Independent AES-256-GCM fixture from Python cryptography AESGCM.
  hex <- function(x) as.raw(strtoi(substring(
    x, seq.int(1L, nchar(x), 2L), seq.int(2L, nchar(x), 2L)
  ), 16L))
  key <- as.raw(0:31)
  wrapper <- list(
    v = 2L,
    iv = base64url_encode(as.raw(0:11)),
    ct = base64url_encode(hex(
      "3c20a56fa491a739b763e1eadd801c4faff4ee47830e3a18670691a727587d"
    )),
    tg = base64url_encode(hex("47bb33ec2529b25d01ad4faa1753138e"))
  )
  encode <- function(x) base64url_encode(charToRaw(jsonlite::toJSON(x, auto_unbox = TRUE)))
  token <- encode(wrapper)
  if ("tag" %in% names(formals(openssl::aes_gcm_decrypt))) {
    expect_equal(state_decrypt_gcm(token, key), list(state = "valid", issued_at = 1))
    for (field in c("ct", "tg")) {
      changed <- wrapper
      raw <- base64url_decode_raw(changed[[field]])
      raw[1] <- as.raw(bitwXor(as.integer(raw[1]), 1L))
      changed[[field]] <- base64url_encode(raw)
      expect_error(state_decrypt_gcm(encode(changed), key), "State authentication failed")
    }
  } else {
    expect_error(state_decrypt_gcm(token, key), "Version 2 state requires openssl")
  }

  calls <- 0L
  testthat::local_mocked_bindings(
    aes_gcm_decrypt = function(data, key, iv) { calls <<- calls + 1L; data },
    .package = "openssl"
  )
  expect_error(state_decrypt_gcm(token, key), "Version 2 state requires openssl")
  expect_identical(calls, 0L)

  # The original format stored the last 16 ciphertext bytes as a false tag.
  ciphertext <- base64url_decode_raw(wrapper[["ct"]])
  legacy <- list(
    v = 1L, iv = wrapper[["iv"]],
    ct = base64url_encode(head(ciphertext, -16L)),
    tg = base64url_encode(tail(ciphertext, 16L))
  )
  expect_error(state_decrypt_gcm(encode(legacy), key), "state token version mismatch")
  expect_error(
    state_decrypt_gcm(encode(legacy), key, expected_version = 1L),
    "state token version mismatch"
  )
  legacy[["v"]] <- 3L
  legacy[["iv"]] <- base64url_encode(c(as.raw(0:11), raw(4)))
  legacy[["tg"]] <- base64url_encode(c(tail(ciphertext, 16L), raw(16)))
  legacy[["ct"]] <- base64url_encode(c(head(ciphertext, -16L), raw(1)))
  expect_error(state_decrypt_gcm(encode(legacy), key), "State authentication failed")
})
