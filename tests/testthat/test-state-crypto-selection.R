test_that("GCM selection includes openssl 2.6.0 and later releases", {
  expect_false(state_openssl_gcm_available("2.1.2"))
  expect_false(state_openssl_gcm_available("2.5.99"))
  expect_true(state_openssl_gcm_available("2.6.0"))
  expect_true(state_openssl_gcm_available("2.6.0.9000"))
  expect_true(state_openssl_gcm_available("2.10.0"))
})

test_that("new state selects the installed openssl backend and roundtrips", {
  if (state_openssl_gcm_available()) {
    local_mocked_bindings(
      state_warn_old_openssl = function(...) stop("unexpected upgrade warning")
    )
  }
  key <- strrep("k", 64)
  payload <- list(state = "valid", issued_at = 1)
  token <- state_encrypt_gcm(payload, key)
  wrapper <- jsonlite::fromJSON(rawToChar(base64url_decode_raw(token)))
  modern <- state_openssl_gcm_available()
  expect_identical(wrapper[["v"]], if (modern) 2L else 3L)
  expect_length(base64url_decode_raw(wrapper[["iv"]]), if (modern) 12L else 16L)
  expect_length(base64url_decode_raw(wrapper[["tg"]]), if (modern) 16L else 32L)
  expect_equal(state_decrypt_gcm(token, key), payload)

  if (modern) {
    expect_identical(
      openssl::aes_gcm_decrypt(
        data = base64url_decode_raw(wrapper[["ct"]]),
        tag = base64url_decode_raw(wrapper[["tg"]]),
        key = normalize_key32(key),
        iv = base64url_decode_raw(wrapper[["iv"]])
      ),
      charToRaw(jsonlite::toJSON(payload, auto_unbox = TRUE))
    )
    cbc <- state_encrypt_gcm(payload, key, version = 3L)
    expect_equal(state_decrypt_gcm(cbc, key), payload)
  } else {
    expect_error(
      state_encrypt_gcm(payload, key, version = 2L),
      "requires openssl >= 2.6.0", class = "shinyOAuth_config_error"
    )
  }
})

test_that("CBC-HMAC on older openssl warns only once across clients and keys", {
  rlang::reset_warning_verbosity("shinyOAuth-openssl-upgrade")
  withr::defer(suppressWarnings(state_warn_old_openssl()))
  local_mocked_bindings(state_openssl_gcm_available = function(...) FALSE)
  warnings <- list()
  tokens <- withCallingHandlers(
    lapply(c("a", "b", "c"), function(client) {
      state_encrypt_gcm(list(client = client), strrep(client, 64))
    }),
    warning = function(w) {
      warnings[[length(warnings) + 1L]] <<- w
      invokeRestart("muffleWarning")
    }
  )
  expect_length(tokens, 3L)
  expect_length(warnings, 1L)
  expect_s3_class(warnings[[1L]], "shinyOAuth_openssl_upgrade_warning")
  expect_match(conditionMessage(warnings[[1L]]), "2.6.0", fixed = TRUE)
  expect_match(conditionMessage(warnings[[1L]]), 'install.packages("openssl")', fixed = TRUE)
  expect_match(conditionMessage(warnings[[1L]]), "restart R", fixed = TRUE)
})

test_that("modern GCM output requires a real tag without silently falling back", {
  returned <- raw(32)
  local_mocked_bindings(state_openssl_gcm_available = function(...) TRUE)
  local_mocked_bindings(
    aes_gcm_encrypt = function(...) returned,
    .package = "openssl"
  )
  local_mocked_bindings(
    state_warn_old_openssl = function(...) stop("unexpected upgrade warning")
  )
  for (tag in list(NULL, raw(0), raw(15), raw(17), strrep("x", 16))) {
    returned <- structure(raw(32), tag = tag)
    expect_error(
      state_encrypt_gcm(list(state = "valid"), strrep("k", 64)),
      "requires a 16-byte authentication tag", class = "shinyOAuth_config_error"
    )
  }
  returned <- list(data = raw(32), tag = raw(16))
  expect_error(
    state_encrypt_gcm(list(state = "valid"), strrep("k", 64)),
    "Unexpected ciphertext", class = "shinyOAuth_config_error"
  )
})
