test_that("JWE native decryption uses a fresh process that exits after each call", {
  key <- openssl::rsa_keygen(2048)
  compact <- jwe_compact_encrypt(
    "header.payload.signature", key[["pubkey"]],
    "RSA-OAEP", "A256CBC-HS512"
  )
  sessions <- list()
  create_session <- new_jwe_decryption_session
  local_mocked_bindings(new_jwe_decryption_session = function() {
    worker <- create_session()
    sessions[[length(sessions) + 1L]] <<- worker
    expect_true(worker[["is_alive"]]())
    expect_false(identical(worker[["get_pid"]](), Sys.getpid()))
    worker
  })
  # These bindings affect this R process only. A successful round trip proves
  # neither native decryptor was invoked in the calling Shiny/async worker.
  local_mocked_bindings(
    rsa_decrypt = function(...) stop("RSA decryption reached the parent"),
    aes_cbc_decrypt = function(...) stop("AES decryption reached the parent"),
    .package = "openssl"
  )
  for (i in seq_len(2)) {
    expect_identical(
      jwe_compact_decrypt(compact, key)[["plaintext"]],
      "header.payload.signature"
    )
    expect_false(sessions[[i]][["is_alive"]]())
  }
  expect_length(sessions, 2L)
  expect_false(identical(sessions[[1]], sessions[[2]]))
})

test_that("RSA and authenticated CBC errors terminate their decryption processes", {
  key <- openssl::rsa_keygen(2048)
  enc <- "A256CBC-HS512"
  cek <- openssl::rand_bytes(64)
  keys <- split_jwe_cbc_hmac_cek(cek, enc)
  protected <- base64url_encode(charToRaw(
    '{"alg":"RSA-OAEP","enc":"A256CBC-HS512","cty":"JWT"}'
  ))
  encrypted_key <- openssl::rsa_encrypt(cek, key[["pubkey"]], oaep = TRUE)
  iv <- raw(16)
  ciphertext <- openssl::aes_cbc_encrypt(charToRaw("test"), keys[["enc_key"]], iv)
  # One block of plaintext has twelve padding bytes. Flip its final byte to
  # zero via the IV, then authenticate the modified IV with the known CEK.
  bad_iv <- iv
  bad_iv[[16L]] <- as.raw(12)
  sessions <- list()
  calls <- 0L
  failures <- 0L
  create_session <- new_jwe_decryption_session
  local_mocked_bindings(new_jwe_decryption_session = function() {
    worker <- create_session()
    sessions[[length(sessions) + 1L]] <<- worker
    list(
      run = function(...) {
        calls <<- calls + 1L
        tryCatch(worker[["run"]](...), error = function(e) {
          failures <<- failures + 1L
          stop(e)
        })
      },
      close = worker[["close"]],
      finalize = worker[["finalize"]]
    )
  })
  local_mocked_bindings(
    rsa_decrypt = function(...) stop("RSA decryption reached the parent"),
    aes_cbc_decrypt = function(...) stop("AES decryption reached the parent"),
    .package = "openssl"
  )
  for (failure in c("RSA-OAEP", "CBC padding")) {
    calls <- failures <- 0L
    current_iv <- if (failure == "CBC padding") bad_iv else iv
    current_key <- if (failure == "RSA-OAEP") raw(length(encrypted_key)) else encrypted_key
    tag <- compute_compact_jwe_auth_tag(
      enc, keys[["mac_key"]], protected, current_iv, ciphertext
    )
    compact <- paste(
      protected, base64url_encode(current_key), base64url_encode(current_iv),
      base64url_encode(ciphertext), base64url_encode(tag), sep = "."
    )
    error <- expect_error(jwe_compact_decrypt(compact, key), "Compact JWE decryption failed")
    expect_identical(
      error[["context"]][["compact_jwe_failure"]],
      "authenticated_decryption"
    )
    expect_false(sessions[[length(sessions)]][["is_alive"]]())
    expect_identical(calls, if (failure == "RSA-OAEP") 1L else 2L)
    expect_identical(failures, 1L)
  }
  expect_length(sessions, 2L)
})

test_that("decryption process startup fails closed without dependency diagnostics", {
  key <- openssl::rsa_keygen(2048)
  compact <- jwe_compact_encrypt(
    "header.payload.signature", key[["pubkey"]],
    "RSA-OAEP", "A128CBC-HS256"
  )
  local_mocked_bindings(new_jwe_decryption_session = function() {
    stop("synthetic private diagnostic")
  })
  error <- expect_error(jwe_compact_decrypt(compact, key), "Compact JWE decryption failed")
  expect_false(grepl("synthetic private diagnostic", conditionMessage(error), fixed = TRUE))
  expect_identical(error[["context"]][["compact_jwe_failure"]], "authenticated_decryption")
})

test_that("parent-side failures also close the JWE decryption process", {
  key <- openssl::rsa_keygen(2048)
  compact <- jwe_compact_encrypt(
    "header.payload.signature", key[["pubkey"]],
    "RSA-OAEP", "A128CBC-HS256"
  )
  worker <- NULL
  create_session <- new_jwe_decryption_session
  local_mocked_bindings(
    new_jwe_decryption_session = function() {
      worker <<- create_session()
      worker
    },
    compute_compact_jwe_auth_tag = function(...) stop("synthetic parent failure")
  )
  expect_error(jwe_compact_decrypt(compact, key), "synthetic parent failure")
  expect_false(worker[["is_alive"]]())
})

test_that("a decryption process startup timeout closes and finalizes the process", {
  closed <- finalized <- FALSE
  local_mocked_bindings(
    r_session = list(new = function(options, wait) {
      expect_false(wait)
      list(
        poll_process = function(timeout) "timeout",
        close = function(grace) {
          closed <<- TRUE
        },
        finalize = function() {
          finalized <<- TRUE
        }
      )
    }),
    .package = "callr"
  )
  expect_error(new_jwe_decryption_session(), "did not start")
  expect_true(closed)
  expect_true(finalized)
})
