test_that("audit events fire on malformed state tokens", {
  # Capture audit events via option hook
  events <- list()
  old <- options(shinyOAuth.audit_hook = function(e) {
    events[[length(events) + 1]] <<- e
  })
  on.exit(options(old), add = TRUE)

  # Use a strong enough key string to pass normalize_key32
  key <- paste(rep("k", 40), collapse = "")

  # 1) Not a base64 token
  expect_error(
    state_decrypt_gcm("***", key = key),
    class = "shinyOAuth_state_error"
  )

  # 2) Valid JSON envelope but bad fields
  bad_env <- jsonlite::toJSON(
    list(v = 1L, iv = "?", tg = "?", ct = "?"),
    auto_unbox = TRUE
  )
  tkn <- openssl::base64_encode(charToRaw(bad_env))
  tkn <- sub("=+$", "", tkn)
  tkn <- chartr("+/", "-_", tkn)
  expect_error(
    state_decrypt_gcm(tkn, key = key),
    class = "shinyOAuth_state_error"
  )

  # 3) Cache key invalid state
  expect_error(state_cache_key(""), class = "shinyOAuth_state_error")

  # Assert at least one audit_state_parse_failure event was emitted
  types <- vapply(events, function(e) as.character(e$type), character(1))
  expect_true(any(grepl("audit_state_parse_failure", types, fixed = TRUE)))

  # Validate context shape for one event
  idx <- which(grepl("audit_state_parse_failure", types))[1]
  ctx <- events[[idx]]
  expect_true(!is.null(ctx$trace_id))
  expect_equal(ctx$phase %||% NA_character_, "decrypt")
  expect_true(!is.null(ctx$reason))
})
