test_that("tampered state payload fails authentication during callback", {
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  tok <- valid_browser_token()
  url <- shinyOAuth:::prepare_call(cli, browser_token = tok)
  enc <- parse_query_param(url, "state")

  # Tamper inside the sealed JSON (flip one base64url char in tg field)
  raw <- shinyOAuth:::base64url_decode_raw(enc)
  obj <- jsonlite::fromJSON(rawToChar(raw), simplifyVector = TRUE)
  tg <- obj[["tg"]]
  pos <- if (nchar(tg) >= 1) 1 else stop("unexpected tg")
  ch <- substr(tg, pos, pos)
  substr(tg, pos, pos) <- if (ch == "A") "B" else "A"
  obj[["tg"]] <- tg
  tampered <- shinyOAuth:::base64url_encode(charToRaw(jsonlite::toJSON(
    obj,
    auto_unbox = TRUE
  )))

  expect_error(
    shinyOAuth:::handle_callback(
      cli,
      code = "c",
      state = tampered,
      browser_token = tok
    ),
    "State authentication failed",
    class = "shinyOAuth_state_error"
  )
})

test_that("state_decrypt_gcm fails safely for malformed tokens", {
  key <- strrep("a", 64)

  expect_error(
    shinyOAuth:::state_decrypt_gcm("!!!", key = key),
    class = "shinyOAuth_state_error"
  )

  not_json <- shinyOAuth:::base64url_encode(charToRaw("not-json"))
  expect_error(
    shinyOAuth:::state_decrypt_gcm(not_json, key = key),
    class = "shinyOAuth_state_error"
  )

  missing_fields <- shinyOAuth:::base64url_encode(charToRaw(jsonlite::toJSON(
    list(v = 2),
    auto_unbox = TRUE
  )))
  expect_error(
    shinyOAuth:::state_decrypt_gcm(missing_fields, key = key),
    class = "shinyOAuth_state_error"
  )
})

test_that("state envelopes reject malformed UTF-8 without parser warnings", {
  for (bytes in list(0x80, 0xFF, c(0xC3, 0x28), c(0xED, 0xA0, 0x80))) {
    token <- shinyOAuth:::base64url_encode(c(
      charToRaw('{"v":1,"extension":"'), as.raw(bytes), charToRaw('"}')
    ))
    expect_warning(expect_error(
      shinyOAuth:::state_decrypt_gcm(token, key = strrep("a", 64)),
      "not valid UTF-8", class = "shinyOAuth_state_error"
    ), NA)
  }
})

test_that("GCM authentication failures preserve the rightful pending login", {
  local_options(shinyOAuth.state_fail_delay_ms = 0)
  client <- make_test_client()
  browser <- valid_browser_token()
  wire <- parse_query_param(prepare_call(client, browser), "state", decode = TRUE)
  payload <- state_decrypt_gcm(wire, client@state_key)
  state_key <- state_cache_key(payload[["state"]])
  stored <- client@state_store[["get"]](state_key)
  wrapper <- state_test_unwrap(wire)
  calls <- 0L
  local_mocked_bindings(
    swap_code_for_token_set = function(...) {
      calls <<- calls + 1L
      list(access_token = "synthetic-access", token_type = "Bearer", expires_in = 300)
    }
  )
  changed <- payload
  substr(changed[["state"]], 1L, 1L) <- if (startsWith(payload[["state"]], "A")) "B" else "A"
  plaintext <- charToRaw(jsonlite::toJSON(payload, auto_unbox = TRUE, digits = NA, null = "null"))
  changed_json <- charToRaw(jsonlite::toJSON(changed, auto_unbox = TRUE, digits = NA, null = "null"))
  forged_ct <- as.raw(bitwXor(
    as.integer(base64url_decode_raw(wrapper[["ct"]])),
    bitwXor(as.integer(plaintext), as.integer(changed_json))
  ))
  for (field in c("ct", "tg", "iv")) {
    forged <- wrapper
    forged[[field]] <- base64url_encode(if (field == "ct") {
      forged_ct
    } else {
      state_test_flip_byte(base64url_decode_raw(wrapper[[field]]))
    })
    expect_error(
      handle_callback(client, "code", state_test_wrap(forged), browser_token = browser),
      "State authentication failed", class = "shinyOAuth_state_error"
    )
    expect_identical(calls, 0L)
    expect_identical(client@state_store[["get"]](state_key), stored)
  }
  for (version in c(1L, 3L)) {
    obsolete <- wrapper
    obsolete[["v"]] <- version
    expect_error(
      handle_callback(client, "code", state_test_wrap(obsolete), browser_token = browser),
      "state token version mismatch", class = "shinyOAuth_state_error"
    )
    expect_identical(calls, 0L)
    expect_identical(client@state_store[["get"]](state_key), stored)
  }
  token <- handle_callback(client, "code", wire, browser_token = browser)
  expect_identical(token@access_token, "synthetic-access")
  expect_identical(calls, 1L)
  expect_error(
    handle_callback(client, "code", wire, browser_token = browser),
    class = "shinyOAuth_state_error"
  )
  expect_identical(calls, 1L)
})

test_that("an interrupted login after restart does not prevent a fresh login", {
  local_options(shinyOAuth.state_fail_delay_ms = 0)
  calls <- 0L
  local_mocked_bindings(
    swap_code_for_token_set = function(...) {
      calls <<- calls + 1L
      list(access_token = "synthetic-access", token_type = "Bearer", expires_in = 300)
    }
  )
  for (transport in c("encrypted", "reference")) {
    client <- make_test_client()
    client@state_transport <- transport
    browser <- valid_browser_token()
    old_wire <- parse_query_param(prepare_call(client, browser), "state", decode = TRUE)
    # Keep the same key and browser binding; only the default in-memory store resets.
    client@state_store <- cachem::cache_mem(max_age = 300)
    before <- calls
    expect_error(
      handle_callback(client, "old-code", old_wire, browser_token = browser),
      class = "shinyOAuth_state_error"
    )
    expect_identical(calls, before)
    fresh_wire <- parse_query_param(prepare_call(client, browser), "state", decode = TRUE)
    token <- handle_callback(client, "new-code", fresh_wire, browser_token = browser)
    expect_identical(token@access_token, "synthetic-access")
    expect_identical(calls, before + 1L)
  }
})
