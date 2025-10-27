test_that("tampered state payload fails AES-GCM auth during callback", {
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  tok <- valid_browser_token()
  url <- shinyOAuth:::prepare_call(cli, browser_token = tok)
  enc <- parse_query_param(url, "state")

  # Tamper inside the sealed JSON (flip one base64url char in tg field)
  raw <- shinyOAuth:::b64url_decode(enc)
  obj <- jsonlite::fromJSON(rawToChar(raw), simplifyVector = TRUE)
  tg <- obj$tg
  pos <- if (nchar(tg) >= 1) 1 else stop("unexpected tg")
  ch <- substr(tg, pos, pos)
  substr(tg, pos, pos) <- if (ch == "A") "B" else "A"
  obj$tg <- tg
  tampered <- shinyOAuth:::b64url_encode(charToRaw(jsonlite::toJSON(
    obj,
    auto_unbox = TRUE
  )))

  expect_error(
    shinyOAuth:::handle_callback(
      cli,
      code = "c",
      payload = tampered,
      browser_token = tok
    )
  )
})

test_that("state_decrypt_gcm fails safely for malformed tokens", {
  key <- strrep("a", 64)

  expect_error(
    shinyOAuth:::state_decrypt_gcm("!!!", key = key),
    class = "shinyOAuth_state_error"
  )

  not_json <- shinyOAuth:::b64url_encode(charToRaw("not-json"))
  expect_error(
    shinyOAuth:::state_decrypt_gcm(not_json, key = key),
    class = "shinyOAuth_state_error"
  )

  missing_fields <- shinyOAuth:::b64url_encode(charToRaw(jsonlite::toJSON(
    list(v = 1),
    auto_unbox = TRUE
  )))
  expect_error(
    shinyOAuth:::state_decrypt_gcm(missing_fields, key = key),
    class = "shinyOAuth_state_error"
  )
})
