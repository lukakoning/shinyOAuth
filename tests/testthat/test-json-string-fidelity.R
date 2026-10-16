test_that("protocol JSON rejects malformed UTF-8 before scanning strings", {
  for (bytes in list(0x80, 0xFF, c(0xC3, 0x28), c(0xED, 0xA0, 0x80))) {
    text <- rawToChar(c(charToRaw('{"value":"'), as.raw(bytes), charToRaw('"}')))
    Encoding(text) <- "UTF-8"
    expect_warning(expect_error(
      shinyOAuth:::reject_duplicate_json_object_members(text, "Protocol JSON"),
      "invalid UTF-8", class = "shinyOAuth_parse_error"
    ), NA)
  }
})

test_that("protocol JSON rejects lossy Unicode escapes in all strings", {
  for (escape in c(
    "\\u0000", "\\ud800", "\\uDBFF", "\\udc00", "\\uDFFF",
    "\\ud800\\u0061", "\\ud800\\\\udc00", "\\ud800\\ud800"
  )) {
    for (text in c(
      paste0('{"sub":"', escape, 'suffix"}'),
      paste0('{"sub":"prefix', escape, 'suffix"}'),
      paste0('{"sub":"prefix', escape, '"}'),
      paste0('{"sub', escape, '":"user"}'),
      paste0('{"extension":[{"value":"', escape, '"}]}')
    )) {
      expect_error(
        shinyOAuth:::reject_duplicate_json_object_members(text, "Protocol JSON"),
        "escaped NUL|unpaired Unicode surrogate",
        class = "shinyOAuth_parse_error"
      )
    }
  }
})

test_that("protocol JSON preserves literal backslashes and valid Unicode", {
  text <- paste0(
    '{"literal":"\\\\u0000",',
    '"surrogate_text":"\\\\ud800",',
    '"emoji":"\\ud83d\\ude00",',
    '"accent":"\\u00e9","escaped_quote":"\\\"",',
    '"newline":"\\n"}'
  )
  expect_no_error(
    shinyOAuth:::reject_duplicate_json_object_members(text, "Protocol JSON")
  )
  decoded <- jsonlite::fromJSON(text, simplifyVector = FALSE)
  expect_identical(decoded[["literal"]], "\\u0000")
  expect_identical(decoded[["surrogate_text"]], "\\ud800")
  expect_identical(decoded[["emoji"]], intToUtf8(0x1F600))
  expect_identical(decoded[["accent"]], "\u00e9")
  expect_identical(decoded[["escaped_quote"]], '"')
  expect_identical(decoded[["newline"]], "\n")
})

test_that("JARM duplicate issuer compatibility cannot hide lossy strings", {
  for (suffix in c("\\u0000suffix", "\\ud800")) {
    text <- paste0(
      '{"iss":"issuer","iss":"issuer","iss":"issuer', suffix, '"}'
    )
    normalized <- shinyOAuth:::normalize_duplicate_jarm_iss_claim(text)
    expect_identical(normalized, text)
    expect_error(
      shinyOAuth:::reject_duplicate_json_object_members(normalized, "JWT payload"),
      "escaped NUL|unpaired Unicode surrogate"
    )
  }
})

test_that("real signed ID tokens reject lossy claim and header strings", {
  key <- openssl::rsa_keygen(2048)
  jwk <- jsonlite::fromJSON(write_test_jwk(key[["pubkey"]]), simplifyVector = FALSE)
  jwk[["kid"]] <- "unicode-key"
  cli <- make_test_client(use_nonce = TRUE)
  cli@provider@id_token_validation <- TRUE
  cli@provider@allowed_algs <- "RS256"
  testthat::local_mocked_bindings(
    fetch_jwks = function(...) list(keys = list(jwk)),
    .package = "shinyOAuth"
  )
  now <- floor(as.numeric(Sys.time()))
  payload <- paste0(
    '{"iss":"https://issuer.example.com","aud":"abc","sub":"user",',
    '"nonce":"expected","iat":', now, ',"exp":', now + 300, '}'
  )
  header <- '{"alg":"RS256","kid":"unicode-key"}'
  sign <- function(payload, header) {
    input <- paste(
      shinyOAuth:::base64url_encode(charToRaw(header)),
      shinyOAuth:::base64url_encode(charToRaw(payload)), sep = "."
    )
    signature <- openssl::signature_create(
      charToRaw(input), hash = openssl::sha256, key = key
    )
    paste(input, shinyOAuth:::base64url_encode(signature), sep = ".")
  }
  validate <- function(payload, header) {
    shinyOAuth:::validate_id_token(cli, sign(payload, header), "expected")
  }
  expect_true(attr(validate(payload, header), "signature_verified", exact = TRUE))
  for (target in c("https://issuer.example.com", "abc", "user", "expected")) {
    expect_error(
      validate(sub(target, paste0(target, "\\u0000other"), payload, fixed = TRUE), header),
      "escaped NUL", class = "shinyOAuth_id_token_error"
    )
  }
  expect_error(
    validate(payload, sub("RS256", "RS256\\u0000other", header, fixed = TRUE)),
    "escaped NUL", class = "shinyOAuth_id_token_error"
  )
  expect_error(
    validate(sub('"nonce":', '"nonce\\u0000alias":', payload, fixed = TRUE), header),
    "escaped NUL", class = "shinyOAuth_id_token_error"
  )
  expect_error(
    validate(sub('"user"', '"user\\ud800"', payload, fixed = TRUE), header),
    "unpaired Unicode surrogate", class = "shinyOAuth_id_token_error"
  )
})

test_that("HTTP protocol parsers reject escaped NUL names and values", {
  response <- function(body) httr2::response(
    status_code = 200L,
    headers = list("Content-Type" = "application/json"),
    body = charToRaw(body)
  )
  expect_error(
    shinyOAuth:::parse_token_response(response(
      '{"access_token\\u0000alias":"token","token_type":"Bearer"}'
    )), "escaped NUL"
  )
  expect_error(
    shinyOAuth:::parse_token_response(response(
      '{"access_token":"token\\u0000other","token_type":"Bearer"}'
    )), "escaped NUL"
  )
  expect_error(testthat::with_mocked_bindings(
    oauth_provider_oidc_discover("https://issuer.example.com"),
    .discover_fetch_response = function(...) response(
      '{"issuer":"https://issuer.example.com\\u0000other"}'
    ), .package = "shinyOAuth"
  ), "escaped NUL")

  cli <- make_test_client(use_nonce = TRUE)
  cli@provider@userinfo_url <- "https://example.com/userinfo"
  cli@provider@userinfo_required <- TRUE
  cli@provider@userinfo_id_token_match <- TRUE
  cli@provider@introspection_url <- "https://example.com/introspect"
  token <- OAuthToken(
    access_token = "synthetic", token_type = "Bearer",
    id_token = build_dummy_jwt(list(sub = "user")), id_token_validated = TRUE
  )
  expect_error(testthat::with_mocked_bindings(
    get_userinfo(cli, token),
    req_with_retry = function(...) response('{"sub":"user\\u0000other"}'),
    .package = "shinyOAuth"
  ), class = "shinyOAuth_userinfo_error")
  introspection <- testthat::with_mocked_bindings(
    introspect_token(cli, token),
    req_with_retry = function(...) response('{"active\\u0000alias":true}'),
    .package = "shinyOAuth"
  )
  expect_identical(introspection[["status"]], "invalid_json")
  expect_false(isTRUE(introspection[["active"]]))
  expect_null(introspection[["raw"]])
})

test_that("state envelopes reject lossy strings without changing valid ciphertext", {
  key <- strrep("a", 64)
  sealed <- shinyOAuth:::state_encrypt_gcm(list(state = "original"), key)
  expect_identical(
    shinyOAuth:::state_decrypt_gcm(sealed, key)[["state"]], "original"
  )
  text <- shinyOAuth:::base64url_decode(sealed)
  for (altered in c(
    sub('"ct":', '"ct\\u0000alias":', text, fixed = TRUE),
    paste0(substr(text, 1L, nchar(text) - 1L), ',"extension":"\\ud800"}')
  )) {
    expect_error(
      shinyOAuth:::state_decrypt_gcm(
        shinyOAuth:::base64url_encode(charToRaw(altered)), key
      ), class = "shinyOAuth_state_error"
    )
  }
})
