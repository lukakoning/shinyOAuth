parse_query_param <- function(url, name) {
  q <- sub("^[^?]*\\?", "", url)
  if (identical(q, url) || !nzchar(q)) {
    return(NA_character_)
  }
  parts <- strsplit(q, "&", fixed = TRUE)[[1]]
  kv <- strsplit(parts, "=", fixed = TRUE)
  vals <- vapply(
    kv,
    function(p) if (length(p) > 1) utils::URLdecode(p[2]) else "",
    ""
  )
  names(vals) <- vapply(kv, function(p) utils::URLdecode(p[1]), "")
  vals[[name]] %||% NA_character_
}

make_client_for_tests <- function() {
  prov <- shinyOAuth::oauth_provider_github()
  shinyOAuth::oauth_client(
    prov,
    client_id = "id",
    client_secret = "secret",
    redirect_uri = "http://localhost:8100",
    state_store = cachem::cache_mem(max_age = 600),
    state_key = paste0(
      "0123456789abcdefghijklmnopqrstuvwxyz",
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    )
  )
}

with_option <- function(opt, value, code) {
  old <- getOption(opt)
  on.exit(options(structure(list(old), names = opt)), add = TRUE)
  options(structure(list(value), names = opt))
  force(code)
}

# Valid 128-hex-char browser token helper
valid_browser_token <- function() paste(rep("ab", 64), collapse = "")

test_that("prepare_call rejects oversized browser_token and does not cache", {
  client <- make_client_for_tests()

  # initial keys
  k0 <- sort(client@state_store$keys())

  huge <- strrep("A", 1024 * 1024) # 1MB
  expect_error(
    shinyOAuth:::prepare_call(client, browser_token = huge),
    class = "shinyOAuth_pkce_error"
  )

  # keys unchanged
  k1 <- sort(client@state_store$keys())
  expect_identical(k0, k1)
})

test_that("prepare_call accepts valid token and caches state values", {
  client <- make_client_for_tests()

  tok <- valid_browser_token()
  url <- shinyOAuth:::prepare_call(client, browser_token = tok)
  expect_true(is.character(url) && length(url) == 1L && nzchar(url))

  enc_payload <- parse_query_param(url, "state")
  expect_true(is.character(enc_payload) && nzchar(enc_payload))

  payload <- shinyOAuth:::state_decrypt_gcm(enc_payload, key = client@state_key)
  st <- payload$state
  expect_true(is.character(st) && nzchar(st))

  key <- shinyOAuth:::state_cache_key(st)
  val <- client@state_store$get(key, missing = NULL)
  expect_type(val, "list")
  expect_true(all(
    c("browser_token", "pkce_code_verifier", "nonce") %in% names(val)
  ))
  expect_identical(val$browser_token, tok)
})

test_that("prepare_call rejects malformed length browser_token", {
  client <- make_client_for_tests()

  too_short <- paste(rep("a", 127), collapse = "")
  expect_error(
    shinyOAuth:::prepare_call(client, browser_token = too_short),
    class = "shinyOAuth_pkce_error"
  )

  too_long_hex <- paste(rep("A", 129), collapse = "")
  expect_error(
    shinyOAuth:::prepare_call(client, browser_token = too_long_hex),
    class = "shinyOAuth_pkce_error"
  )
})
