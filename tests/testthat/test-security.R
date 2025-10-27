test_that("normalize_key32 is case-sensitive for passphrases", {
  # Two different-case passphrases of sufficient length should derive different keys
  a_lower <- paste(rep("a", 32), collapse = "")
  a_upper <- paste(rep("A", 32), collapse = "")
  k_lower <- shinyOAuth:::normalize_key32(a_lower)
  k_upper <- shinyOAuth:::normalize_key32(a_upper)
  expect_false(identical(k_lower, k_upper))
  expect_type(k_lower, "raw")
  expect_equal(length(k_lower), 32L)
})

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

with_option <- function(opt, value, code) {
  old <- getOption(opt)
  on.exit(options(structure(list(old), names = opt)), add = TRUE)
  options(structure(list(value), names = opt))
  force(code)
}

test_that("state is stored under hashed lowercase-hex cache key", {
  # Build a simple client with deterministic state_key
  prov <- shinyOAuth::oauth_provider_github()
  client <- shinyOAuth::oauth_client(
    prov,
    client_id = "id",
    client_secret = "secret",
    redirect_uri = "http://localhost:8100",
    # isolate cache for this test
    state_store = cachem::cache_mem(max_age = 600),
    # long, stable state key for test
    state_key = paste0(
      "0123456789abcdefghijklmnopqrstuvwxyz",
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    )
  )

  # Skip browser token requirement for this unit test
  auth_url <- with_option(
    "shinyOAuth.skip_browser_token",
    TRUE,
    shinyOAuth:::prepare_call(client, browser_token = NULL)
  )

  # Extract and decrypt the payload to recover the original high-entropy state
  enc_payload <- parse_query_param(auth_url, "state")
  expect_true(
    is.character(enc_payload) &&
      length(enc_payload) == 1L &&
      nzchar(enc_payload)
  )
  payload <- shinyOAuth:::state_decrypt_gcm(enc_payload, key = client@state_key)
  raw_state <- payload$state
  expect_true(
    is.character(raw_state) && length(raw_state) == 1L && nzchar(raw_state)
  )

  # Compute expected cache key and assert it exists and is lowercase-hex
  expected_key <- shinyOAuth:::state_cache_key(raw_state)
  keys <- client@state_store$keys()
  expect_true(expected_key %in% keys)
  expect_match(expected_key, "^[0-9a-f]+$")

  # And the stored value round-trips using the derived key
  val <- client@state_store$get(expected_key, missing = NULL)
  expect_type(val, "list")
  expect_true(all(
    c("browser_token", "pkce_code_verifier", "nonce") %in% names(val)
  ))
})
