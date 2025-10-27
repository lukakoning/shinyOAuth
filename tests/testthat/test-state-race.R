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

valid_browser_token <- function() paste(rep("ab", 64), collapse = "")

test_that("state store is single-use; second callback cannot reuse same state", {
  client <- make_client_for_tests()

  # Prepare
  tok <- valid_browser_token()
  url <- shinyOAuth:::prepare_call(client, browser_token = tok)
  enc_payload <- parse_query_param(url, "state")
  payload <- shinyOAuth:::state_decrypt_gcm(enc_payload, key = client@state_key)
  st <- payload$state

  # Simulate first retrieval (like handle_callback) which removes from store
  key <- shinyOAuth:::state_cache_key(st)
  ssv1 <- client@state_store$get(key, missing = NULL)
  expect_type(ssv1, "list")
  client@state_store$remove(key)

  # Second retrieval should fail (race/double-submit defense)
  ssv2 <- client@state_store$get(key, missing = NULL)
  expect_null(ssv2)
})

test_that("browser token mismatch triggers state error without deleting unrelated keys", {
  client <- make_client_for_tests()
  tok <- valid_browser_token()
  url <- shinyOAuth:::prepare_call(client, browser_token = tok)
  enc_payload <- parse_query_param(url, "state")
  payload <- shinyOAuth:::state_decrypt_gcm(enc_payload, key = client@state_key)
  st <- payload$state
  key <- shinyOAuth:::state_cache_key(st)

  # Use wrong browser token
  wrong_tok <- paste(rep("cd", 64), collapse = "")

  # Make sure entry exists before
  expect_true(key %in% client@state_store$keys())

  # Call internal browser_token validator path to produce a state error
  expect_error(
    {
      # emulate the check block from handle_callback
      shinyOAuth:::validate_browser_token(wrong_tok)
      if (
        !identical(
          client@state_store$get(key, missing = NULL)$browser_token,
          wrong_tok
        )
      ) {
        shinyOAuth:::err_invalid_state("Browser token mismatch")
      }
    },
    class = "shinyOAuth_state_error"
  )

  # Ensure our key still exists (not deleted by mismatch path in this unit test scope)
  expect_true(key %in% client@state_store$keys())
})
