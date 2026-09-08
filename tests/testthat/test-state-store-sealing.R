test_that("external state records hide credentials and authenticate context", {
  client <- make_test_client(use_pkce = TRUE, use_nonce = TRUE)
  memory <- cachem::cache_mem()
  client@state_store <- custom_cache(
    get = function(key, missing = NULL) memory$get(key, missing = missing),
    set = function(key, value) memory$set(key, value),
    remove = function(key) memory$remove(key),
    take = function(key, missing = NULL) {
      value <- memory$get(key, missing = missing)
      memory$remove(key)
      value
    }
  )
  browser <- valid_browser_token()
  url <- prepare_call(client, browser_token = browser)
  payload <- shinyOAuth:::state_decrypt_gcm(
    parse_query_param(url, "state"),
    client@state_key
  )
  state <- payload$state
  key <- shinyOAuth:::state_cache_key(state)
  sealed <- memory$get(key)
  expect_identical(names(sealed), "sealed_state_record")
  expect_false(grepl(browser, sealed$sealed_state_record, fixed = TRUE))
  record <- shinyOAuth:::state_store_get(client, state)
  expect_identical(record$browser_token, browser)
  expect_true(nzchar(record$pkce_code_verifier))
  expect_true(nzchar(record$nonce))
  same_worker <- client
  expect_identical(
    shinyOAuth:::state_store_unseal(sealed, same_worker, state),
    record
  )
  other <- client
  other@client_id <- "other-client"
  expect_error(
    shinyOAuth:::state_store_unseal(sealed, other, state),
    class = "shinyOAuth_state_error"
  )
  expect_error(
    shinyOAuth:::state_store_unseal(sealed, client, "other-state"),
    class = "shinyOAuth_state_error"
  )
  expect_error(
    shinyOAuth:::state_store_unseal(record, client, state),
    "not sealed"
  )
  expect_identical(shinyOAuth:::state_store_get_remove(client, state), record)
  expect_error(
    shinyOAuth:::state_store_get_remove(client, state),
    class = "shinyOAuth_state_error"
  )
})
