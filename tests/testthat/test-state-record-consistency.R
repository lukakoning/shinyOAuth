test_that("callback consumption rejects changed security fields", {
  client <- make_test_client(use_pkce = TRUE, use_nonce = TRUE)
  expected <- list(
    browser_token = valid_browser_token(),
    pkce_code_verifier = strrep("a", 43),
    nonce = "original-nonce"
  )
  for (field in names(expected)) {
    consumed <- expected
    consumed[[field]] <- paste0(consumed[[field]], "changed")
    local_mocked_bindings(
      state_store_get_remove = function(...) consumed,
      .package = "shinyOAuth"
    )
    expect_error(
      shinyOAuth:::state_store_consume_checked(
        client,
        "state",
        expected
      ),
      "record changed",
      class = "shinyOAuth_state_error"
    )
  }
})

test_that("callback consumption permits equivalent backend serialization", {
  client <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  expected <- list(
    browser_token = valid_browser_token(),
    pkce_code_verifier = strrep("a", 43),
    nonce = NULL
  )
  consumed <- expected[c("pkce_code_verifier", "browser_token")]
  local_mocked_bindings(
    state_store_get_remove = function(...) consumed,
    .package = "shinyOAuth"
  )
  expect_identical(
    shinyOAuth:::state_store_consume_checked(
      client,
      "state",
      expected
    ),
    consumed
  )
})
