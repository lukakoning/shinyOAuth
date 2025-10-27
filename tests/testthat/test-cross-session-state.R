test_that("state from user A cannot be reused by user B (cross-session)", {
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))

  # Two separate clients (distinct state stores) but same provider/client config
  cliA <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  cliB <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)

  # User A prepares login (produces encrypted state and stores associated values in A's store)
  tokA <- valid_browser_token()
  urlA <- shinyOAuth:::prepare_call(cliA, browser_token = tokA)
  encA <- parse_query_param(urlA, "state")

  # Attacker tries to reuse A's state with B's session/browser token -> must fail
  tokB <- valid_browser_token() # different token than A
  expect_error(
    shinyOAuth:::handle_callback(
      cliB,
      code = "any",
      payload = encA,
      browser_token = tokB
    ),
    class = "shinyOAuth_state_error",
    regexp = "State access failed|state|Browser token"
  )
})
