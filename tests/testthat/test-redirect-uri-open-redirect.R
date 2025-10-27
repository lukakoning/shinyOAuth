test_that("handle_callback rejects tampered redirect_uri in state payload", {
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))

  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  tok <- valid_browser_token()
  url <- shinyOAuth:::prepare_call(cli, browser_token = tok)
  enc <- parse_query_param(url, "state")

  # Decrypt, tamper redirect_uri, and re-encrypt with the same key (simulating an on-path attacker with state token)
  p <- shinyOAuth:::state_decrypt_gcm(enc, key = cli@state_key)
  p$redirect_uri <- "http://attacker.example.com/callback"
  tampered <- shinyOAuth:::state_encrypt_gcm(p, key = cli@state_key)

  # Token swap is not reached due to early binding failure; mock to be safe
  expect_error(
    testthat::with_mocked_bindings(
      swap_code_for_token_set = function(client, code, code_verifier) {
        list(access_token = "t", expires_in = 60)
      },
      .package = "shinyOAuth",
      shinyOAuth:::handle_callback(
        cli,
        code = "c",
        payload = tampered,
        browser_token = tok
      )
    ),
    class = "shinyOAuth_state_error",
    regexp = "redirect_uri mismatch|redirect_uri"
  )
})
