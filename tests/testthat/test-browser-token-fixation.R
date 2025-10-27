testthat::test_that("pre-set browser token works only for that session (fixation bound)", {
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))

  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  tok_fixed <- valid_browser_token()

  # Prepare call using a caller-supplied browser token (pre-set cookie scenario)
  url <- shinyOAuth:::prepare_call(cli, browser_token = tok_fixed)
  enc <- parse_query_param(url, "state")

  # Successful callback with same token (stub network)
  t1 <- testthat::with_mocked_bindings(
    swap_code_for_token_set = function(client, code, code_verifier) {
      list(access_token = "at", expires_in = 60)
    },
    .package = "shinyOAuth",
    shinyOAuth:::handle_callback(
      cli,
      code = "ok",
      payload = enc,
      browser_token = tok_fixed
    )
  )
  testthat::expect_s3_class(t1, "S7_object")
  testthat::expect_true(
    is.character(t1@access_token) && nzchar(t1@access_token)
  )

  # The same state cannot be reused and a different token must fail
  # (simulate attacker changing cookie after login)
  tok_other <- paste0("ff", substring(tok_fixed, 3))
  testthat::expect_error(
    shinyOAuth:::handle_callback(
      cli,
      code = "ok2",
      payload = enc,
      browser_token = tok_other
    ),
    class = "shinyOAuth_state_error"
  )
})
