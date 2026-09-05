test_that("browser errors use bounded known codes and are reported once", {
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))
  events <- list()
  local_mocked_bindings(audit_event = function(event, context = list(), ...) {
    if (identical(event, "browser_cookie_error")) {
      events[[length(events) + 1L]] <<- context
    }
  }, .package = "shinyOAuth")
  client <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  shiny::testServer(oauth_module_server,
    args = list(id = "auth", client = client, auto_redirect = FALSE), {
      session$flushReact()
      session$setInputs(shinyOAuth_cookie_error = paste0(
        "forged\r\n", strrep("secret", 10000)))
      expect_match(values$error_description, "error: unknown.", fixed = TRUE)
      expect_identical(events[[1]]$reason, "unknown")
      session$setInputs(shinyOAuth_cookie_error = "webcrypto_unavailable")
      expect_length(events, 1L)
    })
})
