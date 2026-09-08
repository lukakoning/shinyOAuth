test_that("module test snapshots contain no credentials or callback contents", {
  exported <- NULL
  export_env <- NULL
  local_mocked_bindings(
    exportTestValues = function(...) {
      exported <<- as.list(substitute(list(...)))[-1L]
      export_env <<- parent.frame()
    },
    .package = "shiny"
  )
  client <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  shiny::testServer(
    oauth_module_server,
    args = list(id = "auth", client = client, auto_redirect = FALSE),
    {
      values$token <- OAuthToken(
        access_token = "secret-access",
        refresh_token = "secret-refresh",
        id_token = "secret-id",
        expires_at = as.numeric(Sys.time()) + 3600,
        userinfo = list(email = "secret-email")
      )
      values$browser_token <- "secret-browser"
      values$pending_callback <- list(
        code = "secret-code",
        payload = "secret-state",
        state_store_values = list(nonce = "secret-nonce")
      )
      values$error <- "secret-error"
      values$error_description <- "secret-description"
      values$error_uri <- "https://example.test/secret-uri"
      snapshot <- shiny::isolate(lapply(exported, eval, envir = export_env))
      expect_true(snapshot$token_present)
      expect_true(snapshot$browser_token_present)
      expect_true(snapshot$callback_pending)
      expect_true(snapshot$error_present)
      expect_false(any(grepl("secret-", unlist(snapshot), fixed = TRUE)))
      expect_true(all(vapply(
        snapshot,
        function(x) {
          is.null(x) || is.logical(x) || is.numeric(x)
        },
        logical(1)
      )))
    }
  )
})
