testthat::test_that("expired token marks token_stale in indefinite_session", {
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))

  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)

  shiny::testServer(
    app = oauth_module_server,
    args = list(
      id = "auth",
      client = cli,
      auto_redirect = FALSE,
      indefinite_session = TRUE,
      refresh_check_interval = 100
    ),
    expr = {
      # Seed an already expired token
      t <- OAuthToken(
        access_token = "x",
        refresh_token = NA_character_,
        expires_at = as.numeric(Sys.time()) - 5,
        id_token = NA_character_
      )
      values$token <- t
      session$flushReact()
      # In indefinite_session mode we keep token but mark stale
      testthat::expect_true(isTRUE(values$authenticated))
      testthat::expect_true(
        is.logical(values$token_stale) && isTRUE(values$token_stale)
      )

      # A fresh successful login should reset the flag
      values$token <- OAuthToken(
        access_token = "fresh",
        refresh_token = NA_character_,
        expires_at = as.numeric(Sys.time()) + 3600,
        id_token = NA_character_
      )
      session$flushReact()
      testthat::expect_false(isTRUE(values$token_stale))
    }
  )
})
