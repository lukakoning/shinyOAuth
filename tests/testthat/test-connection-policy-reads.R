test_that("repeated connection reads recheck transport policy and key-file contents", {
  local_options(shinyOAuth.skip_browser_token = TRUE)
  local_options(shinyOAuth.tls_min_version = NULL)
  for (managed in c(FALSE, TRUE)) {
    for (change in c("transport", "key")) {
      key_file <- withr::local_tempfile(fileext = ".pem")
      writeLines(openssl::write_pem(openssl::rsa_keygen(2048)), key_file)
      client <- make_test_client(use_nonce = FALSE, scopes = c("read", "write"))
      client@redirect_uri <- "https://app.example/callback"
      client@client_assertion_private_key <- key_file
      provider <- client@provider
      provider@token_target_mode <- "rfc8707"
      S7::props(client) <- list(
        provider = provider,
        token_targets = list(
          api = list(resource = "urn:api", scopes = c("read", "write"))
        ),
        default_token_target = "api"
      )
      fixture <- ordinary_manager_fixture(client)
      shiny::testServer(
        if (managed) oauth_connections_server else oauth_module_server,
        args = if (managed) {
          list(id = "health", manager = fixture[["manager"]])
        } else {
          list(
            id = "auth",
            client = client,
            auto_redirect = FALSE,
            revoke_on_session_end = FALSE
          )
        },
        session = manager_test_session(
          if (managed) manager_test_cookie(fixture) else NULL
        ),
        {
          session[["flushReact"]]()
          if (managed) {
            id <- manager_test_accept(controller, token = manager_test_token())
            current <- connection(id)
          } else {
            .accept_login_token(manager_test_token(), NULL)
            current <- values[["connection"]]()
          }
          session[["flushReact"]]()
          for (i in 1:3) {
            expect_identical(current[["access_token"]](), "synthetic-access")
            expect_true(current[["has_scopes"]]("read"))
          }
          # Neither mutation changes the client object or stored grant. A cache
          # keyed by those values would incorrectly preserve authorization.
          check_rejected <- function() {
            expect_false(current[["has_scopes"]]("read"))
            expect_error(
              current[["access_token"]](),
              "no longer available",
              class = "shinyOAuth_access_error"
            )
          }
          if (change == "transport") {
            withr::with_options(
              list(shinyOAuth.tls_min_version = "1.2"),
              check_rejected()
            )
          } else {
            writeLines(openssl::write_pem(openssl::rsa_keygen(2048)), key_file)
            check_rejected()
          }
        }
      )
    }
  }
})
