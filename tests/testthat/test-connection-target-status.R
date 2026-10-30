test_that("target status reads track each token without acquiring or refreshing", {
  local_options(shinyOAuth.skip_browser_token = TRUE)
  provider <- make_test_provider()
  provider@token_target_mode <- "rfc8707"
  client <- oauth_client(
    provider, "app", "secret",
    redirect_uri = "https://app.example/callback",
    scopes = c("read", "write", "extra"),
    token_targets = list(
      primary = list(resource = "urn:primary", scopes = c("read", "write")),
      secondary = list(resource = "urn:secondary", scopes = "extra")
    ),
    token_target_default = "primary"
  )
  acquisitions <- 0L
  local_mocked_bindings(
    refresh_token_dispatch = function(...) {
      acquisitions <<- acquisitions + 1L
      token <- manager_test_token(access = "secondary-access")
      token@granted_scopes <- "extra"
      token
    },
    revoke_token = function(...) invisible(NULL)
  )
  shiny::testServer(
    oauth_module_server,
    args = list(id = "auth", client = client, auto_redirect = FALSE),
    {
      operation <- .begin_auth_operation("login", NULL, new_epoch = TRUE)
      .accept_login_token(manager_test_token(), NULL)
      .finish_auth_operation(operation, "login")
      current <- values[["connection"]]()
      expect_true(current[["is_usable"]]())
      expect_identical(current[["summary"]](), current[["summary"]]("primary"))
      expect_false(current[["is_usable"]]("secondary"))
      pending <- current[["summary"]]("secondary")
      expect_identical(pending[["status"]], "not_acquired")
      expect_identical(pending[["expires_at"]], NA_real_)
      expect_identical(acquisitions, 0L)

      expect_identical(current[["access_token"]](target = "secondary"), "secondary-access")
      expect_true(current[["is_usable"]](target = "secondary"))
      expect_identical(current[["summary"]]("secondary")[["status"]], "active")
      bundle <- values[["targets"]]
      token <- bundle[["tokens"]][["secondary"]]
      token@expires_at <- as.numeric(Sys.time()) - 1
      bundle[["tokens"]][["secondary"]] <- token
      values[["targets"]] <- bundle
      expect_false(current[["is_usable"]]("secondary"))
      expired <- current[["summary"]](target = "secondary")
      expect_identical(expired[["status"]], "expired")
      expect_identical(expired[["expires_at"]], token@expires_at)
      expect_true(current[["is_usable"]]())
      expect_identical(acquisitions, 1L)

      for (method in c("is_usable", "summary")) {
        error <- tryCatch(current[[method]]("missing"), error = identity)
        expect_identical(error[["context"]][["reason"]], "unknown_target")
      }
      values[["logout"]]()
      expect_false(current[["is_usable"]]("secondary"))
      expect_error(current[["summary"]]("secondary"), class = "shinyOAuth_access_error")
      expect_identical(acquisitions, 1L)
    }
  )
})
