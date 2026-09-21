test_that("target staleness follows primary expiry independently of secondary refresh", {
  local_options(shinyOAuth.skip_browser_token = TRUE)
  client <- make_test_client(
    use_nonce = FALSE,
    scopes = c("read", "write", "contacts")
  )
  provider <- client@provider
  provider@token_target_mode <- "rfc8707"
  S7::props(client) <- list(
    provider = provider,
    token_targets = list(
      primary = list(resource = "urn:primary", scopes = c("read", "write")),
      secondary = list(resource = "urn:secondary", scopes = "contacts")
    ),
    default_token_target = "primary"
  )
  for (async in c(FALSE, TRUE)) {
    for (indefinite in c(FALSE, TRUE)) {
      fail_refresh <- FALSE
      local_mocked_bindings(refresh_token_dispatch = function(
        oauth_client,
        token,
        async = FALSE,
        target_request,
        ...
      ) {
        if (fail_refresh) {
          stop(refresh_outcome_error(
            simpleError("fixture failure"),
            "possibly_consumed"
          ))
        }
        fresh <- OAuthToken(
          access_token = paste0(target_request[["target"]], "-fresh"),
          refresh_token = "rotated",
          token_type = "Bearer",
          expires_at = as.numeric(Sys.time()) + 3600,
          granted_scopes = target_request[["scopes"]],
          granted_scopes_verified = TRUE
        )
        if (async) promises::promise_resolve(fresh) else fresh
      })
      shiny::testServer(
        oauth_module_server,
        args = list(
          id = "auth",
          client = client,
          auto_redirect = FALSE,
          async = async,
          indefinite_session = indefinite
        ),
        {
          .accept_login_token(manager_test_token(), NULL)
          current <- values[["connection"]]()
          expired <- values[["token"]]
          expired@expires_at <- as.numeric(Sys.time()) - 1
          values[["token"]] <- expired
          session[["flushReact"]]()
          expect_true(values[["authenticated"]])
          expect_true(values[["token_stale"]])
          expect_false(current[["is_usable"]]())
          refresh <- function(target) {
            result <- tryCatch(
              current[["refresh"]](target = target),
              error = identity
            )
            if (inherits(result, "promise")) {
              settled <- NULL
              promises::then(
                result,
                function(value) settled <<- value,
                function(error) settled <<- error
              )
              poll_for_async(function() !is.null(settled), session)
              result <- settled
            }
            result
          }
          expect_true(refresh("secondary"))
          expect_true(values[["token_stale"]])
          session[["flushReact"]]()
          expect_true(values[["token_stale"]])
          expect_true(values[["authenticated"]])
          expect_identical(
            current[["targets"]]()[["secondary"]][["status"]],
            "active"
          )
          expect_true(refresh("primary"))
          expect_false(values[["token_stale"]])
          session[["flushReact"]]()
          expect_false(values[["token_stale"]])
          expect_true(current[["is_usable"]]())
          if (indefinite) {
            fail_refresh <<- TRUE
            expect_s3_class(refresh("primary"), "shinyOAuth_access_error")
            session[["flushReact"]]()
            expect_true(values[["token_stale"]])
          }
        }
      )
    }
  }
})
