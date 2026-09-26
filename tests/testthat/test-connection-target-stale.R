test_that("target staleness follows primary expiry independently of secondary refresh", {
  local_options(shinyOAuth.skip_browser_token = TRUE)
  client <- make_test_client(
    use_nonce = FALSE,
    scopes = c("read", "write", "contacts", "files")
  )
  provider <- client@provider
  provider@token_target_mode <- "rfc8707"
  S7::props(client) <- list(
    provider = provider,
    token_targets = list(
      primary = list(resource = "urn:primary", scopes = c("read", "write")),
      secondary = list(resource = "urn:secondary", scopes = "contacts"),
      unacquired = list(resource = "urn:files", scopes = "files")
    ),
    default_token_target = "primary"
  )
  for (async in c(FALSE, TRUE)) {
    for (indefinite in c(FALSE, TRUE)) {
      fail_refresh <- FALSE
      dispatches <- 0L
      local_mocked_bindings(revoke_token = function(...) invisible(NULL))
      local_mocked_bindings(refresh_token_dispatch = function(
        oauth_client,
        token,
        async = FALSE,
        target_request,
        ...
      ) {
        dispatches <<- dispatches + 1L
        if (fail_refresh) {
          error <- refresh_outcome_error(
            simpleError("fixture failure"),
            "possibly_consumed"
          )
          if (async) {
            return(promises::promise_reject(error))
          }
          stop(error)
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
          settle <- function(expr) {
            result <- tryCatch(
              expr,
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
          refresh <- function(target) {
            settle(current[["refresh"]](target = target))
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
            expect_true(values[["authenticated"]])
            expect_false(is_valid_string(values[["token"]]@refresh_token))
            calls_after_failure <- dispatches
            # Indefinite sessions retain usable cached access tokens, but an
            # uncertain refresh credential must never be submitted again.
            for (target in c("primary", "secondary")) {
              expect_identical(
                current[["targets"]]()[[target]][["status"]],
                "active"
              )
              expect_identical(
                settle(current[["access_token"]](
                  target = target,
                  async = async
                )),
                paste0(target, "-fresh")
              )
              for (result in list(
                settle(current[["access_token"]](
                  target = target,
                  force_refresh = TRUE,
                  async = async
                )),
                refresh(target)
              )) {
                expect_s3_class(result, "shinyOAuth_access_error")
                expect_identical(
                  result[["context"]][["reason"]],
                  "interaction_required"
                )
              }
            }
            missing <- settle(current[["access_token"]](
              target = "unacquired",
              async = async
            ))
            expect_identical(
              missing[["context"]][["reason"]],
              "interaction_required"
            )
            primary <- values[["token"]]
            primary@expires_at <- as.numeric(Sys.time()) - 1
            values[["token"]] <- primary
            bundle <- values[["targets"]]
            bundle[["tokens"]][[
              "secondary"
            ]]@expires_at <- as.numeric(Sys.time()) - 1
            values[["targets"]] <- bundle
            for (target in c("primary", "secondary")) {
              expect_identical(
                current[["targets"]]()[[target]][["status"]],
                "expired"
              )
              expired <- settle(current[["access_token"]](
                target = target,
                async = async
              ))
              expect_identical(
                expired[["context"]][["reason"]],
                "interaction_required"
              )
            }
            expect_identical(dispatches, calls_after_failure)
            values[["logout"]]()
            expect_false(current[["has_scopes"]]("read", target = "primary"))
          }
        }
      )
    }
  }
})
