for (async in c(FALSE, TRUE)) {
  for (stage in c("deadline", "targets", "scopes")) {
    test_that(
      paste("rejected login is discarded atomically, async =", async, stage),
      {
        skip_if_not_installed("promises")
        skip_if_not_installed("later")
        withr::local_options(shinyOAuth.skip_browser_token = TRUE)
        client <- make_test_client(use_nonce = FALSE)
        client@provider@revocation_url <- "https://example.com/revoke"
        now <- as.numeric(Sys.time())
        result <- OAuthToken(
          access_token = "rejected-access",
          refresh_token = "live-refresh",
          expires_at = now + if (stage == "deadline") 1 else 3600
        )
        finish <- NULL
        revoked <- list()
        original_bundle <- token_target_bundle
        original_extra_scopes <- authorization_extra_scopes
        local_mocked_bindings(
          Sys.time = function() as.POSIXct(now, origin = "1970-01-01"),
          .package = "base"
        )
        local_mocked_bindings(
          handle_callback = function(...) {
            if (stage == "deadline") now <<- now + 2
            result
          },
          async_dispatch = function(...) {
            promises::promise(function(resolve, reject) {
              finish <<- resolve
            })
          },
          token_target_bundle = function(...) {
            if (stage == "targets") err_token("Rejected target bundle")
            original_bundle(...)
          },
          authorization_extra_scopes = function(...) {
            if (stage == "scopes") err_token("Rejected scope history")
            original_extra_scopes(...)
          },
          revoke_token = function(client, token, token_kind, async, ...) {
            revoked[[length(revoked) + 1L]] <<- list(
              token = token,
              kind = token_kind,
              async = async
            )
            if (stage == "scopes" && token_kind == "refresh") {
              stop("Revocation endpoint unavailable")
            }
            invisible(NULL)
          },
          .package = "shinyOAuth"
        )
        shiny::testServer(
          oauth_module_server,
          args = list(
            id = "auth",
            client = client,
            auto_redirect = FALSE,
            async = async,
            refresh_proactively = FALSE
          ),
          {
            state <- parse_query_param(values[["build_auth_url"]](), "state")
            fields <- c(
              "target_limits",
              "refresh_scope_narrowed",
              "last_authorized_scope_narrowed",
              "last_authorized_extra_scopes",
              "last_authorized_scopes"
            )
            before <- lapply(fields, function(field) auth_operations[[field]])
            previous_targets <- values[["targets"]]
            previous_started_at <- values[["auth_started_at"]]
            values[[".process_query"]](paste0("?code=ok&state=", state))
            if (async) {
              expect_true(is.function(finish))
              if (stage == "deadline") now <<- now + 2
              finish(result)
              poll_for_async(function() !is.null(values[["error"]]), session)
            }
            expect_null(values[["token"]])
            expect_false(is.null(values[["error"]]))
            expect_null(auth_operations[["active_login_id"]])
            expect_identical(values[["targets"]], previous_targets)
            expect_identical(values[["auth_started_at"]], previous_started_at)
            expect_identical(
              lapply(fields, function(field) auth_operations[[field]]),
              before
            )
            expect_length(revoked, 2L)
            expect_setequal(
              vapply(revoked, function(call) call[["kind"]], character(1)),
              c("refresh", "access")
            )
            for (call in revoked) {
              expect_identical(call[["token"]], result)
              expect_identical(call[["async"]], async)
            }
          }
        )
      }
    )
  }
}
