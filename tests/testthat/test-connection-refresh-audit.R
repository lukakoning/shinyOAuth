test_that("module refresh failure audits preserve async classification and redaction", {
  skip_if_not_installed("mirai")
  mirai::daemons(1L)
  withr::defer(mirai::daemons(0L))
  mirai::call_mirai(mirai::mirai(NULL))
  events <- list()
  observed_error <- NULL
  local_options(
    shinyOAuth.skip_browser_token = TRUE,
    shinyOAuth.otel_logging_enabled = FALSE,
    shinyOAuth.audit_hook = function(event) {
      events[[length(events) + 1L]] <<- event
    }
  )
  local_mocked_bindings(
    refresh_token = function(..., async = FALSE) {
      if (!async) {
        observed_error <<- simpleError("private-provider-detail")
        stop(observed_error)
      }
      result <- promises::as.promise(mirai::mirai(stop(
        "private-provider-detail"
      )))
      promises::catch(result, function(error) {
        observed_error <<- error
        stop(error)
      })
    },
    revoke_token = function(...) invisible(NULL)
  )
  for (async in c(FALSE, TRUE)) {
    for (keep in c(FALSE, TRUE)) {
      events <- list()
      observed_error <- NULL
      client <- make_test_client(use_nonce = FALSE, scopes = c("read", "write"))
      shiny::testServer(
        oauth_module_server,
        args = list(
          id = "auth",
          client = client,
          auto_redirect = FALSE,
          async = async,
          indefinite_session = keep
        ),
        {
          .accept_login_token(manager_test_token(), NULL)
          current <- values[["connection"]]()
          if (async) {
            failure <- NULL
            promises::catch(current[["refresh"]](), function(error) {
              failure <<- error
            })
            poll_for_async(function() !is.null(failure), session, timeout = 30)
            expect_s3_class(failure, "shinyOAuth_access_error")
          } else {
            expect_error(
              current[["refresh"]](),
              class = "shinyOAuth_access_error"
            )
          }
          relevant <- Filter(
            function(event) {
              event[["type"]] %in%
                c(
                  "audit_session_cleared",
                  "audit_refresh_failed_but_kept_session"
                )
            },
            events
          )
          expect_length(relevant, 1L)
          event <- relevant[[1L]]
          expect_identical(
            event[["type"]],
            if (keep) {
              "audit_refresh_failed_but_kept_session"
            } else {
              "audit_session_cleared"
            }
          )
          expect_identical(
            event[["reason"]],
            if (async) "refresh_failed_async" else "refresh_failed_sync"
          )
          expect_identical(event[["kept_token"]], keep)
          expect_identical(!is.null(values[["token"]]), keep)
          expect_identical(
            event[["error_class"]],
            paste(class(observed_error), collapse = ", ")
          )
          expect_identical("mirai_error_type" %in% names(event), async)
          if (async) {
            expect_identical(
              event[["mirai_error_type"]],
              classify_mirai_error(observed_error) %||% NA_character_
            )
          }
          serialized <- jsonlite::toJSON(event, auto_unbox = TRUE)
          expect_false(grepl(
            "private-provider-detail|synthetic-access|synthetic-refresh",
            serialized
          ))
        }
      )
    }
  }
})
