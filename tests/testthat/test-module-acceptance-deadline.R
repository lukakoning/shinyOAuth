for (async in c(FALSE, TRUE)) {
  test_that(paste("login records a result that expires during delivery, async =", async), {
    skip_if_not_installed("otelsdk")
    skip_if_not_installed("promises")
    skip_if_not_installed("later")
    withr::local_options(shinyOAuth.skip_browser_token = TRUE,
                        shinyOAuth.otel_tracing_enabled = TRUE)
    reset_test_otel_cache()
    withr::defer(reset_test_otel_cache())
    withr::local_options(shinyOAuth.otel_tracing_enabled = TRUE)
    client <- make_test_client(use_nonce = FALSE)
    now <- as.numeric(Sys.time())
    result <- OAuthToken(access_token = "replacement", expires_at = now + 1)
    finish <- NULL
    local_mocked_bindings(
      Sys.time = function() as.POSIXct(now, origin = "1970-01-01"), .package = "base"
    )
    local_mocked_bindings(
      handle_callback = function(...) {
        now <<- now + 2
        result
      },
      async_dispatch = function(...) {
        promises::promise(function(resolve, reject) finish <<- resolve)
      },
      .package = "shinyOAuth"
    )
    record <- otelsdk::with_otel_record({
      shiny::testServer(oauth_module_server, args = list(
        id = "auth", client = client, auto_redirect = FALSE, async = async,
        refresh_proactively = FALSE
      ), {
        state <- parse_query_param(values$build_auth_url(), "state")
        values$.process_query(paste0("?code=ok&state=", state))
        if (async) {
          expect_true(is.function(finish))
          now <<- now + 2
          finish(result)
          for (i in seq_len(10L)) {
            later::run_now(0)
            session$flushReact()
          }
        }
        expect_null(values$token)
        expect_false(is.null(values$error))
        expect_false(values$token_stale)
        expect_null(auth_operations$active_login_id)
      })
    })
    if (async) {
      spans <- Filter(function(span) identical(span$name, "shinyOAuth.callback"), record$traces)
      expect_length(spans, 1L)
      expect_identical(spans[[1]]$status, "error")
    }
  })

  for (keep in c(FALSE, TRUE)) {
    test_that(paste("refresh delivery expiry follows failure policy, async =", async, "keep =", keep), {
      skip_if_not_installed("promises")
      skip_if_not_installed("later")
      withr::local_options(shinyOAuth.skip_browser_token = TRUE)
      client <- make_test_client(use_nonce = FALSE)
      now <- as.numeric(Sys.time())
      result <- OAuthToken(access_token = "replacement", refresh_token = "new-refresh",
                           expires_at = now + 1)
      previous <- OAuthToken(access_token = "previous", refresh_token = "old-refresh",
                             expires_at = now + 30)
      finish <- NULL
      local_mocked_bindings(
        Sys.time = function() as.POSIXct(now, origin = "1970-01-01"), .package = "base"
      )
      local_mocked_bindings(refresh_token = function(...) {
        if (async) {
          promises::promise(function(resolve, reject) finish <<- resolve)
        } else {
          now <<- now + 2
          result
        }
      }, .package = "shinyOAuth")
      shiny::testServer(oauth_module_server, args = list(
        id = "auth", client = client, auto_redirect = FALSE, async = async,
        refresh_proactively = TRUE, refresh_lead_seconds = 60,
        indefinite_session = keep
      ), {
        values$token <- previous
        session$flushReact()
        if (async) {
          expect_true(values$refresh_in_progress)
          now <<- now + 2
          finish(result)
          for (i in seq_len(10L)) {
            later::run_now(0)
            session$flushReact()
          }
        }
        expect_identical(values$error, "token_refresh_error")
        expect_identical(values$token, if (keep) previous else NULL)
        expect_identical(values$token_stale, keep)
        expect_false(values$refresh_in_progress)
        expect_identical(values$refresh_failure_count, 1L)
        expect_identical(values$refresh_success_generation, 0L)
        expect_true(is.na(values$refresh_last_success_at))
        expect_gt(values$refresh_next_attempt_at, now)
        expect_null(auth_operations$active_refresh_id)
      })
    })
  }
}
