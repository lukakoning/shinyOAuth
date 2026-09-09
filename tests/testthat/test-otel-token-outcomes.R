test_that("normalized token outcomes classify sync and async operation spans", {
  skip_if_not_installed("otelsdk")
  skip_if_not_installed("future")
  skip_if_not_installed("promises")
  reset_test_otel_cache()
  withr::defer(reset_test_otel_cache())
  local_options(shinyOAuth.otel_tracing_enabled = TRUE)
  # Execute the real captured worker expression in-process so the SDK recorder
  # observes both worker and parent spans; completion still uses real promises.
  local_mocked_bindings(
    future_promise = function(expr, envir, ...) {
      worker <- eval(call("function", pairlist(), expr), envir)
      promises::promise_resolve(worker())
    },
    .package = "promises"
  )
  http_status <- 200L
  body <- '{"active":true}'
  local_mocked_bindings(
    mirai_daemons_active = function() FALSE,
    # Keep the in-process SDK recorder instead of recreating providers from
    # exporter environment variables intended for a separate worker process.
    capture_async_otel_envvars = function() NULL,
    req_with_retry = function(req, ...) {
      httr2::response(
        url = req$url,
        status = http_status,
        headers = list("content-type" = "application/json"),
        body = charToRaw(body)
      )
    },
    .package = "shinyOAuth"
  )
  await_result <- function(value, async) {
    if (!async) {
      return(value)
    }
    done <- FALSE
    result <- NULL
    promises::then(
      value,
      function(x) {
        result <<- x
        done <<- TRUE
      },
      function(e) {
        result <<- e
        done <<- TRUE
      }
    )
    deadline <- Sys.time() + 5
    while (!done && Sys.time() < deadline) {
      later::run_now(0.01)
    }
    expect_true(done)
    expect_false(inherits(result, "error"))
    result
  }
  for (operation in c("revoke", "introspect")) {
    cases <- c(
      "http_failure",
      "redirect",
      "success",
      "missing_token",
      "unsupported"
    )
    if (operation == "introspect") {
      cases <- c(
        cases,
        "inactive",
        "invalid_json",
        "missing_active",
        "invalid_active"
      )
    }
    for (async in c(FALSE, TRUE)) {
      for (case in cases) {
        cli <- make_test_client(use_nonce = FALSE)
        cli@provider@revocation_url <- "https://example.com/revoke"
        cli@provider@introspection_url <- "https://example.com/introspect"
        if (case == "unsupported") {
          cli@provider@revocation_url <- NA_character_
          cli@provider@introspection_url <- NA_character_
        }
        token <- OAuthToken(access_token = "sample-access")
        which <- if (case == "missing_token") "refresh" else "access"
        http_status <- switch(case, http_failure = 500L, redirect = 302L, 200L)
        body <- switch(
          case,
          inactive = '{"active":false}',
          invalid_json = 'invalid',
          missing_active = '{}',
          invalid_active = '{"active":"invalid"}',
          '{"active":true}'
        )
        fn <- if (operation == "revoke") revoke_token else introspect_token
        record <- otelsdk::with_otel_record({
          await_result(fn(cli, token, which = which, async = async), async)
        })
        neutral <- case %in% c("missing_token", "unsupported")
        expected <- if (neutral) {
          "unset"
        } else if (case %in% c("success", "inactive")) {
          "ok"
        } else {
          "error"
        }
        parents <- Filter(
          function(span) {
            span$name == paste0("shinyOAuth.token.", operation)
          },
          record$traces
        )
        expect_true(length(parents) > 0L)
        for (span in parents) {
          expect_identical(
            span$status,
            expected,
            info = paste(operation, case, async)
          )
          expect_identical(
            span$attributes[["oauth.status"]],
            record$value$status
          )
        }
        if (!neutral) {
          children <- Filter(
            function(span) grepl("[.]http$", span$name),
            record$traces
          )
          expect_true(length(children) > 0L)
          expect_identical(
            children[[1]]$status,
            if (http_status >= 400L) "error" else "unset"
          )
        }
        workers <- Filter(
          function(span) grepl("[.]worker$", span$name),
          record$traces
        )
        if (async) {
          expect_length(workers, 1L)
          expect_identical(workers[[1]]$status, expected)
        }
      }
    }
  }
})
