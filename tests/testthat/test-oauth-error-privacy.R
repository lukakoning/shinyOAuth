test_that("unknown endpoint error codes obey diagnostic exposure on every sink", {
  skip_if_not_installed("otelsdk")
  reset_test_otel_cache()
  withr::defer(reset_test_otel_cache())
  client <- make_test_client()
  raw_error <- "invalid_grant refresh_token=PRIVATE_REFRESH_TOKEN_SENTINEL"
  local_mocked_bindings(req_with_dpop_retry = function(req, ...) {
    httr2::response(
      url = req[["url"]],
      status_code = 400L,
      headers = list(`content-type` = "application/json"),
      body = charToRaw(jsonlite::toJSON(
        list(error = raw_error),
        auto_unbox = TRUE
      ))
    )
  })
  for (expose in c(FALSE, TRUE)) {
    for (operation in c("exchange", "refresh")) {
      events <- list()
      local_options(
        shinyOAuth.expose_error_body = expose,
        shinyOAuth.otel_tracing_enabled = TRUE,
        shinyOAuth.audit_digest_key = strrep("k", 32),
        shinyOAuth.audit_hook = function(event) {
          events[[length(events) + 1L]] <<- event
        }
      )
      log_file <- local_test_otel_log_file()
      browser <- valid_browser_token()
      state <- parse_query_param(prepare_call(client, browser), "state")
      record <- otelsdk::with_otel_record(tryCatch(
        if (operation == "exchange") {
          handle_callback(client, "code", state, browser_token = browser)
        } else {
          refresh_token(
            client,
            OAuthToken(
              access_token = "synthetic-access",
              refresh_token = "synthetic-refresh"
            )
          )
        },
        error = identity
      ))
      error <- record[["value"]]
      http_error <- error[["parent"]] %||% error
      expect_s3_class(http_error, "shinyOAuth_http_error")
      expect_identical(http_error[["oauth_error"]], "unknown")
      expect_identical(
        http_error[["oauth_error_digest"]],
        string_digest(raw_error)
      )
      http_events <- Filter(
        function(event) identical(event[["type"]], "http_error"),
        events
      )
      expect_length(http_events, 1L)
      expect_identical(http_events[[1]][["oauth_error"]], "unknown")
      expect_identical(
        http_events[[1]][["oauth_error_digest"]],
        string_digest(raw_error)
      )
      logs <- readLines(log_file, warn = FALSE)
      expect_true(any(grepl("http_error", logs, fixed = TRUE)))
      expect_true(any(grepl(string_digest(raw_error), logs, fixed = TRUE)))
      for (surface in list(
        conditionMessage(error),
        http_error[["oauth_error_detail"]],
        events,
        record[["traces"]],
        logs
      )) {
        expect_identical(
          any(grepl(
            "PRIVATE_REFRESH_TOKEN_SENTINEL",
            unlist(surface),
            fixed = TRUE
          )),
          expose
        )
      }
    }
  }
})

test_that("direct event sanitization classifies extension errors and bounds opt-in detail", {
  for (expose in c(FALSE, TRUE)) {
    local_options(shinyOAuth.expose_error_body = expose)
    raw_error <- paste0("private-marker ", strrep("x", 1000))
    event <- sanitize_event_diagnostics(list(oauth_error = raw_error))
    expect_identical(event[["oauth_error"]], "unknown")
    expect_identical(event[["oauth_error_digest"]], string_digest(raw_error))
    if (expose) {
      expect_lte(nchar(event[["oauth_error_detail"]], type = "bytes"), 512L)
    } else {
      expect_null(event[["oauth_error_detail"]])
    }
    expect_identical(sanitize_event_diagnostics(event), event)
  }
  for (code in c(
    "invalid_grant",
    "invalid_client",
    "use_dpop_nonce",
    "invalid_target"
  )) {
    expect_identical(oauth_error_code(code), code)
  }
})
