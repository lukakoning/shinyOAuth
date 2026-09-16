test_that("UserInfo parse failures redact URLs across conditions, hooks and telemetry", {
  skip_if_not_installed("otelsdk")
  reset_test_otel_cache()
  withr::defer(reset_test_otel_cache())
  client <- make_test_client()
  client@provider@userinfo_url <-
    "https://example.com/private-patient?api_key=secret-marker"
  local_mocked_bindings(req_with_retry = function(req, ...) {
    httr2::response(
      url = req[["url"]],
      status_code = 200L,
      headers = list("content-type" = "application/json"),
      body = charToRaw("invalid-json")
    )
  })
  for (expose in c(FALSE, TRUE)) {
    log_file <- local_test_otel_log_file()
    events <- list()
    local_options(
      shinyOAuth.expose_error_body = expose,
      shinyOAuth.telemetry_path_scrubber = NULL,
      shinyOAuth.otel_tracing_enabled = TRUE,
      shinyOAuth.audit_hook = function(event) {
        events[[length(events) + 1L]] <<- event
      }
    )
    record <- otelsdk::with_otel_record({
      tryCatch(get_userinfo(client, "synthetic-access"), error = identity)
    })
    error <- record[["value"]]
    expect_s3_class(error, "shinyOAuth_userinfo_error")
    expect_match(
      conditionMessage(error),
      "Failed to parse userinfo response as JSON"
    )
    expect_length(
      Filter(function(e) identical(e[["status"]], "parse_error"), events),
      1L
    )
    expect_true(file.exists(log_file))
    logs <- readLines(log_file, warn = FALSE)
    expect_true(any(grepl("audit_userinfo", logs, fixed = TRUE)))
    expect_true(any(grepl("parse_error", logs, fixed = TRUE)))
    surfaces <- list(
      conditionMessage(error),
      error[["context"]],
      events,
      record[["traces"]],
      logs
    )
    expect_false(any(grepl("private-patient|secret-marker", unlist(surfaces))))
    if (expose) {
      expect_match(
        conditionMessage(error),
        "https://example.com/",
        fixed = TRUE
      )
    } else {
      expect_false(grepl("example.com", conditionMessage(error), fixed = TRUE))
    }
  }
})

test_that("UserInfo diagnostics export only validated media types", {
  skip_if_not_installed("otelsdk")
  reset_test_otel_cache()
  withr::defer(reset_test_otel_cache())
  client <- make_test_client(userinfo_signed_jwt_required = TRUE)
  client@provider@userinfo_url <- "https://example.com/userinfo"
  secret <- "https://user:review-password@example.test/patient/review-patient?token=review-token"
  headers <- c(
    paste0('text/plain; report="', secret, '"'),
    paste0("malformed ", secret),
    paste0("text/", strrep("a", 128), ";", secret)
  )
  for (signed in c(FALSE, TRUE)) {
    client@provider@userinfo_signed_jwt_required <- signed
    for (i in seq_along(headers)) {
      ct <- headers[[i]]
      expected <- if (i == 1L) "text/plain" else "<invalid>"
      local_mocked_bindings(req_with_retry = function(req, ...) {
        httr2::response(
          url = req[["url"]],
          status_code = 200L,
          headers = list("content-type" = ct),
          body = charToRaw("invalid-json")
        )
      })
      events <- list()
      log_file <- local_test_otel_log_file()
      local_options(
        shinyOAuth.expose_error_body = FALSE,
        shinyOAuth.otel_tracing_enabled = TRUE,
        shinyOAuth.audit_hook = function(event) {
          events[[length(events) + 1L]] <<- event
        }
      )
      record <- otelsdk::with_otel_record({
        tryCatch(get_userinfo(client, "synthetic-access"), error = identity)
      })
      error <- record[["value"]]
      expect_s3_class(error, "shinyOAuth_userinfo_error")
      expect_match(conditionMessage(error), expected, fixed = TRUE)
      diagnostic <- Filter(
        function(e) {
          identical(
            e[["status"]],
            if (signed) "userinfo_not_jwt" else "parse_error"
          )
        },
        events
      )
      expect_length(diagnostic, 1L)
      expect_identical(diagnostic[[1]][["content_type"]], expected)
      logs <- readLines(log_file, warn = FALSE)
      expect_true(any(grepl("audit_userinfo", logs, fixed = TRUE)))
      surfaces <- list(
        conditionMessage(error),
        error[["context"]],
        events,
        record[["traces"]],
        logs
      )
      expect_false(any(grepl(
        "review-password|review-patient|review-token",
        unlist(surfaces)
      )))
    }
  }
  expect_identical(
    otel_http_content_type(" Application/Problem+JSON; charset=UTF-8"),
    "application/problem+json"
  )
  expect_identical(
    sanitize_event_diagnostics(list(content_type = headers[[1]]))[[
      "content_type"
    ]],
    "text/plain"
  )
})
