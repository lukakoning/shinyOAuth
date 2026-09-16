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
    surfaces <- list(
      conditionMessage(error),
      error[["context"]],
      events,
      record[["traces"]],
      record[["logs"]]
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
