test_that("endpoint values are redacted recursively for native and OTel events", {
  url <- "https://user:password@example.test/token?code=private#private"
  expected <- "https://example.test/token"
  event <- list(
    type = "test_endpoint",
    endpoint = url,
    context = list(endpoint = url, token_endpoint = url)
  )
  safe <- sanitize_event_url_fields(event)
  expect_identical(safe[["endpoint"]], expected)
  expect_identical(safe[["context"]][["endpoint"]], expected)
  expect_identical(safe[["context"]][["token_endpoint"]], expected)
  expect_false(any(grepl(
    "private|password|user@",
    unlist(otel_event_attributes(event))
  )))
  seen <- NULL
  local_options(shinyOAuth.audit_hook = function(event) {
    seen <<- event
  })
  emit_trace_event(event)
  expect_identical(seen[["endpoint"]], expected)
  for (input in list("private?code=private", "https://[private", c(url, url))) {
    expect_null(sanitize_event_url_fields(list(endpoint = input))[["endpoint"]])
    error <- tryCatch(validate_endpoint(input, "other.test"), error = identity)
    expect_s3_class(error, "shinyOAuth_config_error")
    expect_false(grepl("private|password", conditionMessage(error)))
  }
  error <- tryCatch(validate_endpoint(url, "other.test"), error = identity)
  expect_false(grepl("private|password", conditionMessage(error)))
})
