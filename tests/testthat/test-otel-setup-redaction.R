test_that("setup and cache-reset warnings gate exception details", {
  messages <- character()
  local_mocked_bindings(warn_pkg = function(title, bullets, ...) {
    messages <<- c(messages, paste(c(title, bullets), collapse = " "))
  })
  for (expose in c(FALSE, TRUE)) {
    withr::local_options(shinyOAuth.expose_error_body = expose)
    error <- simpleError(paste0(
      "Authorization: Bearer SETUP-SENTINEL ",
      "https://user:URL-SECRET@example.com/export?key=QUERY-SECRET\n{detail}"
    ))
    messages <- character()
    otel_telemetry_warning("setup", error)
    warn_about_async_otel_cache_reset("failed", "reset", error)
    expect_length(messages, 2L)
    for (message in messages) {
      expect_match(message, "simpleError")
      expect_match(message, "diagnostic digest: [a-f0-9]+")
      expect_identical(grepl("SETUP-SENTINEL", message, fixed = TRUE), expose)
      expect_false(grepl("URL-SECRET|QUERY-SECRET|\n", message))
    }
  }
})
