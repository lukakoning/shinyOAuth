test_that("HTTP paths are omitted by default and route export is explicit", {
  local_options(shinyOAuth.telemetry_path_scrubber = NULL)
  url <- "https://user:password@example.test/users/private-name?secret=1#fragment"
  expect_identical(
    shinyOAuth:::otel_http_url_full(url),
    "https://example.test/"
  )
  req <- list(
    REQUEST_METHOD = "GET",
    PATH_INFO = "/users/private-name",
    HTTP_HOST = "example.test",
    QUERY_STRING = "secret=1"
  )
  expect_null(shinyOAuth:::build_http_summary(req)$path)
  local_options(shinyOAuth.telemetry_path_scrubber = function(path) {
    if (startsWith(path, "/users/")) "/users/:id" else NULL
  })
  expect_identical(shinyOAuth:::build_http_summary(req)$path, "/users/:id")
  expect_identical(
    shinyOAuth:::otel_http_url_full(url),
    "https://example.test/users/:id"
  )
  for (bad in list(
    function(path) stop("secret"),
    function(path) "//secret",
    function(path) "/safe?secret",
    function(path) NA_character_
  )) {
    local_options(shinyOAuth.telemetry_path_scrubber = bad)
    expect_identical(
      shinyOAuth:::otel_http_url_full(url),
      "https://example.test/"
    )
  }
})

test_that("HTTP request metadata is bounded and free of control characters", {
  for (redact in c(TRUE, FALSE)) {
    local_options(
      shinyOAuth.audit_redact_http = redact,
      shinyOAuth.telemetry_path_scrubber = identity
    )
    req <- list(
      REQUEST_METHOD = paste0("GET\r\n", strrep("x", 100)),
      PATH_INFO = paste0("/", strrep("é\u200b", 2000)),
      HTTP_HOST = paste0("host\t", strrep("x", 2000)),
      HTTP_X_FORWARDED_PROTO = paste0("https\n", strrep("x", 100))
    )
    result <- shinyOAuth:::build_http_summary(req)
    for (field in c("method", "path", "host", "scheme")) {
      limit <- switch(field, method = 32, scheme = 16, host = 255, 512)
      expect_lte(nchar(result[[field]], type = "bytes"), limit)
      expect_false(grepl("[[:cntrl:]\\p{Cf}]", result[[field]], perl = TRUE))
    }
  }
})
