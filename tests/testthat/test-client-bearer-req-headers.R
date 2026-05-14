test_that("resource_req accepts named character vector headers", {
  req <- resource_req(
    token = "tok",
    url = "https://example.com/base",
    headers = c(Accept = "application/json", `X-Test` = "1")
  )

  dry <- httr2::req_dry_run(req, quiet = TRUE, redact_headers = FALSE)
  expect_equal(dry$headers$authorization, "Bearer tok")
  expect_equal(dry$headers$accept, "application/json")
  expect_equal(dry$headers$`x-test`, "1")
})

test_that("resource_req ignores invalid headers input with warning", {
  expect_warning(
    req <- resource_req(
      token = "tok",
      url = "https://example.com/base",
      headers = c("application/json")
    ),
    regexp = "Ignoring invalid client bearer headers"
  )

  dry <- httr2::req_dry_run(req, quiet = TRUE, redact_headers = FALSE)
  expect_equal(dry$headers$authorization, "Bearer tok")
  # Accept remains at package/httr2 default since invalid input was ignored
  expect_equal(dry$headers$accept, "*/*")
  # And no extra custom header slipped through
  expect_null(dry$headers$`x-test`)
})
