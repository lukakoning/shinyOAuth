test_that("client_bearer_req accepts named character vector headers", {
  req <- client_bearer_req(
    token = "tok",
    url = "https://example.com/base",
    headers = c(Accept = "application/json", `X-Test` = "1")
  )

  dry <- httr2::req_dry_run(req, redact_headers = FALSE)
  expect_equal(dry$headers$authorization, "Bearer tok")
  expect_equal(dry$headers$accept, "application/json")
  expect_equal(dry$headers$`x-test`, "1")
})

test_that("client_bearer_req ignores invalid headers input with warning", {
  expect_warning(
    req <- client_bearer_req(
      token = "tok",
      url = "https://example.com/base",
      headers = c("application/json")
    ),
    regexp = "Ignoring 'headers'"
  )

  dry <- httr2::req_dry_run(req, redact_headers = FALSE)
  expect_equal(dry$headers$authorization, "Bearer tok")
  # Accept remains at package/httr2 default since invalid input was ignored
  expect_equal(dry$headers$accept, "*/*")
  # And no extra custom header slipped through
  expect_null(dry$headers$`x-test`)
})
