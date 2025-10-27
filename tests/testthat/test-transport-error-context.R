test_that("req_with_retry transport error includes method and url context", {
  req <- httr2::request("https://nonexistent.invalid/path")
  req <- httr2::req_method(req, "POST")
  withr::local_options(list(
    shinyOAuth.retry_max_tries = 1L, # fail fast
    shinyOAuth.retry_backoff_base = 0.01,
    shinyOAuth.retry_backoff_cap = 0.01
  ))

  # Mock req_perform to avoid real network and force transport error
  testthat::local_mocked_bindings(
    req_perform = function(request) {
      stop("forced transport fail")
    },
    .package = "httr2"
  )

  err <- tryCatch(shinyOAuth:::req_with_retry(req), error = identity)
  expect_s3_class(err, "rlang_error")
  expect_true(inherits(err, "shinyOAuth_transport_error"))
  # Context should include method and url
  ctx <- err$context
  expect_true(is.list(ctx))
  expect_identical(ctx$method, "POST")
  expect_match(ctx$url, "nonexistent\\.invalid/path")
})
