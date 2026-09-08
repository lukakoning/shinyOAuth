test_that("per-call redirect policy takes precedence over global and input policy", {
  local_mocked_bindings(req_with_retry = function(req, ...) req)
  for (global in c(FALSE, TRUE)) {
    withr::local_options(shinyOAuth.allow_redirect = global)
    for (call_policy in list(NULL, FALSE, TRUE)) {
      expected <- if (is.null(call_policy)) global else call_policy
      req <- resource_req(
        "fixture",
        "https://example.com/data",
        follow_redirect = call_policy
      )
      expect_identical(req$options$followlocation, expected)
      for (input_policy in c(FALSE, TRUE)) {
        input <- httr2::request("https://example.com/data") |>
          httr2::req_options(followlocation = input_policy)
        result <- perform_resource_req(
          "fixture",
          input,
          follow_redirect = call_policy
        )
        expect_identical(result$options$followlocation, expected)
      }
    }
    expect_false(
      resource_req("fixture", "https://example.com")$options$followlocation
    )
  }
  for (bad in list(NA, c(TRUE, FALSE), "FALSE", 1)) {
    expect_error(
      resource_req("fixture", "https://example.com", follow_redirect = bad),
      "follow_redirect must"
    )
  }
})
