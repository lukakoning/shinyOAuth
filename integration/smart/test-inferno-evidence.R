testthat::test_that("Inferno evidence requires every applicable upstream test exactly once", {
  for (style in c("public", "header", "private_key_jwt")) {
    expected <- inferno_expected_tests(style)
    results <- lapply(expected, function(id) list(test_id = id, result = "pass"))
    testthat::expect_true(inferno_verification_summary(results, expected)$passed)
    testthat::expect_false(inferno_verification_summary(list(), expected)$passed)
    testthat::expect_false(inferno_verification_summary(results[-1L], expected)$passed)
    testthat::expect_false(inferno_verification_summary(c(results, results[1L]), expected)$passed)
    duplicate <- results
    duplicate[[1L]] <- duplicate[[2L]]
    testthat::expect_false(inferno_verification_summary(duplicate, expected)$passed)
    unrelated <- results
    unrelated[[1L]]$test_id <- "different_test"
    testthat::expect_false(inferno_verification_summary(unrelated, expected)$passed)
    for (status in c("skip", "omit", "wait", "fail", "error", "running")) {
      unfinished <- results
      unfinished[[1L]]$result <- status
      testthat::expect_false(inferno_verification_summary(unfinished, expected)$passed)
    }
    # A passing aggregate cannot mask a failed leaf.
    testthat::expect_false(inferno_verification_summary(c(unfinished,
      list(list(test_suite_id = inferno_suite, result = "pass"))), expected)$passed)
  }
})
