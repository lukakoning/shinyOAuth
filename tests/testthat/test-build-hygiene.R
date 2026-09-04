testthat::test_that("local virtual environments are excluded from source builds", {
  buildignore <- testthat::test_path("..", "..", ".Rbuildignore")
  testthat::skip_if_not(file.exists(buildignore), "Source build metadata unavailable")

  patterns <- readLines(buildignore, warn = FALSE)
  testthat::expect_true("^\\.venv$" %in% patterns)
})
