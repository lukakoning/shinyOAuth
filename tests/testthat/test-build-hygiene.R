testthat::test_that("local virtual environments are excluded from source builds", {
  buildignore <- testthat::test_path("..", "..", ".Rbuildignore")
  testthat::skip_if_not(file.exists(buildignore), "Source build metadata unavailable")

  patterns <- readLines(buildignore, warn = FALSE)
  testthat::expect_true("^\\.venv$" %in% patterns)
})

testthat::test_that("browser tests run only in Chrome-provisioned CI", {
  root <- testthat::test_path("..", "..")
  browser_tests <- file.path(root, "tests", "testthat", "test_chromote_cookie.R")
  check_workflow <- file.path(root, ".github", "workflows", "R-CMD-check.yaml")
  browser_workflow <- file.path(
    root,
    ".github",
    "workflows",
    "integration-tests.yml"
  )
  paths <- c(browser_tests, check_workflow, browser_workflow)
  testthat::skip_if_not(
    all(file.exists(paths)),
    "Source test and workflow files unavailable"
  )

  browser_test_text <- paste(readLines(browser_tests), collapse = "\n")
  check_text <- paste(readLines(check_workflow), collapse = "\n")
  browser_ci_text <- paste(readLines(browser_workflow), collapse = "\n")

  testthat::expect_match(
    browser_test_text,
    'Sys.getenv("SHINYOAUTH_BROWSER_TESTS"',
    fixed = TRUE
  )
  testthat::expect_match(
    browser_test_text,
    "chromote::ChromoteSession$new()",
    fixed = TRUE
  )
  testthat::expect_match(
    check_text,
    "SHINYOAUTH_BROWSER_TESTS: false",
    fixed = TRUE
  )
  testthat::expect_match(browser_ci_text, "setup-chrome", fixed = TRUE)
  testthat::expect_match(
    browser_ci_text,
    "SHINYOAUTH_BROWSER_TESTS: true",
    fixed = TRUE
  )
  testthat::expect_match(
    browser_ci_text,
    "test_chromote_cookie.R",
    fixed = TRUE
  )
})
