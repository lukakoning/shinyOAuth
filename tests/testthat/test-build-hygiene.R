testthat::test_that("local virtual environments are excluded from source builds", {
  buildignore <- testthat::test_path("..", "..", ".Rbuildignore")
  testthat::skip_if_not(
    file.exists(buildignore),
    "Source build metadata unavailable"
  )

  patterns <- readLines(buildignore, warn = FALSE)
  testthat::expect_true("^\\.venv$" %in% patterns)
})

testthat::test_that("browser tests run only in Chrome-provisioned CI", {
  root <- testthat::test_path("..", "..")
  browser_tests <- file.path(
    root,
    "tests",
    "testthat",
    "test_chromote_cookie.R"
  )
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
    "Rscript tests/run-browser-tests.R",
    fixed = TRUE
  )
  testthat::expect_match(
    paste(
      readLines(testthat::test_path("..", "run-browser-tests.R")),
      collapse = "\n"
    ),
    "stop_on_failure = TRUE",
    fixed = TRUE
  )
})

testthat::test_that("integration tests require a fresh successful install", {
  runner <- testthat::test_path(
    "..",
    "..",
    "integration",
    "keycloak",
    "run-tests.R"
  )
  testthat::skip_if_not(
    file.exists(runner),
    "Integration runner unavailable in installed package tests"
  )
  runner_text <- paste(readLines(runner, warn = FALSE), collapse = "\n")

  testthat::expect_match(runner_text, "processx::run(", fixed = TRUE)
  testthat::expect_match(runner_text, '"CMD",', fixed = TRUE)
  testthat::expect_match(runner_text, '"INSTALL",', fixed = TRUE)
  testthat::expect_match(runner_text, "error_on_status = FALSE", fixed = TRUE)
  testthat::expect_match(
    runner_text,
    "if (!identical(install_result$status, 0L))",
    fixed = TRUE
  )
  testthat::expect_match(
    runner_text,
    "integration_library <- tempfile(",
    fixed = TRUE
  )
  testthat::expect_match(
    runner_text,
    'find.package("shinyOAuth")',
    fixed = TRUE
  )
  testthat::expect_match(
    runner_text,
    "R_LIBS = integration_library_path",
    fixed = TRUE
  )
})

testthat::test_that("local Keycloak ports are bound only to loopback", {
  compose_file <- testthat::test_path(
    "..",
    "..",
    "integration",
    "keycloak",
    "docker-compose.yml"
  )
  testthat::skip_if_not(
    file.exists(compose_file),
    "Integration compose file unavailable in installed package tests"
  )
  compose_text <- paste(readLines(compose_file, warn = FALSE), collapse = "\n")

  testthat::expect_match(compose_text, '"127.0.0.1:8080:8080"', fixed = TRUE)
  testthat::expect_match(compose_text, '"127.0.0.1:8443:8443"', fixed = TRUE)
  testthat::expect_false(grepl('"8080:8080"', compose_text, fixed = TRUE))
  testthat::expect_false(grepl('"8443:8443"', compose_text, fixed = TRUE))
})
