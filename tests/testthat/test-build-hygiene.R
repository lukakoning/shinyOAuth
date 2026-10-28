testthat::test_that("local virtual environments are excluded from source builds", {
  buildignore <- testthat::test_path("..", "..", ".Rbuildignore")
  testthat::skip_if_not(
    file.exists(buildignore),
    "Source build metadata unavailable"
  )

  patterns <- readLines(buildignore, warn = FALSE)
  patterns <- patterns[nzchar(patterns) & !startsWith(patterns, "#")]
  testthat::expect_true(any(vapply(
    patterns, grepl, logical(1), x = ".venv", ignore.case = TRUE, perl = TRUE
  )))
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
