testthat::test_that("Keycloak runner preserves logs before failure cleanup", {
  script_path <- testthat::test_path(
    "..",
    "..",
    "integration",
    "keycloak",
    "run-integration.sh"
  )
  testthat::skip_if_not(file.exists(script_path), "Integration runner unavailable")

  script <- readLines(script_path, warn = FALSE)
  failure_guard <- grep('if [ "$rc" -ne 0 ]; then', script, fixed = TRUE)
  log_capture <- grep("docker compose logs --no-color >", script, fixed = TRUE)
  teardown <- grep("docker compose down -v >/dev/null", script, fixed = TRUE)

  testthat::expect_length(failure_guard, 1L)
  testthat::expect_length(log_capture, 1L)
  testthat::expect_length(teardown, 1L)
  testthat::expect_lt(failure_guard, log_capture)
  testthat::expect_lt(log_capture, teardown)
  testthat::expect_true(any(grepl(
    "keycloak-compose.log",
    script,
    fixed = TRUE
  )))
})
