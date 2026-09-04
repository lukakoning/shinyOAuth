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

testthat::test_that("Keycloak clients use exact local redirect registrations", {
  fixture_path <- testthat::test_path(
    "..",
    "..",
    "integration",
    "keycloak",
    "realm-shinyoauth.json"
  )
  testthat::skip_if_not(file.exists(fixture_path), "Integration fixture unavailable")

  fixture <- jsonlite::read_json(fixture_path, simplifyVector = FALSE)
  redirects <- unlist(lapply(fixture$clients, `[[`, "redirectUris"))
  origins <- unlist(lapply(fixture$clients, `[[`, "webOrigins"))
  allowed_redirects <- c(
    "http://localhost:3000",
    "http://localhost:3000/callback",
    "http://127.0.0.1:3000",
    "http://127.0.0.1:3000/callback",
    "http://localhost:8100",
    "http://localhost:8100/callback",
    "http://127.0.0.1:8100",
    "http://127.0.0.1:8100/callback"
  )
  allowed_origins <- c(
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:8100",
    "http://127.0.0.1:8100"
  )

  testthat::expect_true(length(redirects) > 0L)
  testthat::expect_true(all(redirects %in% allowed_redirects))
  testthat::expect_false(any(grepl("*", redirects, fixed = TRUE)))
  testthat::expect_true(length(origins) > 0L)
  testthat::expect_true(all(origins %in% allowed_origins))
  testthat::expect_false(any(origins == "+"))
})
