testthat::test_that("Keycloak runner preserves logs before failure cleanup", {
  script_path <- testthat::test_path(
    "..",
    "..",
    "integration",
    "keycloak",
    "run-integration.sh"
  )
  testthat::skip_if_not(
    file.exists(script_path),
    "Integration runner unavailable"
  )

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

testthat::test_that("Keycloak runner bounds pull retries and preserves later failures", {
  script_path <- testthat::test_path(
    "..",
    "..",
    "integration",
    "keycloak",
    "run-integration.sh"
  )
  testthat::skip_if_not(
    file.exists(script_path),
    "Integration runner unavailable"
  )
  bash <- Sys.which("bash")
  if (.Platform[["OS.type"]] == "windows") {
    # Use Git Bash rather than the Windows launcher for WSL.
    bash <- file.path(Sys.getenv("ProgramFiles"), "Git", "bin", "bash.exe")
  }
  testthat::skip_if(!nzchar(bash) || !file.exists(bash), "Bash is required")
  fixture <- normalizePath(
    testthat::test_path("..", "keycloak-runner-fixture.sh"),
    winslash = "/"
  )
  for (scenario in list(
    c(failures = 0L, start = 0L, test = 0L),
    c(failures = 2L, start = 0L, test = 0L),
    c(failures = 3L, start = 0L, test = 0L),
    c(failures = 0L, start = 43L, test = 0L),
    c(failures = 0L, start = 0L, test = 44L)
  )) {
    root <- withr::local_tempdir()
    script_dir <- file.path(root, "integration", "keycloak")
    dir.create(script_dir, recursive = TRUE)
    runner <- file.path(script_dir, "run-integration.sh")
    # Write LF on Windows, too: these files are executed by Bash.
    writeLines(readLines(script_path, warn = FALSE), runner, useBytes = TRUE)
    writeLines(
      c("#!/usr/bin/env bash", "exit 0"),
      file.path(script_dir, "prepare-tls.sh"),
      useBytes = TRUE
    )
    log <- file.path(root, "commands.log")
    result <- processx::run(
      bash,
      c(fixture, runner, log, as.character(scenario)),
      error_on_status = FALSE,
      timeout = 10000
    )
    exhausted <- scenario[["failures"]] == 3L
    expected_status <- if (exhausted) {
      42L
    } else if (scenario[["start"]] != 0L) {
      scenario[["start"]]
    } else {
      scenario[["test"]]
    }
    testthat::expect_identical(
      result[["status"]],
      expected_status,
      info = result[["stderr"]]
    )
    attempts <- min(3L, scenario[["failures"]] + 1L)
    expected <- "docker compose pull --policy missing keycloak"
    if (attempts > 1L) {
      for (attempt in seq_len(attempts - 1L)) {
        expected <- c(
          expected,
          paste("sleep", attempt * 5L),
          "docker compose pull --policy missing keycloak"
        )
      }
    }
    if (!exhausted) {
      expected <- c(expected, "docker compose up -d --pull never")
      if (scenario[["start"]] == 0L) {
        expected <- c(expected, "Rscript integration/keycloak/run-tests.R")
      }
    }
    if (expected_status != 0L) {
      expected <- c(expected, "docker compose logs --no-color")
      testthat::expect_identical(
        readLines(file.path(script_dir, ".generated", "keycloak-compose.log")),
        "synthetic Docker logs"
      )
    }
    testthat::expect_identical(
      readLines(log),
      c(expected, "docker compose down -v")
    )
  }
})

testthat::test_that("Keycloak clients use exact local redirect registrations", {
  fixture_path <- testthat::test_path(
    "..",
    "..",
    "integration",
    "keycloak",
    "realm-shinyoauth.json"
  )
  testthat::skip_if_not(
    file.exists(fixture_path),
    "Integration fixture unavailable"
  )

  fixture <- jsonlite::read_json(fixture_path, simplifyVector = FALSE)
  redirects <- unlist(lapply(fixture[["clients"]], `[[`, "redirectUris"))
  origins <- unlist(lapply(fixture[["clients"]], `[[`, "webOrigins"))
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
