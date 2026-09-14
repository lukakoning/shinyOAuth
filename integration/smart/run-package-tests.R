# Full package suite with its normally optional browser tests enabled.
Sys.setenv(NOT_CRAN = "true", SHINYOAUTH_BROWSER_TESTS = "true",
  R_LIBS = paste(.libPaths(), collapse = .Platform$path.sep))
results <- local({
  source("tests/testthat/helper-shinytest2.R", local = TRUE)
  local_app_driver_navigation()
  testthat::test_local(".", reporter = "summary", stop_on_failure = FALSE)
})
counts <- as.data.frame(results)
totals <- as.list(colSums(counts[c("failed", "error", "warning", "skipped", "passed")]))
skips <- counts[counts$skipped > 0, c("file", "test", "skipped")]
# This filesystem concurrency test is explicitly unsupported on Windows. All
# other skips (including a missing browser prerequisite) fail this runner.
allowed <- .Platform$OS.type == "windows" & skips$file == "test-state-store-concurrent-replay.R" &
  skips$test == "atomic $take() prevents concurrent replay across parallel workers"
passed <- totals$failed == 0 && totals$error == 0 && all(allowed)
output <- file.path("integration/smart/.artifacts", paste0("package-", format(Sys.time(), "%Y%m%d-%H%M%S")))
dir.create(output, recursive = TRUE)
jsonlite::write_json(list(status = if (passed) "passed" else "failed", browser_tests_enabled = TRUE,
  tests = totals, skips = skips, r_version = R.version.string), file.path(output, "evidence.json"),
  auto_unbox = TRUE, pretty = TRUE)
if (!passed) stop("Package/browser tests failed or unexpectedly skipped")
