# Run from the repository root. Mark browser test files with the exact comment
# below so new browser regressions are automatically included in CI.
Sys.setenv(SHINYOAUTH_BROWSER_TESTS = "true", NOT_CRAN = "true")
browser_library <- tempfile("shinyOAuth-browser-library-")
dir.create(browser_library)
.libPaths(c(browser_library, .libPaths()))
invisible(processx::run(
  file.path(
    R.home("bin"),
    if (.Platform$OS.type == "windows") "R.exe" else "R"
  ),
  c("CMD", "INSTALL", paste0("--library=", browser_library), "."),
  echo = FALSE
))
Sys.setenv(
  R_LIBS = paste(.libPaths(), collapse = .Platform[["path.sep"]]),
  R_LIBS_USER = paste(.libPaths(), collapse = .Platform[["path.sep"]])
)
files <- list.files(
  "tests/testthat",
  pattern = "^test.*[.]R$",
  full.names = TRUE
)
selected <- Filter(
  function(file) {
    any(readLines(file, warn = FALSE) == "# shinyOAuth-browser-suite")
  },
  files
)
if (!length(selected)) {
  stop("No browser test files discovered")
}
filters <- sub("^test[-_]", "", sub("[.]R$", "", basename(selected)))
local({
  source("tests/testthat/helper-shinytest2.R", local = TRUE)
  local_app_driver_navigation()
  results <- testthat::test_local(
    filter = paste0("^(", paste(filters, collapse = "|"), ")$"),
    stop_on_failure = TRUE
  )
  if (any(as.data.frame(results)$skipped)) {
    stop(
      "Browser suite requires zero skipped tests; inspect browser/dependency setup"
    )
  }
})
