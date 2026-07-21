if (!exists("keycloak_skip_or_fail", mode = "function")) {
  source(file.path(dirname(sys.frame(1)$ofile %||% "."), "helper-keycloak.R"))
}

testthat::test_that("strict integration mode turns infrastructure skips into failures", {
  withr::local_envvar(c(SHINYOAUTH_INT_STRICT = "1"))

  condition <- tryCatch(
    keycloak_skip_or_fail("broken infrastructure"),
    condition = function(cnd) cnd
  )

  testthat::expect_s3_class(condition, "expectation_failure")
})

testthat::test_that("non-strict integration mode retains developer-friendly skips", {
  withr::local_envvar(c(SHINYOAUTH_INT_STRICT = NA))

  condition <- tryCatch(
    keycloak_skip_or_fail("optional infrastructure"),
    condition = function(cnd) cnd
  )

  testthat::expect_s3_class(condition, "skip")
})

testthat::test_that("occupied browser ports are never skipped", {
  test_dir <- dirname(sys.frame(1)$ofile %||% ".")
  test_files <- list.files(
    test_dir,
    pattern = "\\.[Rr]$",
    full.names = TRUE
  )
  test_files <- test_files[
    basename(test_files) != "test_integration_helper_strict_mode.R"
  ]
  contents <- vapply(
    test_files,
    function(path) paste(readLines(path, warn = FALSE), collapse = "\n"),
    character(1)
  )
  port_skip_pattern <- paste0(
    "testthat::skip(?:_if)?\\s*\\(",
    "(?:(?!testthat::(?:skip|fail))[\\s\\S]){0,300}",
    "already in use"
  )
  offenders <- names(contents)[vapply(
    contents,
    grepl,
    logical(1),
    pattern = port_skip_pattern,
    perl = TRUE
  )]

  testthat::expect_true(
    length(offenders) == 0L,
    info = paste(
      "Occupied ports must fail tests, not skip them:",
      paste(basename(offenders), collapse = ", ")
    )
  )
})

testthat::test_that("AppDriver cleanup survives malformed worker IDs", {
  private <- new.env(parent = emptyenv())
  private$shiny_worker_id <- character()

  process <- new.env(parent = emptyenv())
  process$alive <- TRUE
  process$is_alive <- function() process$alive
  process$kill <- function() process$alive <- FALSE
  private$shiny_process <- process

  enclosing <- new.env(parent = emptyenv())
  enclosing$private <- private
  drv <- new.env(parent = emptyenv())
  drv$.__enclos_env__ <- enclosing
  drv$stop <- function() stop("simulated shinytest2 logging failure")

  testthat::expect_silent(keycloak_stop_app_driver(drv))
  testthat::expect_identical(private$shiny_worker_id, NA_character_)
  testthat::expect_false(process$alive)
})
