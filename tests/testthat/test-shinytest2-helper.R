testthat::test_that("test AppDriver cleanup survives malformed worker IDs", {
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

  testthat::expect_silent(stop_test_app_driver(drv))
  testthat::expect_identical(private$shiny_worker_id, NA_character_)
  testthat::expect_false(process$alive)
})
