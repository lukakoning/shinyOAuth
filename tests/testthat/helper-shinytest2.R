stop_test_app_driver <- function(drv) {
  private <- try(drv$.__enclos_env__$private, silent = TRUE)

  if (!inherits(private, "try-error") && is.environment(private)) {
    worker_id <- private$shiny_worker_id
    if (length(worker_id) != 1L) {
      private$shiny_worker_id <- NA_character_
    }
  }

  try(drv$stop(), silent = TRUE)

  if (!inherits(private, "try-error") && is.environment(private)) {
    process <- private$shiny_process
    if (
      !is.null(process) &&
        isTRUE(tryCatch(
          process$is_alive(),
          error = function(...) FALSE
        ))
    ) {
      try(process$kill(), silent = TRUE)
    }
  }

  invisible(NULL)
}
