local_app_driver_navigation <- function(.env = parent.frame()) {
  pending <- new.env(parent = emptyenv())
  initialize_log <- getFromNamespace("app_init_browser_log", "shinytest2")
  evaluate <- getFromNamespace("chromote_eval", "shinytest2")

  # shinytest2 0.5.1 navigates and immediately injects its tracer. Chrome can
  # still be replacing the initial document, destroying that tracer and its
  # readiness promise. Subscribe before navigation, then wait before injection.
  testthat::local_mocked_bindings(
    app_init_browser_log = function(self, private, options) {
      initialize_log(self, private, options)
      browser <- self$get_chromote_session()
      pending[[browser$get_session_id()]] <- browser$Page$loadEventFired(
        wait_ = FALSE,
        timeout_ = private$load_timeout / 1000
      )
      invisible(NULL)
    },
    chromote_eval = function(chromote_session, js, ...) {
      id <- chromote_session$get_session_id()
      ready <- pending[[id]]
      if (!is.null(ready)) {
        pending[[id]] <- NULL
        chromote_session$wait_for(ready)
      }
      evaluate(chromote_session, js, ...)
    },
    .package = "shinytest2",
    .env = .env
  )
  invisible(NULL)
}

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
