local_app_driver_navigation <- function(.env = parent.frame()) {
  pending <- new.env(parent = emptyenv())
  initialize_log <- getFromNamespace("app_init_browser_log", "shinytest2")
  evaluate <- getFromNamespace("chromote_eval", "shinytest2")

  # shinytest2 0.5.1 navigates and immediately injects its tracer. Chrome can
  # still be replacing the initial document, destroying that tracer and its
  # readiness promise. A load event can also belong to the initial blank page;
  # record that document and wait for the destination before injection.
  testthat::local_mocked_bindings(
    app_init_browser_log = function(self, private, options) {
      initialize_log(self, private, options)
      browser <- self$get_chromote_session()
      pending[[browser$get_session_id()]] <- list(
        frame = browser$Page$getFrameTree()$frameTree$frame,
        timeout = private$load_timeout / 1000
      )
      invisible(NULL)
    },
    chromote_eval = function(chromote_session, js, ...) {
      id <- chromote_session$get_session_id()
      ready <- pending[[id]]
      if (!is.null(ready)) {
        pending[[id]] <- NULL
        wait_for_app_driver_document(
          chromote_session,
          ready$frame,
          ready$timeout
        )
      }
      evaluate(chromote_session, js, ...)
    },
    .package = "shinytest2",
    .env = .env
  )
  invisible(NULL)
}

wait_for_app_driver_document <- function(browser, initial_frame, timeout) {
  deadline <- Sys.time() + timeout
  repeat {
    frame <- browser$Page$getFrameTree()$frameTree$frame
    if (
      !identical(frame$loaderId, initial_frame$loaderId) &&
        !identical(frame$url, initial_frame$url)
    ) {
      ready <- browser$Runtime$evaluate(
        "document.readyState === 'complete'",
        returnByValue = TRUE
      )$result$value
      current <- browser$Page$getFrameTree()$frameTree$frame
      if (isTRUE(ready) && identical(frame$loaderId, current$loaderId)) {
        return(invisible(NULL))
      }
    }
    if (Sys.time() >= deadline) {
      stop(
        "AppDriver destination document did not finish loading",
        call. = FALSE
      )
    }
    later::run_now(0.01, loop = browser$get_child_loop())
  }
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
