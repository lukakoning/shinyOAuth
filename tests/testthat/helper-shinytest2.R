local_app_driver_navigation <- function(.env = parent.frame()) {
  pending <- new.env(parent = emptyenv())
  initialize_log <- getFromNamespace("app_init_browser_log", "shinytest2")
  evaluate <- getFromNamespace("chromote_eval", "shinytest2")
  abort <- getFromNamespace("app_abort", "shinytest2")

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
        timeout = private$load_timeout / 1000,
        log = self$log_message
      )
      invisible(NULL)
    },
    chromote_eval = function(chromote_session, js, ...) {
      id <- chromote_session$get_session_id()
      ready <- pending[[id]]
      if (!is.null(ready)) {
        pending[[id]] <- NULL
        if (is.function(ready$log)) {
          ready$log("Waiting for AppDriver destination document")
        }
        wait_for_app_driver_document(
          chromote_session,
          ready$frame,
          ready$timeout
        )
        if (is.function(ready$log)) {
          ready$log("AppDriver destination document loaded")
        }
      }
      evaluate(chromote_session, js, ...)
    },
    app_abort = function(self, private, message, ...) {
      # shinytest2 discards the CDP exception when its idle check fails. Keep
      # that diagnostic in the test failure instead of reporting only a timeout.
      if (
        identical(
          message,
          "An error occurred while waiting for Shiny to be stable"
        )
      ) {
        result <- get0("ret", envir = parent.frame(), inherits = FALSE)
        detail <- result$exceptionDetails$exception$description
        if (is.null(detail)) {
          detail <- result$result$description
        }
        if (is.character(detail) && length(detail) == 1L) {
          message <- c(message, detail)
        }
      }
      abort(self, private, message, ...)
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
      document <- browser$Runtime$evaluate(
        paste0(
          "({ready: document.readyState === 'complete', ",
          "url: document.URL, href: window.location.href})"
        ),
        returnByValue = TRUE
      )$result$value
      current <- browser$Page$getFrameTree()$frameTree$frame
      # Page.getFrameTree can report the new loader while Runtime.evaluate
      # still targets the old document. Its readyState is already complete.
      # Check the evaluated document itself before accepting frame readiness.
      url <- paste0(current$url, current$urlFragment)
      if (
        isTRUE(document$ready) &&
          identical(document$url, url) &&
          identical(document$href, url) &&
          identical(frame$loaderId, current$loaderId)
      ) {
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
