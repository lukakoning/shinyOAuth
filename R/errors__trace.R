# This file contains the helpers that create, carry, and restore trace ids for
# errors and audit events.
# Use them when one failure or event needs a stable id that can be reused across
# nested helpers, warnings, logs, and rethrown conditions.

# 1 Trace context --------------------------------------------------------------

.trace_context_env <- new.env(parent = emptyenv())

#' Read the current trace id
#'
#' Returns the trace id currently stored in the process-local trace context, if
#' one has been set. Used by error, audit, and telemetry helpers.
#'
#' @return A length-1 character trace id, or `NULL` when no trace id is active.
#' @keywords internal
#' @noRd
get_current_trace_id <- function() {
  trace_id <- .trace_context_env$current %||% NULL
  if (is_valid_string(trace_id)) {
    return(as.character(trace_id)[[1]])
  }
  NULL
}

#' Resolve a trace id
#'
#' Uses a caller-supplied trace id when valid, otherwise falls back to the
#' current trace context or generates a fresh trace id. Used whenever errors or
#' audit events need a guaranteed correlation id.
#'
#' @param trace_id Optional trace id supplied by the caller.
#' @return A length-1 character trace id.
#' @keywords internal
#' @noRd
resolve_trace_id <- function(trace_id = NULL) {
  trace_id <- trace_id %||% get_current_trace_id()
  if (is_valid_string(trace_id)) {
    return(as.character(trace_id)[[1]])
  }
  gen_trace_id()
}

#' Evaluate code with one active trace id
#'
#' Temporarily installs one trace id in the process-local context so nested
#' helpers, warnings, and error paths all share the same correlation id.
#' Used around work that should share one trace id.
#'
#' @param trace_id Optional trace id to activate for the duration of `code`.
#' @param code Expression or value to force while the trace id is active.
#' @return The result of `code`.
#' @keywords internal
#' @noRd
with_trace_id <- function(trace_id = NULL, code) {
  trace_id <- resolve_trace_id(trace_id)
  old <- .trace_context_env$current %||% NULL
  .trace_context_env$current <- trace_id
  on.exit(
    {
      .trace_context_env$current <- old
    },
    add = TRUE
  )
  force(code)
}

#' Rethrow a condition with added context
#'
#' Re-aborts a caught condition while preserving any existing trace id and
#' forwarding additional arguments to [rlang::abort()]. Used by higher-level
#' error wrappers.
#'
#' @param e Condition object to rethrow.
#' @param class Optional condition class or class vector to add to the rethrown
#'   error.
#' @param ... Additional arguments forwarded to [rlang::abort()].
#' @return No return value. This function always aborts.
#' @keywords internal
#' @noRd
rethrow_with_context <- function(e, class = NULL, ...) {
  extra <- list(...)
  trace_id <- tryCatch(e[["trace_id", exact = TRUE]], error = function(...) {
    NULL
  })
  message <- extra$message %||% conditionMessage(e)
  extra$message <- NULL

  args <- c(
    list(
      message = message,
      parent = e
    ),
    extra
  )
  if (!is.null(class)) {
    args$class <- class
  }
  if (is_valid_string(trace_id)) {
    args$trace_id <- trace_id
  }

  do.call(rlang::abort, args)
}

#' Generate a trace id
#'
#' Creates a short trace id suitable for correlating logs, audit events, and
#' conditions. Used as the fallback when no trace id is already active.
#'
#' @return A length-1 character trace id.
#' @keywords internal
#' @noRd
gen_trace_id <- function() {
  tryCatch(random_urlsafe(12), error = function(e) {
    # Fallback if crypto fails
    paste0(as.integer(runif(3, 0, 1e6)), collapse = "-")
  })
}
