# This file contains the helpers that read, capture, normalize, and forward
# Shiny session context.
# Use them when login, audit, telemetry, or async worker code needs to keep a
# connection back to the originating browser session.

# 1 Shiny session context helpers ----------------------------------------------

## 1.1 Read current Shiny session state ----------------------------------------

# Environment to store fallback session context for async workers
# This allows errors thrown in async workers to include session context
.async_context_env <- new.env(parent = emptyenv())

#' Get the current Shiny reactive domain
#'
#' Used by the Shiny-context helpers in this file when code may or may not be
#' running inside an active Shiny session.
#'
#' @return Current Shiny reactive domain, or `NULL` when Shiny is unavailable or
#'   no reactive domain is active.
#' @keywords internal
#' @noRd
get_current_shiny_session <- function() {
  if (!requireNamespace("shiny", quietly = TRUE)) {
    return(NULL)
  }
  dom <- tryCatch(shiny::getDefaultReactiveDomain(), error = function(...) NULL)
  if (is.null(dom)) {
    return(NULL)
  }
  dom
}

#' Get the current Shiny request object
#'
#' Used by audit and telemetry helpers that need browser request context from
#' the active Shiny session.
#'
#' @return Current request object, or `NULL` when no usable request is
#'   available.
#' @keywords internal
#' @noRd
get_current_shiny_request <- function() {
  sess <- get_current_shiny_session()
  if (is.null(sess)) {
    return(NULL)
  }
  # Accessing session$request under shiny::testServer emits warnings because
  # the Rook request is not fully simulated. We only need a best-effort read,
  # so silence those warnings to keep tests/CI noise-free.
  req <- suppressWarnings(tryCatch(sess$request, error = function(...) NULL))
  if (is.null(req)) {
    return(NULL)
  }
  req
}

#' Get the current Shiny session token
#'
#' Used when audit and async helpers need a stable per-session identifier.
#'
#' @return Session token as a scalar character string, or `NA_character_` when
#'   no token is available.
#' @keywords internal
#' @noRd
get_current_shiny_session_token <- function() {
  sess <- get_current_shiny_session()
  if (is.null(sess)) {
    return(NA_character_)
  }
  .scalar_chr(tryCatch(sess$token, error = function(...) NULL))
}

#' Capture the current HTTP summary for audit events
#'
#' Reads the active Shiny request and returns the sanitized HTTP summary used by
#' audit and telemetry helpers.
#'
#' @return Sanitized HTTP summary list, or `NULL` when HTTP capture is disabled
#'   or no request context is available.
#' @keywords internal
#' @noRd
current_audit_http_summary <- function() {
  if (!isTRUE(getOption("shinyOAuth.audit_include_http", TRUE))) {
    return(NULL)
  }

  req <- get_current_shiny_request()
  build_http_summary(req)
}

## 1.2 Capture and normalize async session context -----------------------------
#' Capture the current Shiny session context
#'
#' Captures the browser/session context before leaving the main Shiny process so
#' audit events emitted later in a worker still know which Shiny session they
#' belong to. Used before async work is handed off to workers.
#'
#' @param is_async Whether the captured context will be sent to a worker.
#' @return `NULL`, or a list containing a session token, redacted HTTP request
#'   summary, and process ids for later correlation.
#' @keywords internal
#' @noRd
capture_shiny_session_context <- function(is_async = TRUE) {
  tok <- get_current_shiny_session_token()
  http <- current_audit_http_summary()

  # Capture main process ID for cross-worker correlation
  main_pid <- Sys.getpid()

  # Only return a context if we have at least one useful datum
  if (!is.null(http) || !is.na(tok)) {
    list(
      token = if (!is.na(tok)) tok else NULL,
      http = http,
      is_async = isTRUE(is_async),
      process_id = if (!isTRUE(is_async)) main_pid else NULL,
      main_process_id = if (isTRUE(is_async)) main_pid else NULL
    )
  } else {
    NULL
  }
}

#' Normalize a captured Shiny session context
#'
#' Fills in any missing process-local fields so the context points at the
#' correct main or worker process when later reused by telemetry or audit code.
#' Used when pre-captured context is forwarded or reused.
#'
#' @param shiny_session Previously captured session context, or `NULL`.
#' @return Normalized `shiny_session` context.
#' @keywords internal
#' @noRd
normalize_shiny_session_context <- function(shiny_session) {
  if (is.null(shiny_session) || !is.list(shiny_session)) {
    return(shiny_session)
  }

  normalized <- shiny_session
  async_ctx <- get_async_session_context()

  if (!is.null(async_ctx) && is.list(async_ctx)) {
    for (nm in names(async_ctx)) {
      if (is.null(normalized[[nm]]) && !is.null(async_ctx[[nm]])) {
        normalized[[nm]] <- async_ctx[[nm]]
      }
    }
  }

  current_pid <- Sys.getpid()
  main_pid <- suppressWarnings(as.integer(
    normalized$main_process_id %||% NA_integer_
  ))
  process_pid <- suppressWarnings(as.integer(
    normalized$process_id %||% NA_integer_
  ))

  if (isTRUE(normalized$is_async)) {
    if (!is.na(process_pid)) {
      normalized$process_id <- process_pid
      return(normalized)
    }

    if (!is.na(main_pid) && identical(as.integer(current_pid), main_pid)) {
      normalized$is_async <- FALSE
      normalized$process_id <- current_pid
      return(normalized)
    }

    if (
      isTRUE(is_async_worker_context()) ||
        (!is.na(main_pid) && !identical(as.integer(current_pid), main_pid))
    ) {
      normalized$process_id <- current_pid
      return(normalized)
    }
  }

  if (!isTRUE(normalized$is_async) && is.na(process_pid)) {
    normalized$process_id <- current_pid
  }

  normalized
}

#' Set fallback Shiny session context for the current scope
#'
#' Used at the start of async work so later errors and audit events can still
#' refer back to the originating Shiny session.
#'
#' @param ctx Captured Shiny session context, or `NULL`.
#' @return Invisibly returns the previous fallback context, or `NULL` when none
#'   was set.
#' @keywords internal
#' @noRd
set_async_session_context <- function(ctx) {
  old <- .async_context_env$current
  .async_context_env$current <- ctx
  invisible(old)
}

#' Mark the current execution scope as an async worker
#'
#' Keeps worker detection separate from `shiny_session` so direct async helpers
#' can still detect worker execution when no session context is available.
#'
#' @param is_worker Whether the current scope should be treated as a worker.
#' @return Invisibly returns the previous worker flag.
#' @keywords internal
#' @noRd
set_async_worker_context <- function(is_worker) {
  old <- isTRUE(.async_context_env$is_worker)
  .async_context_env$is_worker <- isTRUE(is_worker)
  invisible(old)
}

#' Check whether the current execution scope is an async worker
#'
#' @return `TRUE` when the current execution scope has been marked as an async
#'   worker; otherwise `FALSE`.
#' @keywords internal
#' @noRd
is_async_worker_context <- function() {
  isTRUE(.async_context_env$is_worker)
}

#' Get the current fallback Shiny session context
#'
#' @return Captured fallback Shiny session context, or `NULL` when none is set.
#' @keywords internal
#' @noRd
get_async_session_context <- function() {
  .async_context_env$current
}

#' Evaluate code with fallback Shiny session context installed
#'
#' Used by async worker code so nested helpers inherit session context and OTEL
#' attributes while the wrapped code runs.
#'
#' @param ctx Captured Shiny session context.
#' @param code Code to evaluate while the context is active.
#' @return Result of `code`.
#' @keywords internal
#' @noRd
with_async_session_context <- function(ctx, code) {
  # Inject the worker's process_id into the context
  if (!is.null(ctx)) {
    ctx$process_id <- Sys.getpid()
  }

  old <- set_async_session_context(ctx)
  on.exit(set_async_session_context(old), add = TRUE)
  if (!is.null(ctx)) {
    try(
      otel_set_span_attributes(attributes = otel_shiny_attributes(ctx)),
      silent = TRUE
    )
  }
  force(code)
}

## 1.3 Attach and forward context ----------------------------------------------

#' Attach Shiny session context to an event list
#'
#' Preserves caller-supplied `shiny_session` context when present, otherwise
#' captures context from the active Shiny session or the current async fallback
#' scope.
#'
#' @param event Event list that may need a `shiny_session` entry.
#' @return `event`, optionally augmented with normalized Shiny session context.
#' @keywords internal
#' @noRd
augment_with_shiny_context <- function(event) {
  # If a caller already provided a shiny_session list, do not override.
  # Normalize it first so borrowed async contexts pick up worker-local fields,
  # or are corrected when the event is still emitted on the main process.
  if (!is.null(event$shiny_session)) {
    event$shiny_session <- normalize_shiny_session_context(event$shiny_session)
    return(event)
  }

  tok <- get_current_shiny_session_token()
  http <- current_audit_http_summary()

  # If we have reactive domain context, use it (main thread)
  if (!is.null(http) || !is.na(tok)) {
    event$shiny_session <- list(
      token = if (!is.na(tok)) tok else NULL,
      http = http,
      is_async = FALSE, # Not pre-captured, so running on main R process
      process_id = Sys.getpid()
    )
    return(event)
  }

  # Fallback: check for async context set via set_async_session_context()
  # This allows errors thrown in async workers to include session context

  async_ctx <- get_async_session_context()
  if (!is.null(async_ctx)) {
    event$shiny_session <- async_ctx
  }

  event
}

#' Call a helper with optional Shiny session forwarding
#'
#' Forwards `shiny_session` only when the target function can accept it. Used
#' by async runtime code so new context plumbing does not break tests or mocks
#' that still expose older helper signatures.
#'
#' @param fn Target function.
#' @param ... Arguments forwarded to `fn`.
#' @param shiny_session Optional Shiny session context to forward.
#' @return Result of `fn(...)`.
#' @keywords internal
#' @noRd
call_with_optional_shiny_session <- function(
  fn,
  ...,
  shiny_session = NULL
) {
  args <- list(...)
  fn_formals <- tryCatch(names(formals(fn)), error = function(...) NULL)
  has_dots <- !is.null(fn_formals) && "..." %in% fn_formals

  if (!is.null(fn_formals) && !has_dots) {
    arg_names <- names(args) %||% rep("", length(args))
    arg_names[is.na(arg_names)] <- ""
    keep <- !nzchar(arg_names) | arg_names %in% fn_formals
    args <- args[keep]
  }

  if (!is.null(fn_formals) && ("shiny_session" %in% fn_formals || has_dots)) {
    args$shiny_session <- shiny_session
  }
  do.call(fn, args)
}
