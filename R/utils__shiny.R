# Shiny integration helpers: capture request/session context for auditing

# Environment to store fallback session context for async workers
# This allows errors thrown in async workers to include session context
.async_context_env <- new.env(parent = emptyenv())

# Internal: return current Shiny session (reactive domain) when available
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

# Public-ish: get the current Shiny request object (original form) if present
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

# Internal: get a stable per-session token/id when available
get_current_shiny_session_token <- function() {
  sess <- get_current_shiny_session()
  if (is.null(sess)) {
    return(NA_character_)
  }
  .scalar_chr(tryCatch(sess$token, error = function(...) NULL))
}

# Internal: capture Shiny session context for later use in async workers.
# Call this on the main thread (inside a reactive observer or module server)
# before spawning an async task. The returned list can be passed to
# audit_event(..., shiny_session = <captured>) so that events emitted from
# the async context include the originating Shiny session information.
# Returns NULL if no session context is available.
#
# The returned context includes is_async = TRUE to indicate that when this
# context is used in an audit event, the event is being emitted from an
# async worker rather than the main R process. It also includes the main
# process_id to help correlate events across workers.
capture_shiny_session_context <- function() {
  tok <- get_current_shiny_session_token()

  # Check if HTTP context should be included (default: TRUE)
  include_http <- !.is_test() &&
    isTRUE(getOption("shinyOAuth.audit_include_http", TRUE))
  http <- if (include_http) {
    req <- get_current_shiny_request()
    build_http_summary(req)
  } else {
    NULL
  }

  # Capture main process ID for cross-worker correlation
  main_pid <- Sys.getpid()

  # Only return a context if we have at least one useful datum
  if (!is.null(http) || !is.na(tok)) {
    list(
      token = if (!is.na(tok)) tok else NULL,
      http = http,
      is_async = TRUE, # When pre-captured context is used, we're in an async worker
      main_process_id = main_pid
    )
  } else {
    NULL
  }
}

# Internal: set a fallback session context for the current execution scope.
# This should be called at the start of async work (inside future_promise)
# so that errors thrown within the worker can still include session context.
# Returns the previous context (for restoration) or NULL if none was set.
set_async_session_context <- function(ctx) {
  old <- .async_context_env$current
  .async_context_env$current <- ctx
  invisible(old)
}

# Internal: get the current fallback session context, if any.
get_async_session_context <- function() {
  .async_context_env$current
}

# Internal: clear the fallback session context.
clear_async_session_context <- function() {
  .async_context_env$current <- NULL
  invisible(NULL)
}

# Internal: execute code with a fallback session context set.
# This is useful for wrapping async work so that errors include session info.
# Also injects the worker's process_id into the context for cross-process tracing.
with_async_session_context <- function(ctx, code) {
  # Inject the worker's process_id into the context
  if (!is.null(ctx)) {
    ctx$process_id <- Sys.getpid()
  }

  old <- set_async_session_context(ctx)
  on.exit(set_async_session_context(old), add = TRUE)
  force(code)
}

# Internal: capture ALL current options from the main process for propagation
# to async workers. Call this on the main thread before spawning a future.
# This ensures fully consistent behavior between main process and workers,
# including logging hooks, HTTP settings, and any other package options.
# Returns a named list of all option values.
capture_async_options <- function() {
  # Capture all current options
  opts <- options()
  # Also capture the originating process ID for audit event context
  opts[[".shinyOAuth.main_process_id"]] <- Sys.getpid()
  opts
}

# Internal: execute code with captured options temporarily set.
# This restores options from the main process inside an async worker.
# Returns the result of evaluating `code`.
with_async_options <- function(captured_opts, code) {
  if (is.null(captured_opts) || length(captured_opts) == 0) {
    return(force(code))
  }
  # Filter out only our internal marker
  opts_to_set <- captured_opts[
    !grepl("^\\.shinyOAuth\\.", names(captured_opts))
  ]
  if (length(opts_to_set) == 0) {
    return(force(code))
  }
  # Temporarily set options and restore on exit
  old_opts <- do.call(options, opts_to_set)
  on.exit(do.call(options, old_opts), add = TRUE)
  force(code)
}

# Internal: get the main process ID from captured async options.
# Returns NA_integer_ if not available.
get_main_process_id <- function(captured_opts) {
  if (is.null(captured_opts)) {
    return(NA_integer_)
  }
  pid <- captured_opts[[".shinyOAuth.main_process_id"]]
  if (is.null(pid)) NA_integer_ else as.integer(pid)
}

# Internal: check if currently running in an async worker (different process).
# Compares current PID against the captured main process PID.
is_async_worker <- function(captured_opts) {
  main_pid <- get_main_process_id(captured_opts)
  if (is.na(main_pid)) {
    return(NA)
  }
  Sys.getpid() != main_pid
}

# Internal: augment any event list with Shiny context when available.
# Priority order:
# 1. If event already has shiny_session, keep it (pre-captured async context)
# 2. If running inside a Shiny reactive domain, capture from there (is_async = FALSE)
# 3. If a fallback async context was set via set_async_session_context(), use it
#    (is_async = TRUE, already set in the captured context)
augment_with_shiny_context <- function(event) {
  # If a caller already provided a shiny_session list, do not override.
  # The pre-captured context will have is_async = TRUE already set.
  if (!is.null(event$shiny_session)) {
    return(event)
  }

  tok <- get_current_shiny_session_token()

  # Check if HTTP context should be included (default: TRUE)
  include_http <- !.is_test() &&
    isTRUE(getOption("shinyOAuth.audit_include_http", TRUE))
  http <- if (include_http) {
    req <- get_current_shiny_request()
    build_http_summary(req)
  } else {
    NULL
  }

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
