# This file contains the helpers that read, capture, normalize, and forward
# Shiny session context.
# Use them when login, audit, telemetry, or async worker code needs to keep a
# connection back to the originating browser session.

# 1 Shiny session context helpers -----------------------------------------

## 1.1 Read current Shiny session state -----------------------------------

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

current_audit_http_summary <- function() {
  if (!isTRUE(getOption("shinyOAuth.audit_include_http", TRUE))) {
    return(NULL)
  }

  req <- get_current_shiny_request()
  build_http_summary(req)
}

# Internal: capture the current browser/session context before leaving the main

## 1.2 Capture and normalize async session context ------------------------
# Shiny process. Used by oauth_module_server() and the async login/token flows
# so audit events emitted later in a worker still know which Shiny session they
# belong to.
#
# Input: `is_async = TRUE` when the context will be sent to a worker, FALSE
# when the event will stay on the main process.
# Output: either NULL (nothing useful to capture) or a small list containing a
# session token, redacted HTTP request summary, and process IDs for later
# correlation.
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

# Internal: normalize a captured `shiny_session` context for whichever process
# is emitting the event now. Used by telemetry and token/login methods before
# they log or audit with a borrowed async context.
#
# Input: a `shiny_session` list captured earlier, or NULL.
# Output: the same list with missing process-local fields filled in, so the
# event points at the correct main or worker process.
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

# Internal: set a fallback session context for the current execution scope.
# This should be called at the start of async work (inside a mirai)
# so that errors thrown within the worker can still include session context.
# Returns the previous context (for restoration) or NULL if none was set.
set_async_session_context <- function(ctx) {
  old <- .async_context_env$current
  .async_context_env$current <- ctx
  invisible(old)
}

# Internal: mark whether the current execution scope is an async worker.
# This is separate from the Shiny session context so direct async token APIs
# can still detect worker execution when no `shiny_session` is available.
set_async_worker_context <- function(is_worker) {
  old <- isTRUE(.async_context_env$is_worker)
  .async_context_env$is_worker <- isTRUE(is_worker)
  invisible(old)
}

# Internal: check whether the current execution scope is an async worker.
is_async_worker_context <- function() {
  isTRUE(.async_context_env$is_worker)
}

# Internal: get the current fallback session context, if any.
get_async_session_context <- function() {
  .async_context_env$current
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
  if (!is.null(ctx)) {
    try(
      otel_set_span_attributes(attributes = otel_shiny_attributes(ctx)),
      silent = TRUE
    )
  }
  force(code)
}

## 1.3 Attach and forward context -----------------------------------------

# Internal: augment any event list with Shiny context when available.
# Priority order:
# 1. If event already has shiny_session, keep it (pre-captured async context)
# 2. If running inside a Shiny reactive domain, capture from there (is_async = FALSE)
# 3. If a fallback async context was set via set_async_session_context(), use it
#    (is_async = TRUE, already set in the captured context)
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

# Internal: call a helper and forward optional context only when the target can
# accept it. This keeps async context propagation explicit in runtime code
# without breaking tests that mock helpers using older signatures.
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
