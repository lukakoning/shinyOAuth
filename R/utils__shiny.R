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
# async worker rather than the main R process.
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

  # Only return a context if we have at least one useful datum
  if (!is.null(http) || !is.na(tok)) {
    list(
      token = if (!is.na(tok)) tok else NULL,
      http = http,
      is_async = TRUE # When pre-captured context is used, we're in an async worker
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
with_async_session_context <- function(ctx, code) {
  old <- set_async_session_context(ctx)
  on.exit(set_async_session_context(old), add = TRUE)
  force(code)
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
      is_async = FALSE # Not pre-captured, so running on main R process
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
