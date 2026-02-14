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
# This should be called at the start of async work (inside a mirai)
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

# Internal: capture shinyOAuth-specific options from the main process for
# propagation to async workers. Call this on the main thread before spawning
# a mirai or future. Only captures options starting with "shinyOAuth." to:
# 1. Reduce serialization overhead
# 2. Avoid serializing closures that may reference other package namespaces
#    (which can cause R serialization warnings)
# 3. Focus on package-specific behavior (audit hooks, HTTP settings, etc.)
# Returns a named list of shinyOAuth option values.
capture_async_options <- function() {
  all_opts <- options()
  # Filter to only shinyOAuth.* options
  shinyoauth_names <- grep("^shinyOAuth\\.", names(all_opts), value = TRUE)
  opts <- all_opts[shinyoauth_names]
  # Also capture the originating process ID for audit event context
  opts[[".shinyOAuth.main_process_id"]] <- Sys.getpid()
  opts
}

# Internal: execute code with captured shinyOAuth options temporarily set.
# This restores package options from the main process inside an async worker.
# Returns the result of evaluating `code`.
with_async_options <- function(captured_opts, code) {
  if (is.null(captured_opts) || length(captured_opts) == 0) {
    return(force(code))
  }
  # Filter out internal markers (start with ".")
  opts_to_set <- captured_opts[
    !startsWith(names(captured_opts), ".")
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

# Internal: dispatch an async task using the best available backend.
# Internal: check whether mirai daemons are currently active.
#
# Uses `mirai::daemons_set()` (available since mirai >= 2.3.0) as the canonical
# lightweight check. Falls back to `mirai::info()` for older mirai versions
# that lack `daemons_set()` — `info()` returns NULL when no daemons are set.
#
# @return TRUE if mirai daemons are active, FALSE otherwise.
mirai_daemons_active <- function() {
  tryCatch(
    mirai::daemons_set(),
    error = function(...) {
      # Fallback for mirai < 2.3.0: daemons_set() doesn't exist.
      # info() returns NULL when no daemons are configured.
      tryCatch(
        !is.null(mirai::info()),
        error = function(...) FALSE
      )
    }
  )
}

# Internal: get the number of mirai daemon connections.
#
# Uses `mirai::info()$connections` (the author-recommended stable interface
# instead of `mirai::status()`).
#
# @return Integer count of connections, or 0L on error.
mirai_connection_count <- function() {
  tryCatch(
    as.integer(mirai::info()$connections),
    error = function(...) 0L
  )
}

# Prefers mirai if daemons are configured, falls back to future_promise.
# Returns a promise in either case.
#
# Warnings emitted by the worker expression are captured and bundled with the
# result in a wrapper list (`$.shinyOAuth_async_wrapped`). Callers should pass
# the resolved value through `replay_async_warnings()` to re-emit the warnings
# in the main process and unwrap the actual result.
#
# @param expr A quoted expression to evaluate (use quote() or substitute())
# @param args A named list of values to pass to the expression
# @param .timeout Optional integer timeout in milliseconds for the mirai task.
#   When using mirai with dispatcher (the default), timed-out tasks are
#   automatically cancelled. Falls back to `getOption("shinyOAuth.async_timeout")`
#   when NULL (default = no timeout).
# @return A promise that resolves to a wrapped result (use `replay_async_warnings()`)
async_dispatch <- function(expr, args, .timeout = NULL) {
  .timeout <- .timeout %||% getOption("shinyOAuth.async_timeout")

  # Wrap the expression to capture warnings emitted in the worker process.
  # Warnings are collected into a list and bundled alongside the result so
  # callers can replay them on the main thread via replay_async_warnings().
  wrapped_expr <- bquote({
    .async_warnings <- list()
    .async_value <- withCallingHandlers(
      .(expr),
      warning = function(w) {
        .async_warnings[[length(.async_warnings) + 1L]] <<- w
        tryInvokeRestart("muffleWarning")
      }
    )
    list(
      .shinyOAuth_async_wrapped = TRUE,
      value = .async_value,
      warnings = .async_warnings
    )
  })

  # Try mirai first (preferred backend)
  mirai_available <- rlang::is_installed("mirai") && mirai_daemons_active()

  if (mirai_available) {
    # Use mirai - inject the expression and args into the call.
    # .timeout enables per-task cancellation when using dispatcher.
    return(rlang::inject(
      mirai::mirai(!!wrapped_expr, .args = args, .timeout = .timeout)
    ))
  }

  # Fall back to future_promise if available
  future_available <- rlang::is_installed("promises") &&
    rlang::is_installed("future") &&
    tryCatch(
      {
        # Check if a non-sequential plan is set
        future::nbrOfWorkers() > 0
      },
      error = function(...) FALSE
    )

  if (future_available) {
    # Build environment with captured args for future
    env <- list2env(args, parent = globalenv())
    # wrapped_expr is already a quoted expression, so disable substitution
    return(promises::future_promise(
      expr = wrapped_expr,
      envir = env,
      substitute = FALSE
    ))
  }

  # Neither backend is properly configured
  rlang::abort(
    c(
      "No async backend available",
      "i" = "Configure mirai daemons: `mirai::daemons(2)`",
      "i" = "Or configure a future plan: `future::plan(future::multisession)`"
    ),
    class = "shinyOAuth_no_async_backend"
  )
}

# Internal: replay warnings captured by async_dispatch() and return the
# unwrapped result value.
#
# When `result` is the wrapped list produced by async_dispatch()'s
# withCallingHandlers wrapper, this function re-emits each captured warning
# in the main process and returns the actual value. If `result` is not wrapped
# (e.g., from a non-async path), it is returned as-is.
#
# @param result The resolved value from an async_dispatch() promise.
# @return The unwrapped result value.
replay_async_warnings <- function(result) {
  if (
    is.list(result) &&
      isTRUE(result$.shinyOAuth_async_wrapped)
  ) {
    for (w in result$warnings) {
      warning(w)
    }
    return(result$value)
  }
  result
}

# Internal: check if any async backend is available
# Returns "mirai", "future", or NULL
async_backend_available <- function() {
  # Check mirai first (preferred)
  if (rlang::is_installed("mirai") && mirai_daemons_active()) {
    return("mirai")
  }

  # Check future
  if (rlang::is_installed("promises") && rlang::is_installed("future")) {
    future_ok <- tryCatch(
      {
        future::nbrOfWorkers() > 0
      },
      error = function(...) FALSE
    )
    if (future_ok) {
      return("future")
    }
  }

  NULL
}

# Internal: prepare a serialization-safe copy of an OAuthClient for async workers.
#
# The state_store (and optionally the JWKS cache) may contain non-serializable
# objects (e.g., closures over database connections, external pointers). Since
# the state was already consumed on the main thread before async dispatch, the
# worker never accesses the state_store, so we replace it with a lightweight
# cachem::cache_mem() that is guaranteed serializable.
#
# After replacement, the entire client is tested with serialize(). If it still
# fails (e.g., due to other non-serializable components), NULL is returned so
# callers can fall back to synchronous execution.
#
# @param client An OAuthClient object.
# @return A serialization-safe OAuthClient copy, or NULL if serialization
#   fails despite cleanup.
prepare_client_for_worker <- function(client) {
  tryCatch(
    {
      # S7 value semantics: assignment copies the object
      worker_client <- client
      # Replace state_store with a lightweight serializable dummy.
      # The state was already consumed on the main thread, so this cache
      # will never be accessed in the worker.
      worker_client@state_store <- cachem::cache_mem(max_age = 1)
      # Verify the cleaned-up client can actually be serialized
      serialize(worker_client, connection = NULL)
      worker_client
    },
    error = function(e) {
      NULL
    }
  )
}

# Internal: classify a mirai error for better diagnostics.
# mirai distinguishes between execution errors (code threw), connection resets
# (daemon crashed, errorValue 19), timeouts (errorValue 5), and cancellations
# (errorValue 20). This helper returns a short classification string for audit
# events and log messages. Returns NULL when mirai is not installed or when
# the value is not an error.
#
# @param x The error value or data from a mirai (e.g. m$data or e in catch)
# @return One of "mirai_error" (code error), "mirai_timeout" (timed out),
#   "mirai_connection_reset" (daemon crash), "mirai_interrupt" (interrupted/cancelled),
#   "mirai_error_value" (other transport error), or NULL (not a mirai error).
classify_mirai_error <- function(x) {
  if (!rlang::is_installed("mirai")) {
    return(NULL)
  }
  if (tryCatch(mirai::is_mirai_error(x), error = function(...) FALSE)) {
    return("mirai_error")
  }
  if (tryCatch(mirai::is_mirai_interrupt(x), error = function(...) FALSE)) {
    return("mirai_interrupt")
  }
  if (tryCatch(mirai::is_error_value(x), error = function(...) FALSE)) {
    # Distinguish timeout (5) and connection reset (19) from other values
    ev <- tryCatch(as.integer(x), error = function(...) NA_integer_)
    if (identical(ev, 5L)) {
      return("mirai_timeout")
    }
    if (identical(ev, 19L)) {
      return("mirai_connection_reset")
    }
    return("mirai_error_value")
  }
  NULL
}
