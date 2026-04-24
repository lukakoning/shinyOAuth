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

# Internal: capture Shiny session context for later use in async workers or
# in callbacks that no longer have a reactive domain available.
# Call this on the main thread (inside a reactive observer or module server)
# before spawning an async task. The returned list can be passed to
# audit_event(..., shiny_session = <captured>) so that events emitted from
# the async context include the originating Shiny session information.
# Returns NULL if no session context is available.
#
# When `is_async = TRUE`, the context is intended for a worker process and
# therefore records the main process ID for later correlation. When
# `is_async = FALSE`, the context represents the current main R process and
# includes its process_id directly.
capture_shiny_session_context <- function(is_async = TRUE) {
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
      is_async = isTRUE(is_async),
      process_id = if (!isTRUE(is_async)) main_pid else NULL,
      main_process_id = if (isTRUE(is_async)) main_pid else NULL
    )
  } else {
    NULL
  }
}

# Internal: normalize a provided shiny_session context for the current process.
# This fills in worker-local fields when async context is active, and corrects
# main-process emissions that were given a worker-intended context before
# dispatch actually happened.
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

# Internal: clear the fallback session context.
clear_async_session_context <- function() {
  .async_context_env$current <- NULL
  .async_context_env$is_worker <- FALSE
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
  if (!is.null(ctx)) {
    try(
      otel_set_span_attributes(attributes = otel_shiny_attributes(ctx)),
      silent = TRUE
    )
  }
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
  # Capture relevant OpenTelemetry env vars as internal metadata so async
  # workers inherit the parent session's telemetry configuration rather than
  # the ambient shell environment.
  opts[[".shinyOAuth.otel_envvars"]] <- capture_async_otel_envvars()
  # Propagate the effective digest key so worker-emitted digests remain
  # comparable even when the operator relies on the default auto-keying.
  opts[[".shinyOAuth.audit_digest_key_cache"]] <- get_audit_digest_key()
  # Also capture the originating process ID for audit event context
  opts[[".shinyOAuth.main_process_id"]] <- Sys.getpid()
  opts
}

# Internal: capture the effective shinyOAuth OTel option gates, including
# default values when the options are currently unset in the main process.
capture_async_otel_option_gates <- function() {
  list(
    shinyOAuth.otel_tracing_enabled = otel_tracing_enabled(),
    shinyOAuth.otel_logging_enabled = otel_logging_enabled()
  )
}

# Internal: apply captured shinyOAuth OTel option gates before restoring worker
# spans. This keeps reused workers from reusing stale FALSE option values from
# previous tasks when the main process expects tracing/logging to be enabled.
apply_async_otel_option_gates <- function(captured_gates) {
  if (is.null(captured_gates) || length(captured_gates) == 0) {
    return(list(old_options = list()))
  }

  list(old_options = do.call(options, captured_gates))
}

# Internal: restore worker-local shinyOAuth OTel option gates after temporary
# async propagation.
restore_async_otel_option_gates <- function(old_options) {
  if (is.null(old_options) || length(old_options) == 0) {
    return(invisible(NULL))
  }

  do.call(options, old_options)
  invisible(NULL)
}

# Internal: capture the OpenTelemetry env vars that influence exporter
# selection and OTLP endpoints. Values set to NA indicate the variable should
# be unset in the async worker.
current_async_otel_envvar_names <- function() {
  grep("^OTEL(_R)?_", names(Sys.getenv()), value = TRUE)
}

capture_async_otel_envvars <- function() {
  otel_names <- unique(c(
    current_async_otel_envvar_names(),
    "OTEL_R_TRACES_EXPORTER",
    "OTEL_R_LOGS_EXPORTER",
    "OTEL_R_METRICS_EXPORTER",
    "OTEL_TRACES_EXPORTER",
    "OTEL_LOGS_EXPORTER",
    "OTEL_METRICS_EXPORTER",
    "OTEL_EXPORTER_OTLP_ENDPOINT",
    "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
    "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT",
    "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT"
  ))
  if (!length(otel_names)) {
    return(stats::setNames(character(0), character(0)))
  }
  Sys.getenv(otel_names, unset = NA_character_)
}

# Internal: apply captured OTEL env vars in the current process and rebuild
# cached providers whenever the effective OTEL configuration changes.
reset_async_otel_cache <- function() {
  otel_clean_cache <- tryCatch(
    get(
      "otel_clean_cache",
      envir = asNamespace("otel"),
      inherits = FALSE
    ),
    error = function(...) NULL
  )
  if (is.function(otel_clean_cache)) {
    try(otel_clean_cache(), silent = TRUE)
  }
}

apply_async_otel_envvars <- function(captured_envvars) {
  if (is.null(captured_envvars) || length(captured_envvars) == 0) {
    return(list(
      changed = FALSE,
      old_envvars = stats::setNames(character(0), character(0))
    ))
  }

  # Reused workers may still carry OTEL_* values that were not explicitly
  # captured by the parent because they were unset there. Treat the captured
  # state as authoritative and clear any extra OTEL vars currently living in
  # the worker, while preserving them for restore on exit.
  env_names <- unique(c(
    names(captured_envvars),
    current_async_otel_envvar_names()
  ))
  old_envvars <- Sys.getenv(env_names, unset = NA_character_)
  desired_envvars <- stats::setNames(
    rep(NA_character_, length(env_names)),
    env_names
  )
  desired_envvars[names(captured_envvars)] <- captured_envvars
  otel_envvars_changed <- !identical(old_envvars, desired_envvars)
  if (!isTRUE(otel_envvars_changed)) {
    return(list(changed = FALSE, old_envvars = old_envvars))
  }

  new_values <- desired_envvars[!is.na(desired_envvars)]
  vars_to_unset <- names(desired_envvars)[is.na(desired_envvars)]
  if (length(new_values)) {
    do.call(Sys.setenv, as.list(new_values))
  }
  if (length(vars_to_unset)) {
    Sys.unsetenv(vars_to_unset)
  }

  # OTEL_* env vars only affect provider setup at initialization time, so
  # reused async workers must rebuild cached providers after any env change,
  # including transitions from an enabled exporter back to "none".
  reset_async_otel_cache()

  list(changed = TRUE, old_envvars = old_envvars)
}

# Internal: restore OTEL env vars after temporary async worker propagation.
restore_async_otel_envvars <- function(old_envvars) {
  if (is.null(old_envvars) || length(old_envvars) == 0) {
    return(invisible(NULL))
  }

  restore_values <- old_envvars[!is.na(old_envvars)]
  restore_unset <- names(old_envvars)[is.na(old_envvars)]
  if (length(restore_values)) {
    do.call(Sys.setenv, as.list(restore_values))
  }
  if (length(restore_unset)) {
    Sys.unsetenv(restore_unset)
  }

  reset_async_otel_cache()

  invisible(NULL)
}

# Internal: execute code with captured shinyOAuth options temporarily set.
# This restores package options from the main process inside an async worker.
# Returns the result of evaluating `code`.
with_async_options <- function(captured_opts, code) {
  if (is.null(captured_opts) || length(captured_opts) == 0) {
    return(force(code))
  }
  old_async_worker <- set_async_worker_context(is_async_worker(captured_opts))
  on.exit(set_async_worker_context(old_async_worker), add = TRUE)
  captured_envvars <- captured_opts[[".shinyOAuth.otel_envvars"]]
  captured_digest_key <- captured_opts[[".shinyOAuth.audit_digest_key_cache"]]
  # Filter out internal markers (start with ".")
  opts_to_set <- captured_opts[
    !startsWith(names(captured_opts), ".")
  ]
  if (!is.null(captured_envvars) && length(captured_envvars) > 0) {
    otel_env_state <- apply_async_otel_envvars(captured_envvars)
    if (isTRUE(otel_env_state$changed)) {
      on.exit(
        restore_async_otel_envvars(otel_env_state$old_envvars),
        add = TRUE
      )
    }
  }

  if (".shinyOAuth.audit_digest_key_cache" %in% names(captured_opts)) {
    old_digest_key <- audit_digest_key_env$key
    audit_digest_key_env$key <- captured_digest_key
    on.exit(
      {
        audit_digest_key_env$key <- old_digest_key
      },
      add = TRUE
    )
  }

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
  # Normalize it first so borrowed async contexts pick up worker-local fields,
  # or are corrected when the event is still emitted on the main process.
  if (!is.null(event$shiny_session)) {
    event$shiny_session <- normalize_shiny_session_context(event$shiny_session)
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

# Internal: call a helper and forward `shiny_session` only when the target
# explicitly declares that parameter. This keeps async context propagation
# explicit in runtime code without breaking tests that mock helpers using the
# older two/three-argument signatures.
call_with_optional_shiny_session <- function(
  fn,
  ...,
  shiny_session = NULL
) {
  args <- list(...)
  fn_formals <- tryCatch(names(formals(fn)), error = function(...) NULL)
  if (!is.null(fn_formals) && "shiny_session" %in% fn_formals) {
    args$shiny_session <- shiny_session
  }
  do.call(fn, args)
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
# Warnings and messages emitted by the worker expression are captured and
# bundled with the result in a wrapper list (`$.shinyOAuth_async_wrapped`).
# Callers should pass the resolved value through `replay_async_conditions()`
# to re-emit the conditions in the main process and unwrap the actual result.
#
# @param expr A quoted expression to evaluate (use quote() or substitute())
# @param args A named list of values to pass to the expression
# @param .timeout Optional integer timeout in milliseconds for the mirai task.
#   When using mirai with dispatcher (the default), timed-out tasks are
#   automatically cancelled. Falls back to `getOption("shinyOAuth.async_timeout")`
#   when NULL (default = no timeout).
# @param otel_context Optional list with `headers`, `worker_span_name`,
#   `attributes`, and `shiny_session` for restoring OpenTelemetry parent
#   context in the worker.
# @return A promise that resolves to a wrapped result (use `replay_async_conditions()`)
async_dispatch <- function(expr, args, .timeout = NULL, otel_context = NULL) {
  .timeout <- .timeout %||% getOption("shinyOAuth.async_timeout")
  captured_otel_envvars <- capture_async_otel_envvars()
  captured_otel_option_gates <- capture_async_otel_option_gates()
  captured_trace_id <- get_current_trace_id()
  if (!is.null(otel_context)) {
    otel_context$attributes <- otel_with_trace_attribute(
      attributes = otel_context$attributes,
      trace_id = captured_trace_id
    )
  }

  # Wrap the expression to capture warnings and messages emitted in the worker
  # process. Conditions are collected into lists and bundled alongside the
  # result so callers can replay them on the main thread via
  # replay_async_conditions().
  wrapped_expr <- bquote({
    .ns <- asNamespace("shinyOAuth")
    .otel_worker_span <- NULL
    .async_error <- NULL
    .otel_envvars <- .(captured_otel_envvars)
    .otel_option_gates <- .(captured_otel_option_gates)
    .otel_context <- .(otel_context)
    if (!is.null(.otel_option_gates) && length(.otel_option_gates) > 0) {
      .otel_option_state <- .ns$apply_async_otel_option_gates(
        .otel_option_gates
      )
      on.exit(
        .ns$restore_async_otel_option_gates(.otel_option_state$old_options),
        add = TRUE
      )
    }
    if (!is.null(.otel_envvars) && length(.otel_envvars) > 0) {
      .otel_env_state <- .ns$apply_async_otel_envvars(.otel_envvars)
      if (isTRUE(.otel_env_state$changed)) {
        on.exit(
          .ns$restore_async_otel_envvars(.otel_env_state$old_envvars),
          add = TRUE
        )
      }
    }
    if (!is.null(.otel_context)) {
      .otel_worker_span <- .ns$otel_restore_parent_in_worker(
        otel_headers = if (!is.null(.otel_context$headers)) {
          .otel_context$headers
        } else {
          NULL
        },
        name = if (!is.null(.otel_context$worker_span_name)) {
          .otel_context$worker_span_name
        } else {
          "shinyOAuth.async.worker"
        },
        attributes = if (!is.null(.otel_context$attributes)) {
          .otel_context$attributes
        } else {
          list()
        },
        shiny_session = if (!is.null(.otel_context$shiny_session)) {
          .otel_context$shiny_session
        } else {
          NULL
        }
      )
    }
    on.exit(
      .ns$otel_end_async_parent(
        list(span = .otel_worker_span),
        status = if (is.null(.async_error)) "ok" else "error",
        error = .async_error
      ),
      add = TRUE
    )
    .async_warnings <- list()
    .async_messages <- list()
    .async_value <- tryCatch(
      withCallingHandlers(
        .ns$otel_with_active_span(.otel_worker_span, {
          .(expr)
        }),
        warning = function(w) {
          .async_warnings[[length(.async_warnings) + 1L]] <<- w
          tryInvokeRestart("muffleWarning")
        },
        message = function(m) {
          .async_messages[[length(.async_messages) + 1L]] <<- m
          tryInvokeRestart("muffleMessage")
        }
      ),
      error = function(e) {
        .async_error <<- e
        stop(e)
      }
    )
    list(
      .shinyOAuth_async_wrapped = TRUE,
      value = .async_value,
      warnings = .async_warnings,
      messages = .async_messages
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

# Internal: replay conditions (warnings and messages) captured by
# async_dispatch() and return the unwrapped result value.
#
# When `result` is the wrapped list produced by async_dispatch()'s
# withCallingHandlers wrapper, this function re-emits each captured condition
# in the main process and returns the actual value. If `result` is not wrapped
# (e.g., from a non-async path), it is returned as-is.
#
# Messages are replayed first, then warnings, mirroring typical execution
# order where informational output precedes diagnostic signals.
#
# Controlled by `options(shinyOAuth.replay_async_conditions)`:
# - TRUE (default): re-emit captured conditions in the main process.
# - FALSE: silently discard captured conditions (result is still unwrapped).
#
# @param result The resolved value from an async_dispatch() promise.
# @return The unwrapped result value.
replay_async_conditions <- function(result) {
  if (
    is.list(result) &&
      isTRUE(result$.shinyOAuth_async_wrapped)
  ) {
    if (!isFALSE(getOption("shinyOAuth.replay_async_conditions", TRUE))) {
      for (m in result$messages) {
        message(m)
      }
      for (w in result$warnings) {
        warning(w)
      }
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
