# Async backend discovery, dispatch, and worker diagnostics.
#
# Helper groups in this file:
# - detect whether mirai or future backends are available
# - dispatch OAuth work off the main process and replay worker conditions
# - prepare serialization-safe worker inputs and classify transport failures

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

# Main async entry point used by oauth_module_server() and async token methods.
# Prefers mirai if daemons are configured, otherwise falls back to
# future_promise. Returns a promise in either case.
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
        # Check if a future plan is set; sequential still reports one worker.
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
