# This file contains the helpers that discover async backends, dispatch work to
# them, and replay worker-side conditions on the main process.
# Use them when login, token, or userinfo code should run away from the main
# Shiny process without losing diagnostics or trace context.

# 1 Async dispatch helpers -----------------------------------------------------

## 1.1 Backend discovery and dispatch ------------------------------------------

#' Check whether mirai daemons are active
#'
#' Uses `mirai::daemons_set()` when available, and falls back to
#' `mirai::info()` for older mirai versions that lack that helper.
#'
#' @return `TRUE` when mirai daemons are active; otherwise `FALSE`.
#' @keywords internal
#' @noRd
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

#' Get the number of mirai daemon connections
#'
#' Uses `mirai::info()$connections`, which is the stable interface recommended
#' by mirai.
#'
#' @return Integer count of connections, or `0L` on error.
#' @keywords internal
#' @noRd
mirai_connection_count <- function() {
  tryCatch(
    as.integer(mirai::info()$connections),
    error = function(...) 0L
  )
}

#' Dispatch async work through the configured backend
#'
#' Main async entry point used by [oauth_module_server()] and the async token
#' and UserInfo helpers. Prefers mirai when daemons are configured and otherwise
#' falls back to `future_promise()`. Warnings and messages emitted by the worker
#' are captured in a wrapper object so callers can replay them in the main
#' process with `replay_async_conditions()`.
#'
#' @param expr Quoted expression to evaluate.
#' @param args Named list of values bound into `expr`.
#' @param .timeout Optional mirai timeout in milliseconds.
#' @param otel_context Optional list of OTEL propagation metadata for the
#'   worker.
#' @return Promise that resolves to a wrapped result object.
#' @keywords internal
#' @noRd
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

## 1.2 Replay and worker preparation -------------------------------------------

#' Replay captured async conditions and unwrap the result
#'
#' Re-emits warnings and messages captured by `async_dispatch()` and then
#' returns the wrapped value. If `result` is not wrapped, it is returned
#' unchanged.
#'
#' @param result Resolved value from an `async_dispatch()` promise.
#' @return Unwrapped result value.
#' @keywords internal
#' @noRd
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

#' Detect the available async backend
#'
#' @return `"mirai"`, `"future"`, or `NULL` when no supported async backend is
#'   available.
#' @keywords internal
#' @noRd
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

#' Prepare a serialization-safe OAuthClient for async workers
#'
#' Replaces worker-unneeded state-store internals with a lightweight
#' serializable cache and tests the result with [serialize()]. Used before
#' OAuth client objects are shipped to worker processes.
#'
#' @param client [OAuthClient] object.
#' @return Serialization-safe OAuthClient copy, or `NULL` when cleanup is still
#'   insufficient.
#' @keywords internal
#' @noRd
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

#' Classify a mirai error value
#'
#' Used by async diagnostics so mirai transport failures, timeouts, and worker
#' code errors can be logged distinctly.
#'
#' @param x Error value or condition returned by mirai.
#' @return One of `"mirai_error"`, `"mirai_timeout"`,
#'   `"mirai_connection_reset"`, `"mirai_interrupt"`,
#'   `"mirai_error_value"`, or `NULL` when `x` is not recognized as a mirai
#'   error.
#' @keywords internal
#' @noRd
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
