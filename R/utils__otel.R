# OpenTelemetry instrumentation helpers
#
# All functions in this file are no-ops when otel is not installed or when
# tracing/logging/metrics are disabled via environment variables. This keeps
# the performance impact at zero for users who do not opt in.

# Tracer name for otel auto-detection (see ?otel::default_tracer_name)
otel_tracer_name <- "r.package.shinyOAuth"

# ---------------------------------------------------------------------------
# Guard helpers
# ---------------------------------------------------------------------------

#' Check whether OpenTelemetry tracing is active
#'
#' Returns TRUE only when the otel package is installed AND an exporter is
#' configured (via `OTEL_TRACES_EXPORTER`).
#'
#' @return Logical scalar.
#' @keywords internal
#' @noRd
is_otel_tracing <- function() {
  requireNamespace("otel", quietly = TRUE) && otel::is_tracing_enabled()
}

#' Check whether OpenTelemetry logging is active
#' @keywords internal
#' @noRd
is_otel_logging <- function() {
  requireNamespace("otel", quietly = TRUE) && otel::is_logging_enabled()
}

#' Check whether OpenTelemetry metrics collection is active
#' @keywords internal
#' @noRd
is_otel_measuring <- function() {
  requireNamespace("otel", quietly = TRUE) && otel::is_measuring_enabled()
}

# ---------------------------------------------------------------------------
# Context propagation helpers (for async boundaries)
# ---------------------------------------------------------------------------

#' Capture the active span context as serialised HTTP headers
#'
#' Call this on the **main thread** before dispatching async work.
#' The returned value can be passed to the worker and fed to
#' `otel_restore_context()` to re-establish the parent-child relationship.
#'
#' @return A named character vector of headers, or NULL when tracing is off.
#' @keywords internal
#' @noRd
otel_capture_context <- function() {
  if (!is_otel_tracing()) {
    return(NULL)
  }
  hdrs <- otel::pack_http_context()
  if (length(hdrs) == 0L) NULL else hdrs
}

#' Restore a parent span context from serialised headers in a worker
#'
#' Call this inside an async worker. It deserialises the headers produced by
#' `otel_capture_context()` and returns the span context object that can be
#' used as `parent` when starting a child span.
#'
#' @param headers Named character vector (from `otel_capture_context()`).
#' @return An `otel_span_context` object, or NULL.
#' @keywords internal
#' @noRd
otel_restore_context <- function(headers) {
  if (is.null(headers) || !is_otel_tracing()) {
    return(NULL)
  }
  ctx <- otel::extract_http_context(as.list(headers))
  if (ctx$is_valid()) ctx else NULL
}

# ---------------------------------------------------------------------------
# Span lifecycle helpers
# ---------------------------------------------------------------------------

#' Start a child span inside an async worker
#'
#' Deserialises the parent context from `parent_headers`, creates a new span
#' that is a child of that remote parent, and activates it for the calling
#' frame.
#'
#' @param name Span name (character scalar).
#' @param parent_headers Serialised headers from `otel_capture_context()`.
#' @param attributes Optional named list of span attributes.
#' @param kind Span kind (default "internal").
#' @return The new span object (invisibly), or NULL when tracing is off.
#' @keywords internal
#' @noRd
otel_start_async_child <- function(
  name,
  parent_headers,
  attributes = NULL,
  kind = "internal",
  .local_envir = parent.frame()
) {
  if (!is_otel_tracing()) {
    return(invisible(NULL))
  }
  parent_ctx <- otel_restore_context(parent_headers)
  opts <- list(kind = kind)
  if (!is.null(parent_ctx)) {
    opts$parent <- parent_ctx
  }
  # Forward activation_scope so the span is scoped to the CALLER's frame
  # (not this helper's frame). Without this the span would auto-end when
  # otel_start_async_child() returns instead of when the worker code completes.
  spn <- otel::start_local_active_span(
    name,
    attributes = attributes,
    options = opts,
    activation_scope = .local_envir
  )
  invisible(spn)
}

#' Safely end a span with status "ok"
#'
#' @param span An otel span object (or NULL — no-op).
#' @keywords internal
#' @noRd
otel_end_span_ok <- function(span) {
  if (is.null(span)) {
    return(invisible(NULL))
  }
  tryCatch(
    span$end(status_code = "ok"),
    error = function(...) NULL
  )
  invisible(NULL)
}

#' Record an error and end a span with status "error"
#'
#' @param span An otel span object (or NULL — no-op).
#' @param error An R error condition, or a character message.
#' @keywords internal
#' @noRd
otel_end_span_error <- function(span, error) {
  if (is.null(span)) {
    return(invisible(NULL))
  }
  tryCatch(
    {
      if (inherits(error, "condition")) {
        span$record_exception(error)
      } else {
        span$add_event(
          "exception",
          attributes = otel::as_attributes(compact_list(list(
            exception.type = "character",
            exception.message = as.character(error)
          )))
        )
      }
      span$end(status_code = "error")
    },
    error = function(...) NULL
  )
  invisible(NULL)
}

# ---------------------------------------------------------------------------
# Metric helpers
# ---------------------------------------------------------------------------

#' Increment the login counter
#' @param success Logical — TRUE for success, FALSE for failure.
#' @param provider Provider name string.
#' @keywords internal
#' @noRd
otel_count_login <- function(success, provider = NULL) {
  if (!is_otel_measuring()) {
    return(invisible(NULL))
  }
  attrs <- otel::as_attributes(compact_list(list(
    success = success,
    provider = provider
  )))
  otel::counter_add("shinyoauth.login.total", attributes = attrs)
  invisible(NULL)
}

#' Increment the token refresh counter
#' @keywords internal
#' @noRd
otel_count_refresh <- function(success, provider = NULL) {
  if (!is_otel_measuring()) {
    return(invisible(NULL))
  }
  attrs <- otel::as_attributes(compact_list(list(
    success = success,
    provider = provider
  )))
  otel::counter_add("shinyoauth.token_refresh.total", attributes = attrs)
  invisible(NULL)
}

#' Record token exchange duration
#' @keywords internal
#' @noRd
otel_record_exchange_duration <- function(seconds, provider = NULL) {
  if (!is_otel_measuring() || is.null(seconds)) {
    return(invisible(NULL))
  }

  attrs <- otel::as_attributes(compact_list(list(provider = provider)))
  otel::histogram_record(
    "shinyoauth.token_exchange.duration_seconds",
    seconds,
    attributes = attrs
  )
  invisible(NULL)
}

#' Record token refresh duration
#' @keywords internal
#' @noRd
otel_record_refresh_duration <- function(seconds, provider = NULL) {
  if (!is_otel_measuring() || is.null(seconds)) {
    return(invisible(NULL))
  }
  attrs <- otel::as_attributes(compact_list(list(provider = provider)))
  otel::histogram_record(
    "shinyoauth.token_refresh.duration_seconds",
    seconds,
    attributes = attrs
  )
  invisible(NULL)
}

#' Adjust the active-sessions gauge
#' @param delta Integer: +1 on session start, -1 on session end.
#' @keywords internal
#' @noRd
otel_active_sessions <- function(delta) {
  if (!is_otel_measuring()) {
    return(invisible(NULL))
  }
  otel::up_down_counter_add("shinyoauth.active_sessions", delta)
  invisible(NULL)
}
