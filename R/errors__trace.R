# This file contains the helpers that create, carry, and restore trace ids for
# errors and audit events.
# Use them when one failure or event needs a stable id that can be reused across
# nested helpers, warnings, logs, and rethrown conditions.

# 1 Trace context ----------------------------------------------------------

.trace_context_env <- new.env(parent = emptyenv())

# Read the current trace id from the process-local trace context.
# Used by error, audit, and telemetry helpers. Input: none. Output: trace id or
# NULL.
get_current_trace_id <- function() {
  trace_id <- .trace_context_env$current %||% NULL
  if (is_valid_string(trace_id)) {
    return(as.character(trace_id)[[1]])
  }
  NULL
}

# Resolve a caller-supplied trace id or generate a new one.
# Used when errors and audit events need a guaranteed correlation id. Input:
# optional trace id. Output: trace id string.
resolve_trace_id <- function(trace_id = NULL) {
  trace_id <- trace_id %||% get_current_trace_id()
  if (is_valid_string(trace_id)) {
    return(as.character(trace_id)[[1]])
  }
  gen_trace_id()
}

# Run code with one trace id made current for nested helpers.
# Used around work that should share the same trace id. Input: optional trace id
# and code. Output: result of the code block.
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

# Rethrow a condition while preserving its trace id and adding extra context.
# Used by higher-level error wrappers. Input: caught condition, optional class,
# and extra abort args. Output: no return; aborts.
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

# Generate a short trace id for correlation in logs and conditions.
# Used as the fallback when no trace id is already active. Input: none.
# Output: trace id string.
# Generate a short trace id for correlating errors in logs
gen_trace_id <- function() {
  tryCatch(random_urlsafe(12), error = function(e) {
    # Fallback if crypto fails
    paste0(as.integer(runif(3, 0, 1e6)), collapse = "-")
  })
}
