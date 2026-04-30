# Internal error helpers with trace IDs and sanitization

# Trace context ------------------------------------------------------------

.trace_context_env <- new.env(parent = emptyenv())

get_current_trace_id <- function() {
  trace_id <- .trace_context_env$current %||% NULL
  if (is_valid_string(trace_id)) {
    return(as.character(trace_id)[[1]])
  }
  NULL
}

resolve_trace_id <- function(trace_id = NULL) {
  trace_id <- trace_id %||% get_current_trace_id()
  if (is_valid_string(trace_id)) {
    return(as.character(trace_id)[[1]])
  }
  gen_trace_id()
}

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

# Generate a short trace id for correlating errors in logs
gen_trace_id <- function() {
  tryCatch(random_urlsafe(12), error = function(e) {
    # Fallback if crypto fails
    paste0(as.integer(runif(3, 0, 1e6)), collapse = "-")
  })
}
