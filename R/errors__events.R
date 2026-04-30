# This file contains the event and audit helpers used when shinyOAuth records
# what happened during login, token, and callback flows.
# Use them to build one structured event, enrich it with session context, and
# send it to the configured hooks and OpenTelemetry logging bridge.

# 1 Event helpers ----------------------------------------------------------

## 1.1 Audit helpers -------------------------------------------------------

# Audit convenience to emit structured audit events
# - type: short action name, e.g., "token_exchange", "token_refresh", "userinfo"
# - context: named list of non-sensitive fields (redacted/digested values only)
# - shiny_session: optional pre-captured session context list (with `token` and
#   optionally `http`). When provided, this context is injected into the event
#   before calling emit_trace_event(), allowing async workers (which lack access
#   to the reactive domain) to include the originating Shiny session information.
#   Use `capture_shiny_session_context()` on the main thread to prepare this.
#
# Emitted event shape (list):
#   - type: "audit_<type>"
#   - trace_id: opaque correlation id
#   - timestamp: POSIXct time when the event was created (Sys.time())
#   - shiny_session: list with session token and optional HTTP context
#   - ...: fields from context

# Build and emit one structured audit event.
# Used across login, token, state, and module code. Input: event type,
# non-sensitive context, and optional Shiny/trace context. Output: invisible
# trace id.
# Broadcast audit events via hooks and OTel logs
audit_event <- function(
  type,
  context = list(),
  shiny_session = NULL,
  trace_id = NULL
) {
  trace_id <- resolve_trace_id(trace_id)
  event <- c(
    list(
      type = paste0("audit_", type),
      trace_id = trace_id,
      timestamp = Sys.time()
    ),
    context
  )
  # Pre-inject shiny_session if provided. emit_trace_event() will still
  # normalize it for the current process so borrowed async contexts pick up
  # worker-local fields or are corrected when emitted on the main thread.
  if (!is.null(shiny_session)) {
    event$shiny_session <- shiny_session
  }
  emit_trace_event(event)
  invisible(trace_id)
}

# Enrich one event and dispatch it to OTEL logging and the configured hook.
# Used by audit_event() and direct internal event emitters. Input: one event
# list. Output: invisible NULL.
# Central event dispatcher: enriches with Shiny context, then fans out to
# OTel logs and the configured native event hook.
# trace_hook remains as a backward-compatible alias for audit_hook when the
# latter is unset.
emit_trace_event <- function(event) {
  audit_hook <- getOption("shinyOAuth.audit_hook", NULL)
  hook_name <- "audit_hook"
  if (!is.function(audit_hook)) {
    audit_hook <- getOption("shinyOAuth.trace_hook", NULL)
    hook_name <- "trace_hook"
  }
  # Enrich with Shiny session/request context when running inside Shiny
  event <- tryCatch(augment_with_shiny_context(event), error = function(...) {
    event
  })
  tryCatch(
    {
      otel_emit_log(event)
    },
    error = function(e) {
      rlang::warn(paste0(
        "[shinyOAuth] otel telemetry error: ",
        conditionMessage(e)
      ))
    }
  )
  if (is.function(audit_hook)) {
    # Surface hook errors as warnings so they are visible in the main process
    # (async_dispatch captures warnings and replays them on the main thread).
    tryCatch(
      audit_hook(event),
      error = function(e) {
        rlang::warn(paste0(
          "[shinyOAuth] ",
          hook_name,
          " error: ",
          conditionMessage(e)
        ))
      }
    )
  }
  invisible(NULL)
}

## 1.2 Other helpers -------------------------------------------------------

# Optionally print a concise internal error summary to the console.
# Used for interactive debugging and explicit tests. Input: condition object,
# optional context, and flags controlling output. Output: invisible NULL.
# Optionally print a concise internal error summary to the console.
# This is an internal debugging aid for interactive development and explicit
# tests, not a user-configurable package option.
log_condition <- function(
  e,
  context = list(),
  enabled = .is_interactive(),
  include_traceback = FALSE
) {
  if (!isTRUE(enabled)) {
    return(invisible(NULL))
  }

  # Compose header
  cls <- paste(class(e), collapse = ", ")
  trace_id <- e[["trace_id"]] # safe even if absent
  status <- e[["status"]]
  parts <- c(
    if (!is.null(trace_id)) paste0("trace=", trace_id) else NULL,
    if (!is.null(status) && is.finite(status)) {
      paste0("status=", status)
    } else {
      NULL
    },
    paste0("class=", cls)
  )
  header <- paste(parts, collapse = " ")

  msg <- conditionMessage(e)

  try(
    {
      cat("\n")
      cat(header, "\n", sep = "")
      cat("  ", msg, "\n", sep = "")

      if (isTRUE(include_traceback)) {
        # Prefer rlang backtrace if present (after entrace())
        if (inherits(e, "rlang_error") && !is.null(e$trace)) {
          cat("-- Backtrace (rlang) --\n")
          cat(paste(format(e$trace), collapse = "\n"), "\n", sep = "")
        } else {
          # Fall back to base call stack available inside the handler
          cat("-- Call stack (base) --\n")
          calls <- sys.calls()
          if (length(calls)) {
            # Drop our own frames to keep it readable
            lines <- vapply(
              calls,
              function(x) paste(deparse(x), collapse = ""),
              character(1)
            )
            drop <- grep("log_condition|tryCatch|withCallingHandlers", lines)
            if (length(drop)) {
              lines <- lines[-drop]
            }
            if (length(lines)) {
              cat(paste(rev(lines), collapse = "\n"), "\n", sep = "")
            }
          }
        }
      }
    },
    silent = TRUE
  )

  invisible(NULL)
}
