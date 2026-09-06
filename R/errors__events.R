# This file contains event and audit helpers for shinyOAuth
# Used for recording what happened during login, token, and callback flows in a
# structured way

# 1 Event helpers --------------------------------------------------------------

## 1.1 Audit helpers -----------------------------------------------------------

#' Registered shinyOAuth audit event types
#'
#' This is the authoritative catalog used by the event emitter, documentation
#' coverage tests, and serialization tests. Test-only event names may use the
#' `test_` prefix without becoming part of the public catalog.
#'
#' @return Character vector of event names without the `audit_` prefix.
#' @keywords internal
#' @noRd
audit_event_registry <- function() {
  c(
    "redirect_issued",
    "callback_query_rejected",
    "callback_iss_missing",
    "callback_iss_mismatch",
    "callback_iss_validation_failed",
    "callback_received",
    "callback_validation_success",
    "callback_validation_failed",
    "state_store_lookup_failed",
    "state_store_removal_failed",
    "token_exchange",
    "token_exchange_error",
    "token_introspection",
    "login_success",
    "login_failed",
    "logout",
    "session_cleared",
    "token_revocation",
    "refresh_failed_but_kept_session",
    "browser_cookie_error",
    "invalid_browser_token",
    "token_refresh",
    "userinfo",
    "state_parse_failure",
    "error_state_consumed",
    "error_state_consumption_failed",
    "session_started",
    "session_ended",
    "session_ended_revoke",
    "authenticated_changed"
  )
}

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
#   - shiny_session: list with session_token_digest and optional HTTP context
#     (the raw `token` field is forwarded only when
#     `shinyOAuth.audit_include_raw_session_token = TRUE`)
#   - ...: fields from context

#' Emit one audit event
#'
#' Builds a structured audit event, attaches a trace id, and forwards it to the
#' configured event pipeline. Used across login, token, state, and module code.
#'
#' @param type Short audit event name, without the `audit_` prefix.
#' @param context Named list of non-sensitive event fields.
#' @param shiny_session Optional pre-captured Shiny session context.
#' @param trace_id Optional trace id to reuse for the emitted event.
#' @return Invisibly returns the trace id used for the event.
#' @keywords internal
#' @noRd
audit_event <- function(
  type,
  context = list(),
  shiny_session = NULL,
  trace_id = NULL
) {
  if (!is_valid_string(type)) {
    err_config("Audit event type must be a single non-empty string")
  }
  if (
    !(type %in% audit_event_registry()) &&
      !startsWith(type, "test_")
  ) {
    err_config(paste0(
      "Unregistered shinyOAuth audit event type: ",
      type
    ))
  }
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
    event[["shiny_session"]] <- shiny_session
  }
  emit_trace_event(event)
  invisible(trace_id)
}

#' Sanitize one Shiny session payload for audit hooks
#'
#' Hook consumers receive a stable session digest by default; the raw Shiny
#' session token is only forwarded when explicitly enabled via a global option.
#'
#' @param shiny_session Optional Shiny session context list.
#' @return Sanitized Shiny session context.
#' @keywords internal
#' @noRd
sanitize_audit_hook_shiny_session <- function(shiny_session) {
  if (is.null(shiny_session) || !is.list(shiny_session)) {
    return(shiny_session)
  }

  sanitized <- shiny_session
  token <- sanitized[["token"]] %||% NULL

  if (
    is.null(sanitized[["session_token_digest"]]) &&
      is_valid_string(token)
  ) {
    sanitized[["session_token_digest"]] <- string_digest(token)
  }

  if (!isTRUE(getOption("shinyOAuth.audit_include_raw_session_token", FALSE))) {
    sanitized[["token"]] <- NULL
  }

  compact_list(sanitized)
}

#' Sanitize one event before it reaches a native audit hook
#'
#' @param event Event list.
#' @return Hook-safe event list.
#' @keywords internal
#' @noRd
sanitize_audit_hook_event <- function(event) {
  if (!is.list(event) || !length(event)) {
    return(event)
  }

  shiny_session <- event[["shiny_session"]] %||% NULL
  if (!is.null(shiny_session)) {
    event[["shiny_session"]] <- sanitize_audit_hook_shiny_session(
      shiny_session
    )
  }

  event
}

#' Remove credentials from URL-valued event fields
#'
#' Sanitizes URL-like fields recursively before an event reaches either an
#' audit hook or OpenTelemetry. Query strings, fragments, and userinfo are not
#' useful as event dimensions and may contain credentials or personal data.
#'
#' @param event Event payload or nested event value.
#' @param field_name Name of the value within its parent, when available.
#' @return Event payload with URL-valued fields reduced to scheme, authority,
#'   and path. Unparseable URL-valued fields are omitted.
#' @keywords internal
#' @noRd
sanitize_event_url_fields <- function(event, field_name = NULL) {
  normalized_name <- if (is_valid_string(field_name)) {
    tolower(gsub("[^A-Za-z0-9]+", "_", trimws(field_name)))
  } else {
    ""
  }
  is_url_field <- grepl("(^|_)(url|uri|issuer)$", normalized_name) ||
    grepl("(^|_)endpoint$", normalized_name)

  if (is_url_field) {
    return(tryCatch(otel_http_url_full(event), error = function(...) NULL))
  }
  if (!is.list(event) || !length(event)) {
    return(event)
  }

  nms <- names(event)
  for (i in seq_along(event)) {
    child_name <- if (!is.null(nms) && nzchar(nms[[i]])) nms[[i]] else NULL
    event[i] <- list(sanitize_event_url_fields(event[[i]], child_name))
  }
  event
}

#' Warn about an observational event-sink failure without throwing
#'
#' @param title Warning title.
#' @param bullets Warning details.
#' @return Invisibly returns `NULL`.
#' @keywords internal
#' @noRd
warn_event_sink_failure <- function(title, bullets) {
  # Audit and telemetry are observational side effects. A strict global warning
  # policy must not turn their failure into a replacement for the OAuth error
  # that the package is in the process of constructing.
  old_warn <- getOption("warn")
  on.exit(options(warn = old_warn), add = TRUE)
  options(warn = 0)
  tryCatch(
    warn_pkg(title, escape_diagnostic_markup(bullets)),
    error = function(...) invisible(NULL)
  )
  invisible(NULL)
}

#' Dispatch one trace or audit event
#'
#' Enriches one event with Shiny context and forwards it to OpenTelemetry and
#' the configured audit hook. `trace_hook` intentionally remains supported only
#' as an undocumented backward-compatible alias when `audit_hook` is unset.
#' When both options are configured, `audit_hook` takes precedence. Native hook
#' payloads expose `shiny_session$session_token_digest` by default; the raw
#' token requires an explicit opt-in. Used by `audit_event()` and direct
#' internal event emitters.
#'
#' @param event Named list describing one event.
#' @return Invisibly returns `NULL`.
#' @keywords internal
#' @noRd
emit_trace_event <- function(event) {
  audit_hook <- getOption("shinyOAuth.audit_hook", NULL)
  hook_name <- "audit_hook"
  if (!is.function(audit_hook)) {
    # Keep trace_hook fallback for backward compatibility only.
    # It remains intentionally undocumented in user-facing options guidance.
    audit_hook <- getOption("shinyOAuth.trace_hook", NULL)
    hook_name <- "trace_hook"
  }
  # Enrich with Shiny session/request context when running inside Shiny
  event <- tryCatch(augment_with_shiny_context(event), error = function(...) {
    event
  })
  event <- sanitize_event_diagnostics(sanitize_event_url_fields(event))
  tryCatch(
    {
      otel_emit_log(event)
    },
    error = function(e) {
      warn_event_sink_failure(
        "Failed to emit OpenTelemetry log",
        c(
          "!" = paste0(
            "OpenTelemetry logging failed while handling an internal shinyOAuth event: ",
            if (allow_expose_error_body()) {
              sanitize_diagnostic_text(conditionMessage(e))
            } else {
              "details withheld"
            }
          )
        )
      )
    }
  )
  if (is.function(audit_hook)) {
    hook_event <- sanitize_audit_hook_event(event)

    # Surface hook errors as warnings so they are visible in the main process
    # (async_dispatch captures warnings and replays them on the main thread).
    tryCatch(
      audit_hook(hook_event),
      error = function(e) {
        warn_event_sink_failure(
          paste0("Configured shinyOAuth ", hook_name, " failed"),
          c(
            "!" = paste0(
              hook_name,
              " error: ",
              if (allow_expose_error_body()) {
                sanitize_diagnostic_text(conditionMessage(e))
              } else {
                "details withheld"
              }
            )
          )
        )
      }
    )
  }
  invisible(NULL)
}

## 1.2 Other helpers -----------------------------------------------------------

#' Print a concise internal condition summary
#'
#' Internal debugging helper used in interactive sessions and explicit tests to
#' summarize a condition and, optionally, include a traceback. Used for
#' interactive debugging and explicit tests.
#'
#' @param e Condition object to summarize.
#' @param context Optional named list of extra debugging context.
#' @param enabled Whether console output should be produced.
#' @param include_traceback Whether to include an rlang or base traceback.
#' @return Invisibly returns `NULL`.
#' @keywords internal
#' @noRd
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

  msg <- if (allow_expose_error_body()) {
    sanitize_diagnostic_text(conditionMessage(e))
  } else {
    short_desc_for_class(class(e))
  }

  try(
    {
      cat("\n")
      cat(header, "\n", sep = "")
      cat("  ", msg, "\n", sep = "")

      if (isTRUE(include_traceback)) {
        # Prefer rlang backtrace if present (after entrace())
        if (
          inherits(e, "rlang_error") &&
            !is.null(e[["trace"]])
        ) {
          cat("-- Backtrace (rlang) --\n")
          cat(
            paste(format(e[["trace"]]), collapse = "\n"),
            "\n",
            sep = ""
          )
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
