# Internal error helpers with trace IDs and sanitization

# Generic -----------------------------------------------------------------

# Generic error abortor with trace id and structured context
err_abort <- function(msg, class = "shinyOAuth_error", context = list()) {
  trace_id <- gen_trace_id()
  emit_trace_event(c(
    list(type = "error", trace_id = trace_id, message = msg),
    context
  ))
  primary <- short_desc_for_class(c(class, "shinyOAuth_error"))
  # Allow rlang-style bullets in `msg`: a character vector with optional names
  bullets <- normalize_bullets(msg, default_type = "!")
  message <- c(
    format_header(primary),
    bullets,
    "i" = paste0("Trace ID: ", trace_id)
  )
  rlang::abort(
    message = message,
    class = c(class, "shinyOAuth_error"),
    trace_id = trace_id,
    context = context
  )
}

# Standard header for all error messages; has the package name & bold short description
format_header <- function(short) {
  paste0("[{.pkg shinyOAuth}] - {.strong ", short, "}")
}

# Map primary class to a short description for the header line
short_desc_for_class <- function(class_vec) {
  known <- c(
    shinyOAuth_http_error = "HTTP request failed",
    shinyOAuth_transport_error = "Transport failure",
    shinyOAuth_state_error = "Invalid OAuth state",
    shinyOAuth_pkce_error = "PKCE validation failed",
    shinyOAuth_token_error = "Token error",
    shinyOAuth_id_token_error = "ID token error",
    shinyOAuth_userinfo_error = "Userinfo request failed",
    shinyOAuth_userinfo_mismatch = "Userinfo does not match ID token",
    shinyOAuth_config_error = "Configuration error",
    shinyOAuth_input_error = "Invalid input",
    shinyOAuth_parse_error = "Parse error",
    shinyOAuth_error = "Error"
  )

  # Find first matching known class
  hit <- intersect(names(known), class_vec)

  # Return known description or generic fallback
  if (length(hit)) known[[hit[[1]]]] else "Miscellaneous error"
}

# Normalize a vector of message bullets to rlang's expected format:
# - Accepts character vectors with optional names (e.g., c("x" = "bad", "i" = "hint"))
# - Unnamed elements are assigned the provided default type (e.g., "!")
# - Non-character inputs are coerced to character
normalize_bullets <- function(msg, default_type = "!") {
  if (is.null(msg)) {
    return(character())
  }
  # Flatten one level if someone supplied list() of strings
  if (is.list(msg)) {
    # Flatten one level if someone supplied list() of strings
    msg <- unlist(msg, recursive = FALSE, use.names = TRUE)
  }
  # Preserve names across coercion to character (as.character() drops names)
  nm <- names(msg)
  if (!is.character(msg)) {
    msg <- as.character(msg)
    # Restore names if they were present prior to coercion
    if (!is.null(nm) && length(nm) == length(msg)) {
      names(msg) <- nm
    }
  }
  # Prepare names vector for bullet types
  nm <- names(msg)
  if (is.null(nm)) {
    nm <- rep_len("", length(msg))
  }
  # Fill empty or NA names with default bullet type
  nm[is.na(nm) | nm == ""] <- default_type
  stats::setNames(as.character(msg), nm)
}

# Specialized error constructors (complex) --------------------------------

# Compose an http error with structured condition and optional sanitized body
err_http <- function(msg, resp = NULL, context = list()) {
  trace_id <- gen_trace_id()
  expose <- isTRUE(allow_expose_error_body())
  status <- NA_integer_
  desc <- NULL
  url <- NULL
  body_snippet <- NULL
  if (!is.null(resp) && inherits(resp, "httr2_response")) {
    st <- try(httr2::resp_status(resp), silent = TRUE)
    status <- if (!inherits(st, "try-error") && length(st) == 1) {
      st
    } else {
      NA_integer_
    }
    desc <- try(httr2::resp_status_desc(resp), silent = TRUE)
    if (inherits(desc, "try-error")) {
      desc <- NULL
    }
    urlv <- try(httr2::resp_url(resp), silent = TRUE)
    url <- if (!inherits(urlv, "try-error") && length(urlv) == 1) urlv else NULL
    if (inherits(url, "try-error")) {
      url <- NULL
    }
    if (expose) {
      body_snippet <- try(httr2::resp_body_string(resp), silent = TRUE)
      if (!inherits(body_snippet, "try-error")) {
        body_snippet <- sanitize_body(body_snippet)
      } else {
        body_snippet <- NULL
      }
    }
  }
  # Compute non-sensitive body digest for debugging if available
  # and extract RFC 6749 §5.2 structured error fields when present
  body_digest <- NULL
  oauth_error <- NULL
  oauth_error_description <- NULL
  oauth_error_uri <- NULL
  if (!is.null(resp) && inherits(resp, "httr2_response")) {
    bs <- try(httr2::resp_body_string(resp), silent = TRUE)
    if (!inherits(bs, "try-error")) {
      dig <- try(openssl::sha256(charToRaw(bs)), silent = TRUE)
      if (!inherits(dig, "try-error")) {
        body_digest <- paste0(sprintf("%02x", as.integer(dig)), collapse = "")
      }
      # RFC 6749 §5.2: try to extract structured error fields from JSON body
      parsed <- try(
        jsonlite::fromJSON(bs, simplifyVector = TRUE),
        silent = TRUE
      )
      if (!inherits(parsed, "try-error") && is.list(parsed)) {
        if (is_valid_string(parsed[["error"]])) {
          oauth_error <- parsed[["error"]]
        }
        if (is_valid_string(parsed[["error_description"]])) {
          oauth_error_description <- parsed[["error_description"]]
        }
        if (is_valid_string(parsed[["error_uri"]])) {
          oauth_error_uri <- parsed[["error_uri"]]
        }
      }
    }
  }

  event <- c(
    list(
      type = "http_error",
      trace_id = trace_id,
      message = msg,
      status = status,
      url = url,
      body_digest = body_digest,
      oauth_error = oauth_error,
      oauth_error_description = oauth_error_description,
      oauth_error_uri = oauth_error_uri
    ),
    context
  )
  emit_trace_event(event)

  # Allow named bullets for msg and ensure subsequent lines are named bullets too
  bullets <- normalize_bullets(msg, default_type = "!")
  status_msg <- if (length(status) == 1 && !is.na(status)) {
    if (is_valid_string(desc)) {
      stats::setNames(paste0("Status ", status, ": ", desc, "."), "x")
    } else {
      stats::setNames(paste0("Status ", status, "."), "x")
    }
  } else {
    character()
  }
  # RFC 6749 §5.2: surface structured error fields from token endpoint
  oauth_error_msg <- if (!is.null(oauth_error)) {
    reason <- oauth_error
    if (!is.null(oauth_error_description)) {
      reason <- paste0(reason, ": ", oauth_error_description)
    }
    stats::setNames(paste0("OAuth error: ", reason), "x")
  } else {
    character()
  }
  oauth_error_uri_msg <- if (!is.null(oauth_error_uri)) {
    stats::setNames(paste0("Error URI: ", oauth_error_uri), "i")
  } else {
    character()
  }
  url_msg <- if (!is.null(url)) {
    stats::setNames(paste0("URL: ", url), "i")
  } else {
    character()
  }
  trace_msg <- c("i" = paste0("Trace ID: ", trace_id))
  body_msg <- if (expose && !is.null(body_snippet)) {
    stats::setNames(paste0("Body: ", body_snippet), "i")
  } else {
    character()
  }
  message <- c(
    format_header("HTTP request failed"),
    bullets,
    status_msg,
    oauth_error_msg,
    oauth_error_uri_msg,
    url_msg,
    trace_msg,
    body_msg
  )

  rlang::abort(
    message = message,
    class = c("shinyOAuth_http_error", "shinyOAuth_error"),
    trace_id = trace_id,
    status = status,
    url = url,
    body_digest = body_digest,
    oauth_error = oauth_error,
    oauth_error_description = oauth_error_description,
    oauth_error_uri = oauth_error_uri,
    context = context
  )
}

# Compose a transport error (no HTTP response available)
# Includes a trace id and chains the original error via `parent` when provided.
err_transport <- function(msg, context = list(), parent = NULL) {
  trace_id <- gen_trace_id()
  emit_trace_event(c(
    list(type = "transport_error", trace_id = trace_id, message = msg),
    context
  ))
  bullets <- normalize_bullets(msg, default_type = "!")
  message <- c(
    format_header("Transport failure"),
    bullets,
    "x" = "No HTTP response was received.",
    "i" = paste0("Trace ID: ", trace_id)
  )
  rlang::abort(
    message = message,
    class = c("shinyOAuth_transport_error", "shinyOAuth_error"),
    trace_id = trace_id,
    context = context,
    parent = parent
  )
}


# Specialized error constructors (basic) ---------------------------------------

err_invalid_state <- function(msg, context = list()) {
  err_abort(msg, class = "shinyOAuth_state_error", context = context)
}

err_pkce <- function(msg, context = list()) {
  err_abort(msg, class = "shinyOAuth_pkce_error", context = context)
}

err_token <- function(msg, context = list()) {
  err_abort(msg, class = "shinyOAuth_token_error", context = context)
}

err_id_token <- function(msg, context = list()) {
  err_abort(msg, class = "shinyOAuth_id_token_error", context = context)
}

err_userinfo <- function(msg, context = list()) {
  err_abort(msg, class = "shinyOAuth_userinfo_error", context = context)
}

err_userinfo_mismatch <- function(
  msg = "userinfo subject mismatch",
  context = list()
) {
  err_abort(msg, class = "shinyOAuth_userinfo_mismatch", context = context)
}

err_config <- function(msg, context = list()) {
  err_abort(msg, class = "shinyOAuth_config_error", context = context)
}

err_input <- function(msg, context = list()) {
  err_abort(msg, class = "shinyOAuth_input_error", context = context)
}

err_parse <- function(msg, context = list()) {
  err_abort(msg, class = "shinyOAuth_parse_error", context = context)
}


# Helpers -------------------------------------------------------------------

## Audit helpers ------------------------------------------------------------

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

# Broadcast audit events via the trace hook (if configured)
audit_event <- function(type, context = list(), shiny_session = NULL) {
  trace_id <- gen_trace_id()
  event <- c(
    list(
      type = paste0("audit_", type),
      trace_id = trace_id,
      timestamp = Sys.time()
    ),
    context
  )
  # Pre-inject shiny_session if provided (augment_with_shiny_context won't override)
  if (!is.null(shiny_session)) {
    event$shiny_session <- shiny_session
  }
  emit_trace_event(event)
  invisible(trace_id)
}

# Emit to: options(shinyOAuth.trace_hook = function(event){...})
emit_trace_event <- function(event) {
  hook <- getOption("shinyOAuth.trace_hook", NULL)
  audit_hook <- getOption("shinyOAuth.audit_hook", NULL)
  # Enrich with Shiny session/request context when running inside Shiny
  event <- tryCatch(augment_with_shiny_context(event), error = function(...) {
    event
  })
  if (is.function(hook)) {
    # Surface hook errors as warnings so they are visible in the main process
    # (async_dispatch captures warnings and replays them on the main thread).
    tryCatch(
      hook(event),
      error = function(e) {
        warning(
          "[shinyOAuth] trace_hook error: ",
          conditionMessage(e),
          call. = FALSE
        )
      }
    )
  }
  if (is.function(audit_hook)) {
    tryCatch(
      audit_hook(event),
      error = function(e) {
        warning(
          "[shinyOAuth] audit_hook error: ",
          conditionMessage(e),
          call. = FALSE
        )
      }
    )
  }
  invisible(NULL)
}


## Other helpers -----------------------------------------------------------

# Generate a short trace id for correlating errors in logs
gen_trace_id <- function() {
  tryCatch(random_urlsafe(12), error = function(e) {
    # Fallback if crypto fails
    paste0(as.integer(runif(3, 0, 1e6)), collapse = "-")
  })
}

# Sanitize potentially sensitive response bodies
sanitize_body <- function(body, max_chars = 200) {
  if (is.null(body) || is.na(body)) {
    return("")
  }
  body <- as.character(body)
  body <- gsub("\n|\r", " ", body)
  if (nchar(body, type = "bytes") > max_chars) {
    paste0(substr(body, 1, max_chars), "... [truncated]")
  } else {
    body
  }
}

# Optionally print error with traceback to console
# Controlled by options:
#   - options(shinyOAuth.print_errors = TRUE/FALSE)
#   - options(shinyOAuth.print_traceback = TRUE/FALSE)
log_condition <- function(e, context = list()) {
  # Do NOT coerce overrides with isTRUE() yet; we need NULL to mean "no override"
  print_errors_override <- allow_print_errors()
  print_traceback_override <- allow_print_traceback()

  # Effective flags: module override > global option > default
  pe <- if (!is.null(print_errors_override)) {
    isTRUE(print_errors_override)
  } else {
    isTRUE(getOption("shinyOAuth.print_errors", FALSE))
  }
  if (!pe) {
    return(invisible(NULL))
  }

  ptb <- if (!is.null(print_traceback_override)) {
    isTRUE(print_traceback_override)
  } else {
    isTRUE(getOption("shinyOAuth.print_traceback", FALSE))
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

      if (isTRUE(ptb)) {
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

print_compact_trace <- function(e) {
  if (!requireNamespace("rlang", quietly = TRUE)) {
    return(invisible(NULL))
  }
  bt <- if (inherits(e, "rlang_error") && !is.null(e$trace)) {
    e$trace
  } else {
    rlang::trace_back()
  }
  # Collapse parallel branches for readability using print() output
  lines <- utils::capture.output(print(bt, simplify = "branch"))

  # Hide noisy framework frames
  drop_pat <- paste(
    c(
      "^.*promises::",
      "^.*shiny::",
      "serviceApp\\(",
      "flush",
      "with_promise_domain",
      "wrapSync\\(",
      "captureStackTraces",
      "\\.domain\\$",
      "Reactive",
      "observeEvent"
    ),
    collapse = "|"
  )
  keep <- lines[!grepl(drop_pat, lines)]
  cat(paste(keep, collapse = "\n"), "\n", sep = "")
}
