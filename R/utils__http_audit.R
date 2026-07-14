# This file contains helpers that turn raw HTTP request data into a safe
# summary for audit events
# Used for logging request context without leaking codes, tokens, cookies, or
# proxy details

# 1 HTTP audit helpers ---------------------------------------------------------

## 1.1 Build and sanitize HTTP summaries ---------------------------------------

# Functions in this subsection summarize request metadata and redact values
# that should not appear in audit events.

#' Build a safe HTTP audit summary
#'
#' Creates a compact request summary that is suitable for audit events, with
#' sensitive query parameters and headers sanitized by default. Used when audit
#' and telemetry events need browser request context. Redaction is enabled by
#' default and can be disabled with
#' `options(shinyOAuth.audit_redact_http = FALSE)`.
#'
#' @param req Request-like object.
#' @return Sanitized summary list, or `NULL`.
#' @keywords internal
#' @noRd
build_http_summary <- function(req) {
  if (is.null(req)) {
    return(NULL)
  }

  # Core request line/meta
  method <- .scalar_chr(tryCatch(
    req[["REQUEST_METHOD"]],
    error = function(...) {
      NULL
    }
  ))
  path <- .scalar_chr(tryCatch(req[["PATH_INFO"]], error = function(...) NULL))
  query_string <- .scalar_chr(tryCatch(
    req[["QUERY_STRING"]],
    error = function(...) {
      NULL
    }
  ))
  host <- .scalar_chr(tryCatch(req[["HTTP_HOST"]], error = function(...) NULL))
  scheme <- .scalar_chr(tryCatch(
    req[["HTTP_X_FORWARDED_PROTO"]],
    error = function(...) NULL
  ))
  if (!is_valid_string(scheme)) {
    # Try rook scheme when not behind proxy
    scheme <- .scalar_chr(tryCatch(
      req[["rook.url_scheme"]],
      error = function(...) NULL
    ))
  }
  # Remote address preference: X-Forwarded-For (first IP) else REMOTE_ADDR
  ra <- .scalar_chr(tryCatch(req[["REMOTE_ADDR"]], error = function(...) NULL))
  xff <- .scalar_chr(tryCatch(
    req[["HTTP_X_FORWARDED_FOR"]],
    error = function(...) {
      NULL
    }
  ))
  if (is_valid_string(xff)) {
    # If multiple comma-separated IPs, take the first hop
    ra <- strsplit(xff, ",", fixed = TRUE)[[1]]
    ra <- .scalar_chr(if (length(ra)) trimws(ra[[1]]) else NULL)
  }

  # Collect HTTP_* into headers list (JSON-friendly scalars)
  nms <- names(req)
  hdr_idx <- if (!is.null(nms)) grepl("^HTTP_", nms) else rep(FALSE, 0)
  hdrs <- list()
  if (length(hdr_idx) && any(hdr_idx)) {
    for (nm in nms[hdr_idx]) {
      key <- tolower(sub("^HTTP_", "", nm))
      val <- .scalar_chr(tryCatch(req[[nm]], error = function(...) NULL))
      hdrs[[key]] <- if (is_valid_string(val)) val else NULL
    }
    # Remove NULLs to keep JSON clean
    hdrs <- Filter(Negate(is.null), hdrs)
  }

  raw <- list(
    method = if (!is.na(method) && nzchar(method)) method else NULL,
    path = if (!is.na(path) && nzchar(path)) path else NULL,
    query_string = if (!is.na(query_string) && nzchar(query_string)) {
      query_string
    } else {
      NULL
    },
    host = if (!is.na(host) && nzchar(host)) host else NULL,
    scheme = if (!is.na(scheme) && nzchar(scheme)) scheme else NULL,
    remote_addr = if (!is.na(ra) && nzchar(ra)) ra else NULL,
    headers = if (length(hdrs)) hdrs else NULL
  )

  # Sanitize by default to prevent secret leakage in audit logs
  # Controlled by options(shinyOAuth.audit_redact_http = TRUE/FALSE)
  if (isTRUE(getOption("shinyOAuth.audit_redact_http", TRUE))) {
    sanitize_http_summary(raw)
  } else {
    raw
  }
}

#' Sanitize an HTTP audit summary
#'
#' Removes or redacts sensitive query parameters and headers before the summary
#' is logged or emitted in audit events. Used by `build_http_summary()`.
#'
#' @param summary HTTP summary list.
#' @return Sanitized summary list.
#' @keywords internal
#' @noRd
sanitize_http_summary <- function(summary) {
  if (is.null(summary)) {
    return(NULL)
  }

  # Redact sensitive query params from query_string
  if (
    !is.null(summary[["query_string"]]) && nzchar(summary[["query_string"]])
  ) {
    summary[["query_string"]] <- redact_query_string(summary[["query_string"]])
  }

  # Redact sensitive headers
  if (!is.null(summary[["headers"]]) && length(summary[["headers"]]) > 0) {
    summary[["headers"]] <- redact_headers(summary[["headers"]])
  }

  # Client IPs can be personal data; keep them out of sanitized audit events.
  if (!is.null(summary[["remote_addr"]]) && nzchar(summary[["remote_addr"]])) {
    summary[["remote_addr"]] <- "[REDACTED]"
  }

  summary
}

#' Redact sensitive OAuth query parameters
#'
#' Used by `sanitize_http_summary()`.
#'
#' @param qs Raw query string.
#' @return Redacted query string.
#' @keywords internal
#' @noRd
redact_query_string <- function(qs) {
  if (is.null(qs) || !nzchar(qs)) {
    return(qs)
  }

  # OAuth-related params that may contain secrets, assertions, signed request
  # objects, single-use request references, or user-identifying hints.
  sensitive_params <- c(
    "code",
    "state",
    "access_token",
    "refresh_token",
    "id_token",
    "token",
    "session_state",
    "code_verifier",
    "nonce",
    "client_secret",
    "client_assertion",
    "assertion",
    "request",
    "request_uri",
    "response",
    "shinyoauth_form_post",
    "shinyoauth_form_post_id",
    "claims",
    "login_hint",
    "error_description",
    "code_challenge",
    "username",
    "password"
  )

  # Parse query string into named list
  parsed <- tryCatch(
    url_query_parse(qs),
    error = function(...) NULL
  )

  if (is.null(parsed)) {
    return(redact_query_string_fallback(qs, sensitive_params))
  }

  if (length(parsed) == 0) {
    return(qs)
  }

  # Redact sensitive params (case-insensitive matching)
  param_names_lower <- tolower(names(parsed))
  for (i in seq_along(parsed)) {
    if (param_names_lower[[i]] %in% sensitive_params) {
      n <- length(parsed[[i]])
      parsed[[i]] <- if (is.null(n) || n == 0) {
        "[REDACTED]"
      } else {
        rep("[REDACTED]", n)
      }
    }
  }

  # Rebuild query string
  # Use paste manually to preserve format (httr2 doesn't have a rebuild function)
  if (length(parsed) == 0) {
    return("")
  }
  nms <- names(parsed)
  parts <- unlist(
    lapply(seq_along(parsed), function(i) {
      nm <- nms[[i]]
      val <- parsed[[i]]

      if (is.null(val) || length(val) == 0) {
        return(nm)
      }

      val_chr <- as.character(val)
      val_chr[is.na(val_chr)] <- ""
      paste0(nm, "=", utils::URLencode(val_chr, reserved = TRUE))
    }),
    use.names = FALSE
  )
  paste(parts, collapse = "&")
}

#' Redact query-string segments without parsing
#'
#' Used by `redact_query_string()` when the query parser rejects the raw string
#' but the original `key=value` segments can still be inspected safely enough to
#' hide known OAuth secrets.
#'
#' @param qs Raw query string.
#' @param sensitive_params Lower-cased parameter names to redact.
#' @return Redacted query string.
#' @keywords internal
#' @noRd
redact_query_string_fallback <- function(qs, sensitive_params) {
  parts <- strsplit(qs, "&", fixed = TRUE)[[1]]
  if (length(parts) == 0L) {
    return(qs)
  }

  parts <- vapply(
    parts,
    function(part) {
      if (!nzchar(part)) {
        return(part)
      }

      eq_pos <- regexpr("=", part, fixed = TRUE)[[1]]
      if (eq_pos < 0L) {
        param_name <- part
        has_value <- FALSE
      } else {
        param_name <- substr(part, 1L, eq_pos - 1L)
        has_value <- TRUE
      }

      if (!(tolower(param_name) %in% sensitive_params)) {
        return(part)
      }

      if (!has_value) {
        return(param_name)
      }

      paste0(param_name, "=[REDACTED]")
    },
    character(1),
    USE.NAMES = FALSE
  )

  paste(parts, collapse = "&")
}

#' Redact sensitive HTTP headers
#'
#' Used by `sanitize_http_summary()`.
#'
#' @param hdrs Named headers list.
#' @return Sanitized headers list.
#' @keywords internal
#' @noRd
redact_headers <- function(hdrs) {
  if (is.null(hdrs) || length(hdrs) == 0) {
    return(hdrs)
  }

  # Headers to completely remove (contain secrets or tokens)
  remove_headers <- c(
    "cookie",
    "set_cookie",
    "authorization",
    "proxy_authorization",
    "proxy_authenticate",
    "www_authenticate"
  )

  # Headers to redact (contain potentially sensitive routing/client info)
  # x_* headers often contain internal infrastructure details
  redact_prefixes <- c(
    "x_"
  )

  nms <- names(hdrs)
  nms_lower <- tolower(nms)

  # Build a new list to avoid modifying during iteration
  result <- list()
  for (i in seq_along(hdrs)) {
    nm <- nms[[i]]
    nm_lower <- nms_lower[[i]]

    # Skip headers that should be removed
    if (nm_lower %in% remove_headers) {
      next
    }

    # Check if header should be redacted by prefix
    should_redact <- FALSE
    for (prefix in redact_prefixes) {
      if (startsWith(nm_lower, prefix)) {
        should_redact <- TRUE
        break
      }
    }

    if (should_redact) {
      result[[nm]] <- "[REDACTED]"
    } else {
      result[[nm]] <- hdrs[[i]]
    }
  }

  result
}
