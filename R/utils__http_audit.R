# This file contains helpers that turn raw HTTP request data into a safe summary
# for audit events.
# Use them when request context should be logged or traced without leaking OAuth
# codes, tokens, cookies, or proxy details.

# 1 HTTP audit helpers -----------------------------------------------------

## 1.1 Build and sanitize HTTP summaries ----------------------------------

# Internal: derive a compact, JSON-serializable HTTP summary from a request
#
# The returned summary is sanitized by default to prevent secret leakage in
# audit logs. Sensitive OAuth query params (code, state, access_token, etc.)
# and headers (Cookie, Authorization, x-* proxy headers) are redacted.
#
# Control via: options(shinyOAuth.audit_redact_http = FALSE) to disable.
#
# See sanitize_http_summary() for the redaction logic.
# Build a compact HTTP summary that is safe to include in audit events.
# Used by Shiny context capture and event helpers. Input: request-like object.
# Output: sanitized summary list or NULL.
build_http_summary <- function(req) {
  if (is.null(req)) {
    return(NULL)
  }

  # Core request line/meta
  method <- .scalar_chr(tryCatch(req$REQUEST_METHOD, error = function(...) {
    NULL
  }))
  path <- .scalar_chr(tryCatch(req$PATH_INFO, error = function(...) NULL))
  query_string <- .scalar_chr(tryCatch(req$QUERY_STRING, error = function(...) {
    NULL
  }))
  host <- .scalar_chr(tryCatch(req$HTTP_HOST, error = function(...) NULL))
  scheme <- .scalar_chr(tryCatch(
    req$HTTP_X_FORWARDED_PROTO,
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
  ra <- .scalar_chr(tryCatch(req$REMOTE_ADDR, error = function(...) NULL))
  xff <- .scalar_chr(tryCatch(req$HTTP_X_FORWARDED_FOR, error = function(...) {
    NULL
  }))
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

# Redact sensitive query and header values in an HTTP summary.
# Used by build_http_summary(). Input: summary list. Output: sanitized summary
# list.
# Internal: redact sensitive data from HTTP summary for safe audit logging
#
# This function removes or redacts:
# - OAuth-related query params: code, state, access_token, refresh_token, id_token
# - Sensitive headers: cookie, authorization, set_cookie, x_* (proxy headers)
#
# Called automatically by build_http_summary() to make audit logging safe by default.
sanitize_http_summary <- function(summary) {
  if (is.null(summary)) {
    return(NULL)
  }

  # Redact sensitive query params from query_string
  if (!is.null(summary$query_string) && nzchar(summary$query_string)) {
    summary$query_string <- redact_query_string(summary$query_string)
  }

  # Redact sensitive headers
  if (!is.null(summary$headers) && length(summary$headers) > 0) {
    summary$headers <- redact_headers(summary$headers)
  }

  summary
}

# Redact sensitive OAuth parameters from a raw query string.
# Used by sanitize_http_summary(). Input: query string. Output: redacted query
# string.
# Internal: redact sensitive OAuth params from a query string
# Returns the redacted query string
redact_query_string <- function(qs) {
  if (is.null(qs) || !nzchar(qs)) {
    return(qs)
  }

  # OAuth-related params that may contain secrets or single-use tokens
  sensitive_params <- c(
    "code",
    "state",
    "access_token",
    "refresh_token",
    "id_token",
    "token",
    "session_state",
    "code_verifier",
    "nonce"
  )

  # Parse query string into named list
  parsed <- tryCatch(
    httr2::url_query_parse(qs),
    error = function(...) NULL
  )

  if (is.null(parsed) || length(parsed) == 0) {
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

# Remove or redact sensitive headers before audit logging.
# Used by sanitize_http_summary(). Input: named headers list. Output: sanitized
# headers list.
# Internal: redact sensitive headers from a headers list
# Returns the redacted headers list
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
