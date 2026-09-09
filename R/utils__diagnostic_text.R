#' Sanitize opt-in diagnostic text
#'
#' Removes URL credentials and control characters and bounds exported detail.
#' @param value Character diagnostic, optionally a bullet vector.
#' @param max_bytes Maximum UTF-8 bytes retained.
#' @return One sanitized string, or `NULL` for invalid input.
#' @keywords internal
#' @noRd
sanitize_diagnostic_text <- function(value, max_bytes = 512L) {
  if (!is.character(value) || !length(value) || anyNA(value)) {
    return(NULL)
  }
  value <- paste(enc2utf8(value), collapse = " ")
  if (!validUTF8(value)) {
    return(NULL)
  }
  urls <- gregexpr(
    "[A-Za-z][A-Za-z0-9+.-]*://[^[:space:]<>\"']+",
    value,
    perl = TRUE
  )
  matches <- regmatches(value, urls)[[1L]]
  if (length(matches)) {
    regmatches(value, urls) <- list(vapply(
      matches,
      function(url) {
        otel_http_url_full(url) %||% "[invalid URL]"
      },
      character(1)
    ))
  }
  value <- gsub("[[:cntrl:]\\p{Cf}]", " ", value, perl = TRUE)
  value <- substr(value, 1L, max_bytes)
  while (nchar(value, type = "bytes") > max_bytes) {
    value <- substr(value, 1L, nchar(value) - 1L)
  }
  value
}

#' Apply diagnostic exposure policy to event fields
#'
#' Shared by native hooks and direct OpenTelemetry calls, including nested
#' exception contexts. Free-form detail requires explicit exposure permission.
#' @param event Event or nested context.
#' @return Event with detail omitted or sanitized.
#' @keywords internal
#' @noRd
sanitize_event_diagnostics <- function(event) {
  if (!is.list(event)) {
    return(event)
  }
  detail_fields <- c(
    "message",
    "error_message",
    "metadata_error",
    "transport_error",
    "oauth_error_description",
    "error_description",
    "body",
    "body_snippet",
    "exception.message"
  )
  for (i in seq_along(event)) {
    field <- names(event)[i] %||% ""
    if (field %in% detail_fields) {
      event[i] <- list(
        if (allow_expose_error_body()) {
          sanitize_diagnostic_text(event[[i]])
        } else {
          NULL
        }
      )
    } else if (is.list(event[[i]])) {
      event[i] <- list(sanitize_event_diagnostics(event[[i]]))
    }
  }
  event
}

# Retain classification without the original condition's calls, request/response
# fields, backtrace, or parent chain. Even opt-in messages use URL redaction.
sanitize_condition_parent <- function(parent) {
  if (is.null(parent)) {
    return(NULL)
  }
  message <- if (allow_expose_error_body()) {
    sanitize_diagnostic_text(conditionMessage(parent))
  } else {
    NULL
  }
  rlang::error_cnd(
    class = setdiff(class(parent), c("error", "condition")),
    message = message %||% "Underlying diagnostic withheld",
    call = NULL
  )
}

#' Check OAuth error text syntax
#'
#' Implements the printable ASCII grammar of RFC 6749 Appendix A.7 and A.8.
#' @param value Candidate error or error description.
#' @return Whether the value obeys the OAuth error text grammar.
#' @keywords internal
#' @noRd
is_oauth_error_text <- function(value) {
  is.character(value) &&
    length(value) == 1L &&
    !is.na(value) &&
    isTRUE(grepl("^[\\x20-\\x21\\x23-\\x5B\\x5D-\\x7E]*$", value, perl = TRUE))
}

#' Escape diagnostic text for CLI formatting
#'
#' Keeps untrusted braces literal when a diagnostic becomes a condition bullet.
#' @param value Sanitized text.
#' @return Text with literal braces escaped.
#' @keywords internal
#' @noRd
escape_diagnostic_markup <- function(value) {
  gsub("}", "}}", gsub("{", "{{", value, fixed = TRUE), fixed = TRUE)
}
# Keep received protocol values out of ordinary conditions. Explicit exposure
# adds bounded literal data; condition constructors never interpolate it.
protocol_diagnostic_message <- function(message, received) {
  if (!allow_expose_error_body()) {
    return(message)
  }
  value <- as.character(jsonlite::toJSON(
    received,
    auto_unbox = TRUE,
    null = "null"
  ))
  c("x" = message, "i" = paste0("Received: ", sanitize_diagnostic_text(value)))
}
