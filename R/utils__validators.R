# This file contains small validation and coercion helpers shared across many
# other files
# Used for common checks such as string validity, cookie-path safety, and
# callback query size limits

# 1 Shared validators ----------------------------------------------------------

## 1.1 Common list, string, and query checks -----------------------------------

#' Internal: drop NULL/NA values from a list (for query building)
#'
#' @param x List-like input to filter.
#' @return `x` with `NULL` values and scalar `NA` entries removed, or `x`
#'   unchanged when it is not a list.
#' @keywords internal
#' @noRd
compact_list <- function(x) {
  if (!is.list(x)) {
    return(x)
  }
  x[
    !vapply(
      x,
      function(v) is.null(v) || (length(v) == 1 && is.na(v)),
      logical(1)
    )
  ]
}

#' Internal: check if input is a non-empty string
#'
#' @param x Value to check.
#' @param min_char Minimum allowed character count.
#' @return `TRUE` when `x` is a single non-empty string meeting the minimum
#'   length; otherwise `FALSE`.
#' @keywords internal
#' @noRd
is_valid_string <- function(x, min_char = 1) {
  is.character(x) &&
    length(x) == 1 &&
    !is.na(x) &&
    nzchar(x) &&
    nchar(x) >= min_char
}

#' Internal: validate cookie Path attribute input
#'
#' Accepts only RFC 6265-safe path values for explicit cookie Path attributes:
#' must start with `/` and must not contain semicolons or control characters.
#'
#' @param x Cookie path candidate.
#' @return `TRUE` when `x` is a valid cookie-path value; otherwise `FALSE`.
#' @keywords internal
#' @noRd
is_valid_cookie_path <- function(x) {
  if (!is_valid_string(x)) {
    return(FALSE)
  }

  starts_with_slash <- startsWith(x, "/")
  has_semicolon <- grepl(";", x, fixed = TRUE)
  has_ctl <- grepl("[[:cntrl:]]", x)

  isTRUE(starts_with_slash) && !isTRUE(has_semicolon) && !isTRUE(has_ctl)
}

#' Internal: validate untrusted scalar query param sizes
#'
#' This helper is used for values that originate from URL query strings.
#' It is intentionally strict about scalar-ness to avoid vector amplification.
#'
#' @param name Query-parameter name used in error messages.
#' @param value Query-parameter value to validate.
#' @param max_bytes Maximum allowed size in bytes.
#' @param allow_empty Whether empty strings are allowed.
#' @return Invisibly returns `NULL` on success. Otherwise this function raises a
#'   state error.
#' @keywords internal
#' @noRd
validate_untrusted_query_param <- function(
  name,
  value,
  max_bytes,
  allow_empty = FALSE
) {
  if (is.null(value)) {
    return(invisible(NULL))
  }

  if (!is.character(value) || length(value) != 1L || is.na(value)) {
    err_invalid_state(
      sprintf("Callback query parameter '%s' must be a single string", name),
      context = list(param = name)
    )
  }

  if (!isTRUE(allow_empty) && !nzchar(value)) {
    err_invalid_state(
      sprintf("Callback query parameter '%s' must be non-empty", name),
      context = list(param = name)
    )
  }

  max_bytes <- as.numeric(max_bytes)
  if (!is.finite(max_bytes) || is.na(max_bytes) || max_bytes <= 0) {
    err_invalid_state(
      "Internal error: invalid max_bytes in query param validator",
      context = list(param = name)
    )
  }

  actual_bytes <- nchar(value, type = "bytes")
  if (!is.finite(actual_bytes) || is.na(actual_bytes)) {
    err_invalid_state(
      sprintf("Callback query parameter '%s' had invalid length", name),
      context = list(param = name)
    )
  }

  if (actual_bytes > max_bytes) {
    err_invalid_state(
      sprintf(
        "Callback query parameter '%s' exceeded maximum length (%s bytes)",
        name,
        format(max_bytes, scientific = FALSE, trim = TRUE)
      ),
      context = list(
        param = name,
        max_bytes = max_bytes,
        actual_bytes = actual_bytes
      )
    )
  }

  invisible(NULL)
}

#' Internal: validate untrusted callback query string sizes
#'
#' This helper guards against extremely large callback query strings causing
#' substantial allocation during parsing.
#'
#' @param query_string Raw callback query string.
#' @param max_bytes Maximum allowed size in bytes.
#' @return Invisibly returns `NULL` on success. Otherwise this function raises a
#'   state error.
#' @keywords internal
#' @noRd
validate_untrusted_query_string <- function(query_string, max_bytes) {
  if (is.null(query_string)) {
    return(invisible(NULL))
  }

  if (
    !is.character(query_string) ||
      length(query_string) != 1L ||
      is.na(query_string)
  ) {
    err_invalid_state(
      "Callback query string must be a single string",
      context = list(component = "query_string")
    )
  }

  max_bytes <- as.numeric(max_bytes)
  if (!is.finite(max_bytes) || is.na(max_bytes) || max_bytes <= 0) {
    err_invalid_state(
      "Internal error: invalid max_bytes in query string validator",
      context = list(component = "query_string")
    )
  }

  actual_bytes <- nchar(query_string, type = "bytes")
  if (!is.finite(actual_bytes) || is.na(actual_bytes)) {
    err_invalid_state(
      "Callback query string had invalid length",
      context = list(component = "query_string")
    )
  }

  if (actual_bytes > max_bytes) {
    err_invalid_state(
      sprintf(
        "Callback query string exceeded maximum length (%s bytes)",
        format(max_bytes, scientific = FALSE, trim = TRUE)
      ),
      context = list(
        component = "query_string",
        max_bytes = max_bytes,
        actual_bytes = actual_bytes
      )
    )
  }

  invisible(NULL)
}

#' Safely coerce one value to a scalar character string
#'
#' @param x Value to coerce.
#' @return Scalar character value, or `NA_character_`.
#' @keywords internal
#' @noRd
.scalar_chr <- function(x) {
  if (is.null(x) || length(x) == 0) {
    return(NA_character_)
  }
  as.character(x[[1]])
}
