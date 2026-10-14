#' Validate HTTP header syntax without exposing header content
#'
#' Shared by request builders and configuration validators. HTTP field names
#' use RFC 9110 token grammar; values may contain horizontal tabs but no other
#' ASCII controls. Removal values are permitted only at request-shaping inputs.
#'
#' @param headers Named character vector or list of atomic header values.
#' @param allow_removal Whether NULL list values may remove a header.
#' @return A diagnostic string, or NULL for valid headers.
#' @keywords internal
#' @noRd
http_headers_problem <- function(headers, allow_removal = FALSE) {
  if (is.null(headers) || length(headers) == 0L) {
    return(NULL)
  }
  if (!is.list(headers) && !is.character(headers)) {
    return("HTTP headers must be a named list or named character vector")
  }
  field_names <- names(headers)
  if (
    is.null(field_names) || anyNA(field_names) ||
      !all(grepl("^[!#$%&'*+.^_`|~0-9A-Za-z-]+$", field_names))
  ) {
    return("HTTP header names must use valid field-name token syntax")
  }
  if (anyDuplicated(tolower(field_names))) {
    return("HTTP header names must be unique ignoring case")
  }
  for (value in headers) {
    if (is.null(value) && isTRUE(allow_removal)) {
      next
    }
    # httr2 stores redacted headers as weak references. Inspect their values
    # locally without replacing the protected representation on the request.
    if (rlang::is_weakref(value)) {
      value <- rlang::wref_value(value)
    }
    if (!is.atomic(value) || !length(value) || anyNA(value)) {
      return("HTTP header values must be non-missing atomic values (no NA)")
    }
    value <- as.character(value)
    if (any(grepl("[\\x00-\\x08\\x0a-\\x1f\\x7f]", value, perl = TRUE))) {
      return("HTTP header values must not contain prohibited control characters")
    }
  }
  NULL
}

#' Assert HTTP header syntax before attaching credentials
#'
#' @param headers Named character vector or list of atomic header values.
#' @param allow_removal Whether NULL list values may remove a header.
#' @return Invisibly returns NULL on success; otherwise raises an input error.
#' @keywords internal
#' @noRd
validate_http_headers <- function(headers, allow_removal = FALSE) {
  problem <- http_headers_problem(headers, allow_removal)
  if (!is.null(problem)) {
    err_input(problem)
  }
  invisible(NULL)
}

#' Validate explicit and body-generated HTTP headers
#'
#' @param req An httr2 request.
#' @return Invisibly returns NULL on success; otherwise raises an input error.
#' @keywords internal
#' @noRd
validate_http_request_headers <- function(req) {
  validate_http_headers(req[["headers"]], allow_removal = TRUE)
  content_type <- req[["body"]][["content_type"]]
  if (!is.null(content_type)) {
    validate_http_headers(list(`Content-Type` = content_type))
  }
  invisible(NULL)
}
