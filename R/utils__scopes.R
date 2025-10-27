#' Validate OAuth 2.0 scope strings
#'
#' Validates that scope values contain only alphanumeric characters and safe
#' special characters. Per RFC 6749 section 3.3, scope tokens should use only
#' printable ASCII characters excluding double-quote and backslash, but in
#' practice most providers restrict to alphanumeric + safe punctuation.
#' This validator allows the common set `[A-Za-z0-9._:/-]` and also `*` and `+`
#' to accommodate providers that use wildcard or quantifier-like tokens.
#'
#' @param scopes Character vector of scope values
#'
#' @keywords internal
#' @noRd
validate_scopes <- function(scopes) {
  if (!is.character(scopes)) {
    err_input("scopes must be a character vector")
  }

  # Allow empty character vector (no scopes requested)
  if (length(scopes) == 0) {
    return(invisible(TRUE))
  }

  # Check each scope value
  for (i in seq_along(scopes)) {
    scope <- scopes[i]

    if (is.na(scope)) {
      err_input(paste0("scope[", i, "] is NA"))
    }

    if (!nzchar(scope)) {
      err_input(paste0("scope[", i, "] is empty"))
    }

    # RFC 6749 allows alphanumeric + safe chars (common practice: alphanumeric, dash, underscore, period, colon, slash)
    # We allow a slightly broader set including '*' and '+' to avoid false positives
    # for providers with wider scope grammars.
    if (!grepl("^[A-Za-z0-9._:/\\-*+]+$", scope, perl = TRUE)) {
      err_input(paste0(
        "scope[",
        i,
        "] contains invalid characters: '",
        scope,
        "' (only alphanumeric and ._:/- * + allowed)"
      ))
    }
  }

  invisible(TRUE)
}
