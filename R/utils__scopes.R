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

  # Check each scope value.
  # Allow (and split) space-delimited scope strings, since user code may pass
  # scopes = "openid profile" as a single value.
  for (i in seq_along(scopes)) {
    scope <- scopes[i]

    if (is.na(scope)) {
      err_input(paste0("scope[", i, "] is NA"))
    }

    if (!nzchar(scope)) {
      err_input(paste0("scope[", i, "] is empty"))
    }

    tokens <- unlist(strsplit(scope, "\\s+"), use.names = FALSE)
    tokens <- tokens[nzchar(tokens)]
    if (length(tokens) == 0L) {
      err_input(paste0("scope[", i, "] is empty"))
    }

    for (token in tokens) {
      # RFC 6749 allows alphanumeric + safe chars (common practice: alphanumeric, dash, underscore, period, colon, slash)
      # We allow a slightly broader set including '*' and '+' to avoid false positives
      # for providers with wider scope grammars.
      if (!grepl("^[A-Za-z0-9._:/\\-*+]+$", token, perl = TRUE)) {
        err_input(paste0(
          "scope[",
          i,
          "] contains invalid characters: '",
          token,
          "' (only alphanumeric and ._:/- * + allowed)"
        ))
      }
    }
  }

  invisible(TRUE)
}

#' Coerce scope input into scope tokens
#'
#' Accepts scopes in a few common shapes (NULL, character vector, list) and
#' returns a character vector of individual scope tokens.
#'
#' Rationale: while OAuth scope tokens cannot contain whitespace, user code may
#' accidentally provide a single space-delimited string (e.g. "openid profile").
#' This helper makes internal comparisons robust by splitting on whitespace.
#'
#' @param scopes NULL, character, or list-like scope values
#'
#' @keywords internal
#' @noRd
as_scope_tokens <- function(scopes) {
  if (is.null(scopes)) {
    return(character())
  }

  if (is.list(scopes)) {
    scopes <- unlist(scopes, recursive = TRUE, use.names = FALSE)
  }

  scopes <- as.character(scopes)
  scopes <- scopes[!is.na(scopes)]
  if (length(scopes) == 0L) {
    return(character())
  }

  tokens <- unlist(strsplit(scopes, "\\s+"), use.names = FALSE)
  tokens <- tokens[nzchar(tokens)]
  tokens
}
