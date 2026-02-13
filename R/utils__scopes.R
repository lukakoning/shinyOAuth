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

#' Ensure openid scope for OIDC providers
#'
#' Per OIDC Core section 1.2.1, OpenID Connect requests MUST contain the
#' `openid` scope value. When the provider has an `issuer` set (indicating
#' OIDC), this helper checks for the `openid` scope and auto-prepends it with
#' a one-time warning if missing.
#'
#' @param scopes Character vector of scope tokens.
#' @param provider An [OAuthProvider] object.
#'
#' @return Character vector of scope tokens, possibly with `"openid"` prepended.
#'
#' @keywords internal
#' @noRd
ensure_openid_scope <- function(scopes, provider) {
  # Only applies to OIDC providers (those with an issuer)
  if (!is_valid_string(provider@issuer)) {
    return(scopes)
  }

  # Normalize to individual tokens so that a single space-delimited string
  # like "openid profile" is correctly recognised by the %in% check below.
  scopes <- as_scope_tokens(scopes)

  # Already present — nothing to do
  if ("openid" %in% scopes) {
    return(scopes)
  }

  rlang::warn(
    c(
      "[{.pkg shinyOAuth}] - {.strong Missing `openid` scope for OIDC provider}",
      "!" = "Provider {.val {provider@name}} has an issuer set, indicating OIDC, but {.val openid} was not in the requested scopes.",
      "i" = "Auto-prepending {.val openid} to scopes per OIDC Core \u00a73.1.2.1.",
      "i" = "Add {.val openid} to your {.code oauth_client(scopes = ...)} to silence this warning."
    ),
    .frequency = "once",
    .frequency_id = "shinyOAuth_missing_openid_scope"
  )

  c("openid", scopes)
}
