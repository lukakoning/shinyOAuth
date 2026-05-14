# This file contains helpers that normalize, validate, and finalize OAuth or
# OIDC scope values
# Scopes are the named permissions or identity fields a client asks for
# Used for turning user input into one clean scope vector for requests and
# later validation

# 1 Scope helpers --------------------------------------------------------------

## 1.1 Normalize and validate scopes -------------------------------------------

#' Validate OAuth 2.0 scope strings
#'
#' Validates that scope values conform to the RFC 6749 §3.3 scope-token
#' grammar: `scope-token = 1*NQSCHAR` where `NQSCHAR = %x21 / %x23-5B /
#' %x5D-7E`. In plain terms, every printable ASCII character is allowed
#' except space (used as the scope-list delimiter), double-quote (`"`), and
#' backslash (`\`).
#'
#' @param scopes Character vector of scope values
#' @return Invisibly returns `TRUE` when all scopes are valid. Otherwise this
#'   function raises an input error.
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
      # RFC 6749 §3.3 NQSCHAR: %x21 / %x23-5B / %x5D-7E
      # i.e. all printable ASCII except SP (%x20), '"' (%x22), '\' (%x5C).
      if (!grepl("^[!#-\\[\\]-~]+$", token, perl = TRUE)) {
        err_input(paste0(
          "scope[",
          i,
          "] contains invalid characters: '",
          token,
          "' (RFC 6749 allows printable ASCII except space, ",
          '\"',
          ", and \\)"
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
#' @return Character vector of individual scope tokens.
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

#' Normalize scope tokens for storage and comparison
#'
#' Coerces scope input to individual tokens, drops empty entries, removes
#' duplicates, and sorts the result so later comparisons stay deterministic.
#'
#' @param scopes NULL, character, or list-like scope values.
#' @return Character vector of normalized scope tokens.
#' @keywords internal
#' @noRd
normalize_scope_tokens <- function(scopes) {
  tokens <- as_scope_tokens(scopes)
  tokens <- tokens[nzchar(tokens)]
  if (!length(tokens)) {
    return(character(0))
  }

  sort(unique(tokens))
}

#' Resolve the granted-scope state for a token response
#'
#' Derives the best-known granted scopes for a token response and whether those
#' scopes were explicitly proven by the current response. Refresh responses that
#' omit `scope` carry forward the prior grant when available.
#'
#' @param token_scope Raw `scope` value from the current token response.
#' @param requested_scopes Normalized scopes requested for this flow.
#' @param is_refresh Whether the current response came from a refresh flow.
#' @param previous_granted_scopes Previously stored granted scopes to carry
#'   forward when a refresh response omits `scope`.
#' @return A list containing normalized `granted_scopes`, logical
#'   `granted_scopes_verified`, and booleans `scope_is_omitted` /
#'   `scope_is_empty`.
#' @keywords internal
#' @noRd
resolve_granted_scope_state <- function(
  token_scope,
  requested_scopes,
  is_refresh = FALSE,
  previous_granted_scopes = NULL
) {
  requested_scopes <- normalize_scope_tokens(requested_scopes)
  previous_granted_scopes <- normalize_scope_tokens(previous_granted_scopes)

  scope_is_omitted <- is.null(token_scope)
  scope_is_empty <- !scope_is_omitted &&
    length(token_scope) == 1L &&
    !nzchar(token_scope)
  explicit_scope <- !scope_is_omitted &&
    !(isTRUE(is_refresh) && scope_is_empty)

  granted_scopes <- if (isTRUE(explicit_scope)) {
    normalize_scope_tokens(token_scope)
  } else if (isTRUE(is_refresh) && length(previous_granted_scopes) > 0) {
    previous_granted_scopes
  } else {
    requested_scopes
  }

  list(
    granted_scopes = granted_scopes,
    granted_scopes_verified = isTRUE(explicit_scope),
    scope_is_omitted = scope_is_omitted,
    scope_is_empty = scope_is_empty
  )
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

  provider_name <- provider@name %||% "(unnamed)"

  warn_pkg(
    "Missing `openid` scope for OIDC provider",
    c(
      "!" = paste0(
        "Provider ",
        provider_name,
        " has an issuer set, indicating OIDC, but {.val openid} was not in the requested scopes."
      ),
      "i" = "Auto-prepending {.val openid} to scopes per OIDC Core \u00a73.1.2.1.",
      "i" = "Add {.val openid} to your {.code oauth_client(scopes = ...)} to silence this warning."
    ),
    .frequency = "once",
    .frequency_id = "shinyOAuth_missing_openid_scope"
  )

  c("openid", scopes)
}

#' Resolve effective requested scopes for an OAuth client
#'
#' For OIDC providers this includes an auto-prepended `openid` scope when the
#' caller omitted it.
#'
#' @param client An [OAuthClient] object.
#'
#' @return Character vector of scope tokens used in the authorization request.
#'
#' @keywords internal
#' @noRd
effective_client_scopes <- function(client) {
  S7::check_is_S7(client, class = OAuthClient)

  ensure_openid_scope(client@scopes, client@provider)
}
