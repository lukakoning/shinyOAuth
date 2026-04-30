# This file contains small helpers that normalize or inspect OAuth parameter
# values before they are used in requests or provider validation.
# Use them to keep token auth style, PKCE, and response-mode handling
# consistent across constructors and request builders.

# 1 OAuth parameter helpers ------------------------------------------------

## 1.1 Normalize protocol parameters --------------------------------------

#' Internal: normalize token endpoint auth style names
#'
#' Canonical runtime spelling uses `public` for secretless public-client token
#' requests. `none` is accepted as an alias to mirror OIDC discovery metadata.
#'
#' @keywords internal
#' @noRd
normalize_token_auth_style <- function(style) {
  if (!is.character(style) || length(style) != 1L || is.na(style)) {
    return(style)
  }

  normalized <- tolower(trimws(style))

  if (identical(normalized, "none")) {
    return("public")
  }

  if (
    normalized %in%
      c(
        "header",
        "body",
        "public",
        "tls_client_auth",
        "self_signed_tls_client_auth",
        "client_secret_jwt",
        "private_key_jwt"
      )
  ) {
    return(normalized)
  }

  style
}

#' Internal: normalize PKCE method names without silently accepting typos
#'
#' @keywords internal
#' @noRd
normalize_pkce_method <- function(pkce_method, default = NULL) {
  if (is.null(pkce_method)) {
    return(default)
  }

  if (
    is.character(pkce_method) && length(pkce_method) == 1L && is.na(pkce_method)
  ) {
    return(default)
  }

  if (!is.character(pkce_method) || length(pkce_method) != 1L) {
    return(pkce_method)
  }

  normalized <- trimws(pkce_method)
  if (identical(toupper(normalized), "S256")) {
    return("S256")
  }
  if (identical(tolower(normalized), "plain")) {
    return("plain")
  }

  pkce_method
}

# Inspect the configured authorization response_mode and reject unsupported
# values early.
# Used by provider validation and constructors. Input: extra_auth_params list.
# Output: list with index, resolved mode, and optional error.
inspect_auth_response_mode <- function(extra_auth_params) {
  out <- list(index = integer(0), mode = NULL, error = NULL)

  if (!is.list(extra_auth_params) || length(extra_auth_params) == 0) {
    return(out)
  }

  nms <- names(extra_auth_params)
  if (is.null(nms)) {
    return(out)
  }

  idx <- which(tolower(trimws(nms)) == "response_mode")
  if (!length(idx)) {
    return(out)
  }
  if (length(idx) > 1L) {
    out$error <- paste0(
      "OAuthProvider: extra_auth_params$response_mode must be supplied at most once"
    )
    return(out)
  }

  out$index <- idx[[1]]
  raw_mode <- extra_auth_params[[out$index]]
  if (
    !is.character(raw_mode) ||
      length(raw_mode) != 1L ||
      is.na(raw_mode) ||
      !nzchar(trimws(raw_mode))
  ) {
    out$error <- paste0(
      "OAuthProvider: extra_auth_params$response_mode must be a single non-empty string"
    )
    return(out)
  }

  mode <- tolower(trimws(raw_mode))
  if (!identical(mode, "query")) {
    out$error <- paste0(
      "OAuthProvider: extra_auth_params$response_mode = ",
      sQuote(raw_mode),
      " is not supported. shinyOAuth only supports the default 'query' response mode because plain Shiny callback URLs do not accept POST form callbacks."
    )
    return(out)
  }

  out$mode <- mode
  out
}
