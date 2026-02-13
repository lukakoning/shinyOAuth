# Some helpers which determine if certain safety checks can be skipped
#   in testing or interactive sessions, based on options
# Options are hard-gated on option + testing/interactive to avoid accidental
#   use in production

#' Throw an error if any safety checks have been disabled
#'
#' @description
#' This function checks if any safety checks have been disabled via options
#' intended for local development use only. If any such options are detected,
#' an error is thrown to prevent accidental use in production environments.
#'
#' @details It checks for the following options:
#' \itemize{
#'  \item `shinyOAuth.skip_browser_token`: Skips browser cookie presence check
#'  \item `shinyOAuth.skip_id_sig`: Skips ID token signature verification
#'  \item `shinyOAuth.print_errors`: Enables printing of error messages
#'  \item `shinyOAuth.print_traceback`: Enables printing of tracebacks (opt-in only; default FALSE)
#'  \item `shinyOAuth.expose_error_body`: Exposes HTTP response bodies
#'  \item `shinyOAuth.allow_unsigned_userinfo_jwt`: Accepts unsigned (`alg=none`) UserInfo JWTs
#'  \item `shinyOAuth.allow_redirect`: Disables anti-redirect protections for sensitive HTTP flows
#'  }
#'
#' Note: Tracebacks are only treated as a "softened" behavior when the
#' `shinyOAuth.print_traceback` option is explicitly set to `TRUE`.
#' The default is `FALSE`, even in interactive or test sessions.
#'
#' @return Invisible TRUE if no safety checks are disabled; otherwise, an error is thrown.
#'
#' @example inst/examples/error_on_softened.R
#' @export
error_on_softened <- function() {
  if (
    any(
      allow_skip_browser_token(),
      allow_skip_signature(),
      allow_print_errors(),
      allow_print_traceback(),
      allow_expose_error_body(),
      allow_unsigned_userinfo_jwt(),
      allow_redirect()
    )
  ) {
    rlang::abort(
      c(
        "One or more safety settings have been disabled",
        "x" = "These settings are only intended for testing & local (interactive) development",
        "i" = "See `?error_on_softened` for more information"
      )
    )
  }

  return(invisible(TRUE))
}

allow_skip_browser_token <- function() {
  if (!getOption("shinyOAuth.skip_browser_token", FALSE)) {
    return(FALSE)
  }

  if (.is_test_or_interactive()) {
    if (!.is_test()) {
      rlang::warn(
        c(
          "Browser cookie presence check is disabled",
          "x" = "`options(shinyOAuth.skip_browser_token = TRUE)` is active",
          "!" = "This bypasses a key security check and is intended only for local testing"
        )
      )
    }

    return(TRUE)
  }

  return(FALSE)
}

allow_skip_signature <- function() {
  if (!getOption("shinyOAuth.skip_id_sig", FALSE)) {
    return(FALSE)
  }

  if (.is_test_or_interactive()) {
    if (!.is_test()) {
      rlang::warn(
        c(
          "ID token signature verification is disabled",
          "x" = "`options(shinyOAuth.skip_id_sig = TRUE)` is active",
          "!" = "This bypasses cryptographic verification and is intended only for local testing"
        )
      )
    }

    return(TRUE)
  }

  return(FALSE)
}

allow_print_errors <- function() {
  if (!getOption("shinyOAuth.print_errors", FALSE)) {
    return(FALSE)
  }

  if (.is_test_or_interactive()) {
    return(TRUE)
  }

  # Explicitly disallow in non-interactive/non-test contexts
  # Prevent callers from falling back to raw option values
  return(FALSE)
}

allow_print_traceback <- function() {
  # Default is FALSE: only treat tracebacks as softened when explicitly opted-in
  if (!getOption("shinyOAuth.print_traceback", FALSE)) {
    return(FALSE)
  }

  if (.is_test_or_interactive()) {
    return(TRUE)
  }

  # Explicitly disallow in non-interactive/non-test contexts
  # Prevent callers from falling back to raw option values
  return(FALSE)
}

# Allow exposing HTTP error bodies in thrown conditions (development only)
allow_expose_error_body <- function() {
  if (!isTRUE(getOption("shinyOAuth.expose_error_body", FALSE))) {
    return(FALSE)
  }

  if (.is_test_or_interactive()) {
    if (!.is_test()) {
      rlang::warn(
        c(
          "Exposing HTTP response bodies in errors is enabled",
          "x" = "`options(shinyOAuth.expose_error_body = TRUE)` is active",
          "!" = "This may leak sensitive information to the console"
        )
      )
    }
    return(TRUE)
  }
  FALSE
}

# Allow HTTP redirects on sensitive OAuth flows (testing only)
allow_redirect <- function() {
  if (!isTRUE(getOption("shinyOAuth.allow_redirect", FALSE))) {
    return(FALSE)
  }

  if (.is_test_or_interactive()) {
    if (!.is_test()) {
      rlang::warn(
        c(
          "HTTP redirect following is enabled for sensitive OAuth flows",
          "x" = "`options(shinyOAuth.allow_redirect = TRUE)` is active",
          "!" = "This disables anti-redirect protections and is intended only for local testing"
        )
      )
    }
    return(TRUE)
  }

  # In production (non-test, non-interactive), refuse to honor the option
  err_config(c(
    "x" = "`options(shinyOAuth.allow_redirect = TRUE)` is set outside a test or interactive session",
    "!" = "Allowing redirects in production can leak tokens, secrets, and credentials to redirect targets",
    "i" = "Remove this option or use `with_mocked_bindings()` in tests instead"
  ))
}

# Allow accepting unsigned (alg=none) UserInfo JWTs (testing only)
allow_unsigned_userinfo_jwt <- function() {
  if (!isTRUE(getOption("shinyOAuth.allow_unsigned_userinfo_jwt", FALSE))) {
    return(FALSE)
  }

  if (.is_test_or_interactive()) {
    if (!.is_test()) {
      rlang::warn(
        c(
          "Unsigned UserInfo JWT acceptance is enabled",
          "x" = "`options(shinyOAuth.allow_unsigned_userinfo_jwt = TRUE)` is active",
          "!" = "This bypasses JWT signature verification and is intended only for local testing"
        )
      )
    }
    return(TRUE)
  }

  # In production (non-test, non-interactive), refuse to honor the option
  err_config(c(
    "x" = "`options(shinyOAuth.allow_unsigned_userinfo_jwt = TRUE)` is set outside a test or interactive session",
    "!" = "Accepting unsigned UserInfo JWTs in production would allow identity forgery",
    "i" = "Remove this option or use `with_mocked_bindings()` in tests instead"
  ))
}

.is_test <- function() {
  if (requireNamespace("testthat", quietly = TRUE)) {
    return(testthat::is_testing())
  }
  return(FALSE)
}

.is_interactive <- function() {
  interactive()
}

.is_test_or_interactive <- function() {
  .is_test() || .is_interactive()
}
