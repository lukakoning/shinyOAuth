# Some helpers which determine if certain safety checks can be skipped
#   based on package options. Most development-only options are hard-gated to
#   testing or interactive sessions; a few explicit opt-ins (for example,
#   allow_redirect) are honored in all sessions.

#' Throw an error if specific dev/debug softeners are enabled
#'
#' @description
#' `r lifecycle::badge("deprecated")`
#'
#' This helper is deprecated because it only checks a narrow subset of
#' shinyOAuth's security-relaxing opt-ins. Use explicit startup checks for the
#' exact options your deployment permits or forbids instead.
#'
#' @details It only checks the following options:
#' \itemize{
#'  \item `shinyOAuth.skip_browser_token`: Skips browser cookie presence check
#'  \item `shinyOAuth.skip_id_sig`: Skips ID token signature verification
#'  \item `shinyOAuth.expose_error_body`: Exposes HTTP response bodies
#'  \item `shinyOAuth.allow_unsigned_userinfo_jwt`: Accepts unsigned (`alg=none`) UserInfo JWTs
#'  \item `shinyOAuth.allow_redirect`: Allows sensitive HTTP flows to follow redirects
#'  }
#'
#' @return Invisible TRUE if no safety checks are disabled; otherwise, an error is thrown.
#'
#' @example inst/examples/error_on_softened.R
#' @keywords internal
#' @export
error_on_softened <- function() {
  lifecycle::deprecate_warn(
    when = "0.4.0.9000",
    what = "error_on_softened()",
    details = c(
      x = paste(
        "This helper only checks a small subset of shinyOAuth's",
        "security-relaxing options."
      ),
      i = paste(
        "Use explicit startup checks for options like",
        "`shinyOAuth.allow_non_atomic_state_store` and",
        "`shinyOAuth.unblock_auth_params` when they matter to your deployment."
      )
    )
  )

  if (
    any(
      allow_skip_browser_token(),
      allow_skip_signature(),
      allow_expose_error_body(),
      allow_unsigned_userinfo_jwt(),
      allow_redirect()
    )
  ) {
    rlang::abort(
      c(
        "One or more safety settings have been disabled",
        "x" = "These settings relax shinyOAuth's default safety protections",
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

# Allow HTTP redirects on sensitive OAuth flows when the operator explicitly
# opts in via shinyOAuth.allow_redirect.
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
          "!" = paste(
            "This disables anti-redirect protections;",
            "only enable it when you deliberately accept that risk"
          )
        )
      )
    }
  }

  TRUE
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
