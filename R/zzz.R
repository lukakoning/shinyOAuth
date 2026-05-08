# This file contains package startup hooks and small namespace-level setup.
# Use it for registrations that must happen when shinyOAuth loads, not for the
# OAuth flow logic itself.

# 1 Package startup ------------------------------------------------------------

## 1.1 Namespace setup ---------------------------------------------------------

utils::globalVariables(c("input", "private", "public"))

#' Package load hook
#'
#' Registers S7 methods and runs package startup hooks when shinyOAuth loads.
#' Used automatically by R package loading.
#'
#' @param ... Package load arguments supplied by R.
#' @return No meaningful return value; this function is called for its side
#'   effects.
#' @keywords internal
#' @noRd
.onLoad <- function(...) {
  S7::methods_register()
  rlang::run_on_load()
}

rlang::on_load(rlang::local_use_cli(format = TRUE, inline = TRUE))
