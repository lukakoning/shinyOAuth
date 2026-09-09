# This file contains package startup hooks and small namespace-level setup
# Used for registrations that must run when shinyOAuth loads

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

# Conditions carry literal data, including nested conditionMessage() output.
# Render only fixed package-owned templates explicitly at their call sites.
rlang::on_load(rlang::local_use_cli(format = TRUE, inline = FALSE))
