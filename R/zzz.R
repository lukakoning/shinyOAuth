# This file contains package startup hooks and small namespace-level setup.
# Use it for registrations that must happen when shinyOAuth loads, not for the
# OAuth flow logic itself.

# 1 Package startup --------------------------------------------------------

## 1.1 Namespace setup -----------------------------------------------------

utils::globalVariables(c("input", "private", "public"))

# Register S7 methods and run rlang startup hooks when the package loads.
# Used automatically by R package loading. Input: package load args. Output:
# side effects only.
.onLoad <- function(...) {
  S7::methods_register()
  rlang::run_on_load()
}

rlang::on_load(rlang::local_use_cli(format = TRUE, inline = TRUE))
