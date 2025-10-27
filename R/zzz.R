utils::globalVariables(c("input", "private", "public"))

.onLoad <- function(...) {
  S7::methods_register()
  rlang::run_on_load()
}

rlang::on_load(rlang::local_use_cli(format = TRUE, inline = TRUE))
