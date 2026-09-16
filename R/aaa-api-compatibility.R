# Resolve a preferred argument and its released spelling without forcing
# a missing argument or changing its default.
resolve_argument_alias <- function(
  value,
  alias,
  value_missing,
  alias_missing,
  name,
  old_name
) {
  if (alias_missing) {
    return(value)
  }
  if (!value_missing) {
    err_input(paste0("Cannot supply both `", name, "` and `", old_name, "`."))
  }
  alias
}
