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
