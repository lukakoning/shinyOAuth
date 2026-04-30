# This file contains tiny environment-detection helpers used to soften noisy
# behavior during tests or interactive development.
# Use them when warnings, logs, or debug output should behave differently in
# tests versus live interactive sessions.

# 1 Environment helpers ----------------------------------------------------

## 1.1 Test and interactive checks ----------------------------------------

# Check whether code is currently running under testthat.
# Used by warning and debug helpers. Input: none. Output: TRUE or FALSE.
.is_test <- function() {
  if (requireNamespace("testthat", quietly = TRUE)) {
    return(testthat::is_testing())
  }
  return(FALSE)
}

# Check whether the current R session is interactive.
# Used by logging and debugging helpers. Input: none. Output: TRUE or FALSE.
.is_interactive <- function() {
  interactive()
}

# Check whether code is running under tests or in an interactive session.
# Used by softening helpers that should stay quiet in non-interactive batch
# execution. Input: none. Output: TRUE or FALSE.
.is_test_or_interactive <- function() {
  .is_test() || .is_interactive()
}
