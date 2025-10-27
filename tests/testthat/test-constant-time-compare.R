test_that("constant_time_compare basic equality/inequality", {
  # Equal values
  expect_true(shinyOAuth:::constant_time_compare("abc", "abc"))
  # Different values
  expect_false(shinyOAuth:::constant_time_compare("abc", "abd"))
  # Different lengths
  expect_false(shinyOAuth:::constant_time_compare("abc", "ab"))
  # Empty vs empty
  expect_true(shinyOAuth:::constant_time_compare("", ""))
  # Invalid inputs treated as mismatch
  expect_false(shinyOAuth:::constant_time_compare(NA_character_, "x"))
  expect_false(shinyOAuth:::constant_time_compare(NULL, "x"))
})

test_that("constant_time_compare ignores length via hashing", {
  # These tests don't measure timing precisely, but we ensure function handles
  # very different lengths without error and returns correct result.
  a <- paste(rep("a", 4096), collapse = "")
  b <- paste(rep("a", 2), collapse = "")
  c <- paste(rep("b", 4096), collapse = "")

  expect_true(shinyOAuth:::constant_time_compare(a, a))
  expect_false(shinyOAuth:::constant_time_compare(a, b))
  expect_false(shinyOAuth:::constant_time_compare(a, c))
})
test_that("constant_time_compare basic equality and inequality", {
  f <- shinyOAuth:::constant_time_compare
  expect_true(f("abc", "abc"))
  expect_false(f("abc", "abd"))
  expect_false(f("abc", "abcd"))
  expect_false(f("abcd", "abc"))
  expect_false(f("", "a"))
  expect_false(f("a", ""))
  expect_true(f("", ""))
})

test_that("constant_time_compare handles NA/NULL/non-char as mismatch", {
  f <- shinyOAuth:::constant_time_compare
  expect_false(f(NA_character_, "a"))
  expect_false(f("a", NA_character_))
  expect_false(f(NULL, "a"))
  expect_false(f("a", NULL))
  expect_false(f(1L, "1"))
  expect_false(f(TRUE, "TRUE"))
})

test_that("constant_time_compare is insensitive to content length timing (coarse)", {
  # We can't perfectly prove constant-time in unit tests, but we can assert
  # that the function runs over the max length without early exit by comparing
  # the runtime ratio of equal vs. first-char-different strings of the same
  # length. Allow generous tolerance to avoid flakiness.
  f <- shinyOAuth:::constant_time_compare
  skip_on_cran()
  n <- 2000
  a <- paste(rep("a", n), collapse = "")
  b_equal <- a
  b_diff <- paste0("b", substring(a, 2))

  t_equal <- system.time({
    invisible(f(a, b_equal))
  })[["elapsed"]]
  t_diff <- system.time({
    invisible(f(a, b_diff))
  })[["elapsed"]]

  # The times should be in the same ballpark; allow 3x to avoid false alarms
  expect_lte(t_diff, max(3 * t_equal, t_equal + 0.02))
})
