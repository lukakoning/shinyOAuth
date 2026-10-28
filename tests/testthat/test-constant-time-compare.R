test_that("constant_time_compare ignores length via hashing", {
  # Exercise long inputs without relying on wall-clock measurements.
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

test_that("constant_time_compare handles raw inputs too", {
  f <- shinyOAuth:::constant_time_compare

  expect_true(f(charToRaw("abc"), charToRaw("abc")))
  expect_false(f(charToRaw("abc"), charToRaw("abd")))
  expect_false(f(charToRaw("abc"), charToRaw("abcd")))
  expect_true(f(raw(), raw()))
  expect_false(f(NULL, charToRaw("a")))
  expect_false(f(charToRaw("a"), NULL))
  expect_true(f("a", charToRaw("a")))
})
