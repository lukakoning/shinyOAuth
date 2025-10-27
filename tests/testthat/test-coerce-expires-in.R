test_that("coerce_expires_in tolerates '3600.0' and leading zeros", {
  f <- get("coerce_expires_in", asNamespace("shinyOAuth"))
  expect_identical(f("3600.0"), 3600)
  expect_identical(f("0003600"), 3600)
})
