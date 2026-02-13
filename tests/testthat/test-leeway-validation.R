test_that("OAuthProvider rejects Inf leeway", {
  expect_error(
    make_test_provider() |>
      (\(p) {
        p@leeway <- Inf
        S7::validate(p)
      })(),
    regexp = "finite"
  )
})

test_that("OAuthProvider rejects -Inf leeway", {
  expect_error(
    make_test_provider() |>
      (\(p) {
        p@leeway <- -Inf
        S7::validate(p)
      })(),
    regexp = "finite"
  )
})

test_that("OAuthProvider rejects NaN leeway", {
  expect_error(
    make_test_provider() |>
      (\(p) {
        p@leeway <- NaN
        S7::validate(p)
      })(),
    regexp = "finite"
  )
})

test_that("OAuthProvider rejects NA leeway", {
  expect_error(
    make_test_provider() |>
      (\(p) {
        p@leeway <- NA_real_
        S7::validate(p)
      })(),
    regexp = "finite"
  )
})

test_that("OAuthProvider accepts finite non-negative leeway", {
  prov <- make_test_provider()
  prov@leeway <- 0
  expect_no_error(S7::validate(prov))
  prov@leeway <- 60
  expect_no_error(S7::validate(prov))
})
