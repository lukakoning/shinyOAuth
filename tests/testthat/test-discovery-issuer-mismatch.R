test_that("validate_discovery_issuer errors on host mismatch by default", {
  f <- shinyOAuth:::validate_discovery_issuer
  expect_error(
    f(
      "https://login.example.com",
      "https://accounts.example.com"
    ),
    class = "shinyOAuth_config_error"
  )
})

test_that("validate_discovery_issuer errors on scheme mismatch by default", {
  f <- shinyOAuth:::validate_discovery_issuer
  expect_error(
    f("http://login.example.com", "https://login.example.com"),
    class = "shinyOAuth_config_error"
  )
})

test_that("validate_discovery_issuer returns discovered on match", {
  f <- shinyOAuth:::validate_discovery_issuer
  expect_identical(
    f(
      "https://login.example.com",
      "https://login.example.com"
    ),
    "https://login.example.com"
  )
})

test_that("validate_discovery_issuer can be overridden via arg", {
  f <- shinyOAuth:::validate_discovery_issuer
  expect_identical(
    f(
      "https://login.example.com",
      "https://accounts.example.com",
      issuer_match = FALSE
    ),
    "https://accounts.example.com"
  )
})
