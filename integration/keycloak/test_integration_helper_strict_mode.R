if (!exists("keycloak_skip_or_fail", mode = "function")) {
  source(file.path(dirname(sys.frame(1)$ofile %||% "."), "helper-keycloak.R"))
}

testthat::test_that("strict integration mode turns infrastructure skips into failures", {
  withr::local_envvar(c(SHINYOAUTH_INT_STRICT = "1"))

  condition <- tryCatch(
    keycloak_skip_or_fail("broken infrastructure"),
    condition = function(cnd) cnd
  )

  testthat::expect_s3_class(condition, "expectation_failure")
})

testthat::test_that("non-strict integration mode retains developer-friendly skips", {
  withr::local_envvar(c(SHINYOAUTH_INT_STRICT = NA))

  condition <- tryCatch(
    keycloak_skip_or_fail("optional infrastructure"),
    condition = function(cnd) cnd
  )

  testthat::expect_s3_class(condition, "skip")
})
