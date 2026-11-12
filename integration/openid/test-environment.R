testthat::test_that("the suite lock rejects floating images and changed schemas", {
  root <- tempfile("openid-lock-")
  dir.create(file.path(root, "integration/openid"), recursive = TRUE)
  withr::defer(unlink(root, recursive = TRUE))
  lock <- openid_lock("../..")
  path <- file.path(root, "integration/openid/suite-lock.json")
  jsonlite::write_json(lock, path, auto_unbox = TRUE)
  testthat::expect_identical(openid_lock(root), lock)
  lock[["images"]][[
    "server"
  ]] <- "registry.gitlab.com/openid/conformance-suite:latest"
  jsonlite::write_json(lock, path, auto_unbox = TRUE)
  testthat::expect_error(openid_lock(root), "every image must use")
  lock <- openid_lock("../..")
  lock[["schema_version"]] <- 2L
  jsonlite::write_json(lock, path, auto_unbox = TRUE)
  testthat::expect_error(openid_lock(root), "Invalid OpenID suite lock")
})

testthat::test_that("missing, malformed and duplicated plan metadata fail preflight", {
  plans <- list(list(planName = "basic"), list(planName = "config"))
  testthat::expect_identical(
    openid_plan_ids(plans, c("basic", "config")),
    c("basic", "config")
  )
  testthat::expect_error(
    openid_plan_ids(plans, "refresh"),
    "missing required plans"
  )
  testthat::expect_error(
    openid_plan_ids(list(), "basic"),
    "missing required plans"
  )
  testthat::expect_error(
    openid_plan_ids(c(plans, plans), "basic"),
    "duplicate plans"
  )
  testthat::expect_error(
    openid_plan_ids(list(list(name = "basic")), "basic"),
    "no planName"
  )
})

testthat::test_that("cleanup refuses another Compose project before invoking Docker", {
  testthat::expect_error(
    openid_compose(list(project = "another-project"), "down"),
    "unowned"
  )
})

testthat::test_that("readiness has a bounded failure and API paths stay local", {
  testthat::expect_error(
    openid_wait(function() FALSE, "unavailable service", 0),
    "Timed out: unavailable"
  )
  testthat::expect_error(
    openid_api(list(), "https://other.example/api/server"),
    "Invalid OpenID API path"
  )
})
