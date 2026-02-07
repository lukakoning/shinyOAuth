# Tests for mirai-related utilities:
# - classify_mirai_error()
# - async_dispatch() .timeout / shinyOAuth.async_timeout option
# - async_backend_available() with daemons_set()

# --- classify_mirai_error --------------------------------------------------

testthat::test_that("classify_mirai_error returns NULL for non-errors", {
  testthat::skip_if_not_installed("mirai")
  testthat::expect_null(shinyOAuth:::classify_mirai_error(42))
  testthat::expect_null(shinyOAuth:::classify_mirai_error("hello"))
  testthat::expect_null(shinyOAuth:::classify_mirai_error(NULL))
  testthat::expect_null(shinyOAuth:::classify_mirai_error(list(a = 1)))
})

testthat::test_that("classify_mirai_error returns NULL when mirai not installed", {
  testthat::local_mocked_bindings(
    is_installed = function(pkg, ...) if (pkg == "mirai") FALSE else TRUE,
    .package = "rlang"
  )
  testthat::expect_null(shinyOAuth:::classify_mirai_error("anything"))
})

testthat::test_that("classify_mirai_error returns 'mirai_error' for code errors", {
  testthat::skip_if_not_installed("mirai")
  # Mock: is_mirai_error returns TRUE, others FALSE
  testthat::local_mocked_bindings(
    is_mirai_error = function(x) TRUE,
    is_mirai_interrupt = function(x) FALSE,
    is_error_value = function(x) FALSE,
    .package = "mirai"
  )
  testthat::expect_equal(
    shinyOAuth:::classify_mirai_error("some error"),
    "mirai_error"
  )
})

testthat::test_that("classify_mirai_error returns 'mirai_interrupt' for interrupts", {
  testthat::skip_if_not_installed("mirai")
  testthat::local_mocked_bindings(
    is_mirai_error = function(x) FALSE,
    is_mirai_interrupt = function(x) TRUE,
    is_error_value = function(x) FALSE,
    .package = "mirai"
  )
  testthat::expect_equal(
    shinyOAuth:::classify_mirai_error("interrupted"),
    "mirai_interrupt"
  )
})

testthat::test_that("classify_mirai_error returns 'mirai_timeout' for errorValue 5", {
  testthat::skip_if_not_installed("mirai")
  val <- structure(5L, class = "errorValue")
  testthat::local_mocked_bindings(
    is_mirai_error = function(x) FALSE,
    is_mirai_interrupt = function(x) FALSE,
    is_error_value = function(x) inherits(x, "errorValue"),
    .package = "mirai"
  )
  testthat::expect_equal(
    shinyOAuth:::classify_mirai_error(val),
    "mirai_timeout"
  )
})

testthat::test_that("classify_mirai_error returns 'mirai_connection_reset' for errorValue 19", {
  testthat::skip_if_not_installed("mirai")
  val <- structure(19L, class = "errorValue")
  testthat::local_mocked_bindings(
    is_mirai_error = function(x) FALSE,
    is_mirai_interrupt = function(x) FALSE,
    is_error_value = function(x) inherits(x, "errorValue"),
    .package = "mirai"
  )
  testthat::expect_equal(
    shinyOAuth:::classify_mirai_error(val),
    "mirai_connection_reset"
  )
})

testthat::test_that("classify_mirai_error returns 'mirai_error_value' for other error values", {
  testthat::skip_if_not_installed("mirai")
  val <- structure(99L, class = "errorValue")
  testthat::local_mocked_bindings(
    is_mirai_error = function(x) FALSE,
    is_mirai_interrupt = function(x) FALSE,
    is_error_value = function(x) inherits(x, "errorValue"),
    .package = "mirai"
  )
  testthat::expect_equal(
    shinyOAuth:::classify_mirai_error(val),
    "mirai_error_value"
  )
})

# --- async_dispatch: .timeout / shinyOAuth.async_timeout --------------------

testthat::test_that("async_dispatch passes explicit .timeout to mirai", {
  testthat::skip_on_cran()
  testthat::skip_if_not_installed("mirai")

  mirai::daemons(sync = TRUE)
  withr::defer(mirai::daemons(0))

  # Explicit .timeout argument

  m <- shinyOAuth:::async_dispatch(
    expr = quote(1 + 1),
    args = list(),
    .timeout = 5000
  )
  testthat::expect_true(inherits(m, "mirai"))
})

testthat::test_that("async_dispatch reads shinyOAuth.async_timeout option", {
  testthat::skip_on_cran()
  testthat::skip_if_not_installed("mirai")

  mirai::daemons(sync = TRUE)
  withr::defer(mirai::daemons(0))

  withr::local_options(list(shinyOAuth.async_timeout = 8000))

  m <- shinyOAuth:::async_dispatch(
    expr = quote(1 + 1),
    args = list()
  )
  testthat::expect_true(inherits(m, "mirai"))
})

testthat::test_that("async_dispatch explicit .timeout overrides option", {
  testthat::skip_on_cran()
  testthat::skip_if_not_installed("mirai")

  mirai::daemons(sync = TRUE)
  withr::defer(mirai::daemons(0))

  withr::local_options(list(shinyOAuth.async_timeout = 99999))

  # Explicit value should take precedence (we can't easily inspect the mirai

  # object's timeout, but we verify it doesn't error and the explicit path
  # is taken via the %||% logic: NULL %||% option, but 5000 is not NULL)
  m <- shinyOAuth:::async_dispatch(
    expr = quote(1 + 1),
    args = list(),
    .timeout = 5000
  )
  testthat::expect_true(inherits(m, "mirai"))
})

testthat::test_that("async_dispatch works without timeout (NULL default)", {
  testthat::skip_on_cran()
  testthat::skip_if_not_installed("mirai")

  mirai::daemons(sync = TRUE)
  withr::defer(mirai::daemons(0))

  withr::local_options(list(shinyOAuth.async_timeout = NULL))

  m <- shinyOAuth:::async_dispatch(
    expr = quote(1 + 1),
    args = list()
  )
  testthat::expect_true(inherits(m, "mirai"))
})

# --- async_backend_available uses daemons_set() ----------------------------

testthat::test_that("async_backend_available returns 'mirai' when daemons are set", {
  testthat::skip_on_cran()
  testthat::skip_if_not_installed("mirai")

  mirai::daemons(sync = TRUE)
  withr::defer(mirai::daemons(0))

  testthat::expect_equal(shinyOAuth:::async_backend_available(), "mirai")
})

testthat::test_that("async_backend_available returns NULL when no backend configured", {
  testthat::skip_on_cran()

  # Ensure mirai daemons off
  if (rlang::is_installed("mirai")) {
    tryCatch(mirai::daemons(0), error = function(...) NULL)
  }

  # Ensure future sequential (nbrOfWorkers() returns 1 for sequential, but
  # sequential is still > 0, so mock it to fail or unload future)
  if (rlang::is_installed("future")) {
    old_plan <- future::plan()
    future::plan(future::sequential)
    withr::defer(future::plan(old_plan))
  }

  # With both backends "off", we need to mock to ensure neither is seen
  testthat::local_mocked_bindings(
    is_installed = function(pkg, ...) FALSE,
    .package = "rlang"
  )

  testthat::expect_null(shinyOAuth:::async_backend_available())
})

testthat::test_that("async_backend_available falls back to 'future' when mirai not set", {
  testthat::skip_on_cran()
  testthat::skip_if_not_installed("future")
  testthat::skip_if_not_installed("promises")

  # Ensure mirai daemons off
  if (rlang::is_installed("mirai")) {
    tryCatch(mirai::daemons(0), error = function(...) NULL)
  }

  future::plan(future::multisession, workers = 1)
  withr::defer(future::plan(future::sequential))

  testthat::expect_equal(shinyOAuth:::async_backend_available(), "future")
})
