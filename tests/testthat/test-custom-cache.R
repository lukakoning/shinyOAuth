test_that("custom_cache requires get and set functions", {
  expect_error(
    custom_cache(get = NULL, set = function(...) NULL),
    class = "shinyOAuth_input_error"
  )
  expect_error(
    custom_cache(get = function(...) NULL, set = NULL),
    class = "shinyOAuth_input_error"
  )
})

test_that("custom_cache validates optional info hook", {
  # Non-function `info` should fail fast with input error
  expect_error(
    custom_cache(
      get = function(key, missing = NULL) missing,
      set = function(key, value) invisible(NULL),
      remove = function(key) invisible(NULL),
      info = list(max_age = 60)
    ),
    class = "shinyOAuth_input_error"
  )
})

test_that("custom_cache stores and retrieves values", {
  store <- new.env(parent = emptyenv())
  cache <- custom_cache(
    get = function(key, missing = NULL) {
      base::get0(key, envir = store, ifnotfound = missing, inherits = FALSE)
    },
    set = function(key, value) {
      assign(key, value, envir = store)
      invisible(NULL)
    },
    remove = function(key) {
      if (exists(key, envir = store, inherits = FALSE)) {
        rm(list = key, envir = store)
      }
      invisible(NULL)
    },
    info = function() list(max_age = 600)
  )

  expect_identical(cache$get("missing", missing = 5), 5)
  cache$set("a", 1)
  expect_identical(cache$get("a", missing = NULL), 1)
  cache$remove("a")
  expect_identical(cache$get("a", missing = 2), 2)
  expect_equal(cache$info()$max_age, 600)
})

test_that("custom_cache supplies benign defaults", {
  cache <- custom_cache(
    get = function(key, missing = NULL) missing,
    set = function(key, value) invisible(NULL),
    remove = function(key) invisible(NULL)
  )
  expect_identical(cache$info(), list())
  expect_null(cache$remove("anything"))
  expect_identical(cache$get("something", missing = 42), 42)
})
