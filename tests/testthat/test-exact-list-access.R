test_that("required cache methods cannot be supplied by prefix collisions", {
  methods <- list(
    get = function(key, missing = NULL) missing,
    set = function(key, value) invisible(NULL),
    remove = function(key) invisible(TRUE)
  )
  for (field in names(methods)) {
    cache <- methods
    names(cache)[names(cache) == field] <- paste0(field, "_extension")
    client <- make_test_client()
    expect_error(
      {
        client@state_store <- cache
      },
      "state_store"
    )
    if (field %in% c("get", "set")) {
      provider <- make_test_provider()
      expect_error(
        {
          provider@jwks_cache <- cache
        },
        "jwks_cache"
      )
    }
  }
})

test_that("a prefixed take method cannot satisfy atomic state consumption", {
  local_options(shinyOAuth.allow_non_atomic_state_store = FALSE)
  called <- FALSE
  store <- list(
    get = function(key, missing = NULL) missing,
    set = function(key, value) invisible(NULL),
    remove = function(key) invisible(TRUE),
    take_extension = function(key, missing = NULL) {
      called <<- TRUE
      missing
    }
  )
  client <- make_test_client()
  client@state_store <- store
  expect_error(
    state_store_get_remove(client, "exact-state"),
    "requires atomic",
    class = "shinyOAuth_config_error"
  )
  expect_false(called)
})
