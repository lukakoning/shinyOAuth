test_that("OAuthProvider validator accepts duck-typed jwks_cache", {
  # Minimal cache exposing get/set
  cache <- local({
    store <- new.env(parent = emptyenv())
    list(
      get = function(key, missing = NULL) {
        if (exists(key, envir = store, inherits = FALSE)) {
          get(key, envir = store)
        } else {
          missing
        }
      },
      set = function(key, value) {
        assign(key, value, envir = store)
        invisible(NULL)
      }
    )
  })

  # Use localhost HTTP which is allowed by default in is_ok_host
  base <- "http://localhost" # we only need host validation

  prov <- oauth_provider(
    name = "duck",
    auth_url = paste0(base, "/auth"),
    token_url = paste0(base, "/token"),
    # Avoid issuer-dependent validations in this unit test
    use_nonce = FALSE,
    id_token_validation = FALSE,
    jwks_cache = cache
  )

  # If validation passed, class should be OAuthProvider and cache retained
  expect_s3_class(prov, "S7_object")
  expect_true(is.list(prov@jwks_cache))
  expect_true(is.function(prov@jwks_cache$get))
  expect_true(is.function(prov@jwks_cache$set))
})
