test_that("OAuthProvider rejects jwks_cache with incompatible signatures", {
  base <- "http://localhost"

  # 1) get() missing the `missing` argument
  bad_get <- list(
    get = function(key) NULL,
    set = function(key, value) invisible(NULL)
  )
  expect_error(
    oauth_provider(
      name = "sig-check",
      auth_url = paste0(base, "/auth"),
      token_url = paste0(base, "/token"),
      use_nonce = FALSE,
      id_token_validation = FALSE,
      jwks_cache = bad_get
    ),
    regexp = "jwks_cache\\$get must accept argument 'missing'"
  )

  # 2) set() missing value argument
  bad_set <- list(
    get = function(key, missing = NULL) missing,
    set = function(key) invisible(NULL)
  )
  expect_error(
    oauth_provider(
      name = "sig-check",
      auth_url = paste0(base, "/auth"),
      token_url = paste0(base, "/token"),
      use_nonce = FALSE,
      id_token_validation = FALSE,
      jwks_cache = bad_set
    ),
    regexp = "jwks_cache\\$set must accept \\(?key, value\\)?"
  )

  # 3) optional remove present but zero-arg
  bad_rm <- list(
    get = function(key, missing = NULL) missing,
    set = function(key, value) invisible(NULL),
    remove = function() invisible(NULL)
  )
  expect_error(
    oauth_provider(
      name = "sig-check",
      auth_url = paste0(base, "/auth"),
      token_url = paste0(base, "/token"),
      use_nonce = FALSE,
      id_token_validation = FALSE,
      jwks_cache = bad_rm
    ),
    regexp = "jwks_cache\\$remove must accept \\(?key\\)?"
  )
})
