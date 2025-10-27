test_that("OAuthClient rejects state_store with incompatible signatures", {
  prov <- oauth_provider(
    name = "sig-check",
    auth_url = "http://localhost/auth",
    token_url = "http://localhost/token",
    use_nonce = FALSE,
    id_token_validation = FALSE
  )

  # 1) get() missing the `missing` argument
  bad_get <- list(
    get = function(key) NULL, # no 'missing'
    set = function(key, value) invisible(NULL),
    remove = function(key) invisible(NULL)
  )
  expect_error(
    oauth_client(
      provider = prov,
      client_id = "x",
      client_secret = "y",
      redirect_uri = "http://localhost/redirect",
      state_store = bad_get,
      state_entropy = 32,
      state_key = random_urlsafe(64)
    ),
    regexp = "state_store\\$get must accept argument 'missing'"
  )

  # 2) set() missing value argument
  bad_set <- list(
    get = function(key, missing = NULL) missing,
    set = function(key) invisible(NULL), # no value
    remove = function(key) invisible(NULL)
  )
  expect_error(
    oauth_client(
      provider = prov,
      client_id = "x",
      client_secret = "y",
      redirect_uri = "http://localhost/redirect",
      state_store = bad_set,
      state_entropy = 32,
      state_key = random_urlsafe(64)
    ),
    regexp = "state_store\\$set must accept \\(?key, value\\)?"
  )

  # 3) remove() missing key arg
  bad_rm <- list(
    get = function(key, missing = NULL) missing,
    set = function(key, value) invisible(NULL),
    remove = function() invisible(NULL) # no key param
  )
  expect_error(
    oauth_client(
      provider = prov,
      client_id = "x",
      client_secret = "y",
      redirect_uri = "http://localhost/redirect",
      state_store = bad_rm,
      state_entropy = 32,
      state_key = random_urlsafe(64)
    ),
    regexp = "state_store\\$remove must accept \\(?key\\)?"
  )
})
