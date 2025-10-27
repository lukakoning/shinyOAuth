test_that("OAuthClient accepts duck-typed state_store and methods work", {
  # Minimal provider that avoids issuer/id-token validations
  prov <- oauth_provider(
    name = "duck",
    auth_url = "http://localhost/auth",
    token_url = "http://localhost/token",
    use_nonce = FALSE,
    id_token_validation = FALSE
  )

  # Duck-typed cache with get/set/remove/info
  make_store <- function(max_age = 123) {
    store <- new.env(parent = emptyenv())
    list(
      get = function(key, missing = NULL) {
        base::get0(key, envir = store, inherits = FALSE, ifnotfound = missing)
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
      info = function() list(max_age = max_age)
    )
  }

  store <- make_store()
  cli <- oauth_client(
    provider = prov,
    client_id = "x",
    client_secret = "y",
    redirect_uri = "http://localhost/redirect",
    state_store = store,
    state_entropy = 32,
    state_key = random_urlsafe(64)
  )

  # prepare_call should set a new state entry
  # 128 hex chars to satisfy validate_browser_token (use shared helper pattern)
  browser_token <- valid_browser_token()
  url <- prepare_call(cli, browser_token = browser_token)
  expect_true(
    is.character(url) && grepl("response_type=code", url, fixed = TRUE)
  )

  # Extract state parameter
  state_param <- parse_query_param(url, "state")
  expect_true(is_valid_string(state_param))

  # Entry exists in store: decrypt payload to recover random state value used as the cache key
  dec <- shinyOAuth:::state_decrypt_gcm(state_param, key = cli@state_key)
  expect_true(is.list(dec) && is_valid_string(dec$state))
  entry <- store$get(shinyOAuth:::state_cache_key(dec$state), missing = NULL)
  expect_type(entry, "list")
  expect_identical(entry$browser_token, browser_token)

  # Simulate callback verification path that removes the entry
  # Slightly hacky: call internal remove directly to test duck-typed remove
  store$remove(shinyOAuth:::state_cache_key(dec$state))
  expect_null(store$get(
    shinyOAuth:::state_cache_key(dec$state),
    missing = NULL
  ))
})
