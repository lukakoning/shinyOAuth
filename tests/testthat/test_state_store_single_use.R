test_that("state_store_get_remove enforces single-use with cachem (sequential)", {
  skip_on_cran()
  prov <- oauth_provider(
    name = "test",
    auth_url = "http://localhost:10001/auth",
    token_url = "http://localhost:10001/token"
  )
  cli <- oauth_client(
    provider = prov,
    client_id = "client",
    client_secret = "secret",
    redirect_uri = "http://localhost:8100"
  )

  # Prepare a real cachem backend and set a state entry
  st <- cachem::cache_mem()
  cli@state_store <- st

  state <- "STATE-123"
  key <- shinyOAuth:::state_cache_key(state)
  ssv <- list(browser_token = "bt", pkce_code_verifier = "cv", nonce = "nn")
  st$set(key, ssv)

  # First call succeeds and returns the stored value
  out1 <- shinyOAuth:::state_store_get_remove(cli, state)
  expect_type(out1, "list")
  expect_equal(out1$browser_token, "bt")

  # Second call should now fail (missing entry)
  expect_error(
    shinyOAuth:::state_store_get_remove(cli, state),
    class = "shinyOAuth_state_error"
  )
})


test_that("state_store_get_remove detects racy second remover (cachem remove return)", {
  skip_on_cran()
  prov <- oauth_provider(
    name = "test",
    auth_url = "http://localhost:10002/auth",
    token_url = "http://localhost:10002/token"
  )
  cli <- oauth_client(
    provider = prov,
    client_id = "client",
    client_secret = "secret",
    redirect_uri = "http://localhost:8100"
  )

  # Underlying real cache and pre-populated entry
  backing <- cachem::cache_mem()
  state <- "STATE-RACE"
  key <- shinyOAuth:::state_cache_key(state)
  ssv <- list(browser_token = "bt2", pkce_code_verifier = "cv2", nonce = "n2")
  backing$set(key, ssv)

  # Snapshot of the value as if two concurrent readers fetched before any remove
  prefetch <- backing$get(key, missing = NULL)

  # Wrapper cache that simulates two concurrent reads before any removal:
  # - The first two get() calls return the prefetched value regardless of backing state
  # - Subsequent get() calls delegate to the backing cache (so post-check sees absence)
  # - remove() delegates to backing and preserves its return value semantics
  get_calls <- 0L
  wrapper <- list(
    get = function(key, missing = NULL) {
      get_calls <<- get_calls + 1L
      if (get_calls <= 2L) {
        prefetch
      } else {
        backing$get(key, missing = missing)
      }
    },
    set = function(key, value) backing$set(key, value),
    remove = function(key) backing$remove(key),
    info = function() list(max_age = 300)
  )
  cli@state_store <- wrapper

  # First simulated concurrent call succeeds
  out_ok <- shinyOAuth:::state_store_get_remove(cli, state)
  expect_equal(out_ok$browser_token, "bt2")

  # Second simulated concurrent call sees the same prefetch, but remove() no longer
  # reports an affirmative TRUE. With the fix, this must be treated as invalid state
  expect_error(
    shinyOAuth:::state_store_get_remove(cli, state),
    class = "shinyOAuth_state_error"
  )
})
