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


test_that("state_store_get_remove catches broken remove via post-check", {
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
  state <- "STATE-BROKEN-REMOVE"
  key <- shinyOAuth:::state_cache_key(state)
  ssv <- list(browser_token = "bt2", pkce_code_verifier = "cv2", nonce = "n2")
  backing$set(key, ssv)

  # Wrapper cache where remove() is a no-op but returns TRUE (simulates the

  # exact vulnerability: cachem-style always-TRUE return without actual deletion,
  # or a broken custom backend). The post-removal absence check must catch this.
  wrapper <- list(
    get = function(key, missing = NULL) backing$get(key, missing = missing),
    set = function(key, value) backing$set(key, value),
    remove = function(key) TRUE, # no-op, pretends success
    info = function() list(max_age = 300)
  )
  cli@state_store <- wrapper

  # With the OLD code (trusted rm_ret=TRUE), this would have SUCCEEDED — the
  # vulnerability. With the NEW code, the post-removal absence check sees the
  # key is STILL present → removal is treated as failed → state error.
  # Note: the no-atomic-take warning may or may not fire depending on test
  # order (.frequency = "once"), so suppress it to focus on the error assertion.
  suppressWarnings(
    expect_error(
      shinyOAuth:::state_store_get_remove(cli, state),
      class = "shinyOAuth_state_error"
    )
  )
})
