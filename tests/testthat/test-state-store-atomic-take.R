# Tests for atomic $take() state store API and TOCTOU hardening

# -- Helper: atomic in-memory store with $take() ----------------------------

make_atomic_store <- function() {
  env <- new.env(parent = emptyenv())
  list(
    get = function(key, missing = NULL) {
      base::get0(key, envir = env, ifnotfound = missing, inherits = FALSE)
    },
    set = function(key, value) {
      assign(key, value, envir = env)
      invisible(NULL)
    },
    remove = function(key) {
      if (exists(key, envir = env, inherits = FALSE)) {
        rm(list = key, envir = env)
        TRUE
      } else {
        FALSE
      }
    },
    take = function(key, missing = NULL) {
      val <- base::get0(
        key,
        envir = env,
        ifnotfound = missing,
        inherits = FALSE
      )
      if (exists(key, envir = env, inherits = FALSE)) {
        rm(list = key, envir = env)
      }
      val
    },
    info = function() list(max_age = 600)
  )
}

make_client_with_store <- function(store) {
  prov <- shinyOAuth::oauth_provider(
    name = "test",
    auth_url = "http://localhost:10099/auth",
    token_url = "http://localhost:10099/token"
  )
  shinyOAuth::oauth_client(
    provider = prov,
    client_id = "client",
    client_secret = "secret",
    redirect_uri = "http://localhost:8100",
    state_store = store
  )
}


# -- Tests for atomic $take() path ------------------------------------------

test_that("state_store_get_remove uses $take() when available (single-use)", {
  store <- make_atomic_store()
  cli <- make_client_with_store(store)

  state <- "TAKE-SINGLE-USE"
  key <- shinyOAuth:::state_cache_key(state)
  ssv <- list(browser_token = "bt", pkce_code_verifier = "cv", nonce = "nn")
  store$set(key, ssv)

  # First call succeeds via atomic take
  out <- shinyOAuth:::state_store_get_remove(cli, state)
  expect_type(out, "list")
  expect_equal(out$browser_token, "bt")

  # Entry is gone after take
  expect_null(store$get(key, missing = NULL))

  # Second call fails (entry was atomically consumed)
  expect_error(
    shinyOAuth:::state_store_get_remove(cli, state),
    class = "shinyOAuth_state_error"
  )
})


test_that("atomic $take() prevents simulated stale-read replay", {
  # Simulate a backend where regular $get() exhibits stale reads but $take()

  # is truly atomic (like Redis GETDEL).
  env <- new.env(parent = emptyenv())
  take_calls <- 0L

  state <- "TAKE-STALE-SIM"
  key <- shinyOAuth:::state_cache_key(state)
  ssv <- list(
    browser_token = "bt_atomic",
    pkce_code_verifier = "c",
    nonce = "n"
  )
  assign(key, ssv, envir = env)

  store <- list(
    get = function(key, missing = NULL) {
      # Deliberately return stale reads (to show $take bypasses this path)
      base::get0(key, envir = env, ifnotfound = missing, inherits = FALSE)
    },
    set = function(key, value) {
      assign(key, value, envir = env)
      invisible(NULL)
    },
    remove = function(key) TRUE, # no-op; shouldn't matter because take is used
    take = function(key, missing = NULL) {
      # Atomic: only the first caller gets the value
      take_calls <<- take_calls + 1L
      if (take_calls == 1L) {
        val <- base::get0(
          key,
          envir = env,
          ifnotfound = missing,
          inherits = FALSE
        )
        if (exists(key, envir = env, inherits = FALSE)) {
          rm(list = key, envir = env)
        }
        val
      } else {
        missing # second caller gets nothing
      }
    },
    info = function() list(max_age = 600)
  )

  cli <- make_client_with_store(store)

  # First consumer succeeds
  out <- shinyOAuth:::state_store_get_remove(cli, state)
  expect_equal(out$browser_token, "bt_atomic")

  # Second consumer fails even though $get() would still return stale data
  expect_error(
    shinyOAuth:::state_store_get_remove(cli, state),
    class = "shinyOAuth_state_error"
  )
})


test_that("custom_cache() with take passes OAuthClient validation and works", {
  mem <- new.env(parent = emptyenv())
  cc <- shinyOAuth::custom_cache(
    get = function(key, missing = NULL) {
      base::get0(key, envir = mem, ifnotfound = missing, inherits = FALSE)
    },
    set = function(key, value) {
      assign(key, value, envir = mem)
      invisible(NULL)
    },
    remove = function(key) {
      if (exists(key, envir = mem, inherits = FALSE)) {
        rm(list = key, envir = mem)
      }
      TRUE
    },
    take = function(key, missing = NULL) {
      val <- base::get0(
        key,
        envir = mem,
        ifnotfound = missing,
        inherits = FALSE
      )
      if (exists(key, envir = mem, inherits = FALSE)) {
        rm(list = key, envir = mem)
      }
      val
    },
    info = function() list(max_age = 300)
  )

  # OAuthClient construction should succeed with $take()
  prov <- shinyOAuth::oauth_provider(
    name = "test",
    auth_url = "http://localhost:10098/auth",
    token_url = "http://localhost:10098/token"
  )
  cli <- shinyOAuth::oauth_client(
    provider = prov,
    client_id = "client",
    client_secret = "secret",
    redirect_uri = "http://localhost:8100",
    state_store = cc
  )

  # Verify $take is present and functional
  expect_true(is.function(cc$take))

  # End-to-end: set + take via state_store_get_remove
  state <- "CC-TAKE"
  key <- shinyOAuth:::state_cache_key(state)
  ssv <- list(browser_token = "bt_cc", pkce_code_verifier = "cv", nonce = "n")
  cc$set(key, ssv)

  out <- shinyOAuth:::state_store_get_remove(cli, state)
  expect_equal(out$browser_token, "bt_cc")

  # Second call fails
  expect_error(
    shinyOAuth:::state_store_get_remove(cli, state),
    class = "shinyOAuth_state_error"
  )
})


test_that("custom_cache() without take has $take == NULL", {
  cc <- shinyOAuth::custom_cache(
    get = function(key, missing = NULL) missing,
    set = function(key, value) invisible(NULL),
    remove = function(key) TRUE,
    info = function() list(max_age = 60)
  )
  expect_null(cc$take)
  expect_false(is.function(cc$take))
})


# -- Tests for fallback (no $take) path -------------------------------------

test_that("fallback errors for non-cachem store without $take()", {
  store <- list(
    get = function(key, missing = NULL) missing,
    set = function(key, value) invisible(NULL),
    remove = function(key) TRUE,
    info = function() list(max_age = 60)
  )
  cli <- make_client_with_store(store)

  state <- "ERR-NO-TAKE"
  key <- shinyOAuth:::state_cache_key(state)
  ssv <- list(browser_token = "bt", pkce_code_verifier = "cv", nonce = "nn")
  store$set(key, ssv)

  # Non-cache_mem store without $take() must error (fail closed)
  expect_error(
    shinyOAuth:::state_store_get_remove(cli, state),
    class = "shinyOAuth_config_error"
  )
})


test_that("fallback does NOT warn for cachem stores", {
  cli <- make_client_with_store(cachem::cache_mem(max_age = 60))

  state <- "NO-WARN-CACHEM"
  key <- shinyOAuth:::state_cache_key(state)

  # No warning for cachem::cache_mem() (per-process safe)
  expect_no_warning(
    expect_error(
      shinyOAuth:::state_store_get_remove(cli, state),
      class = "shinyOAuth_state_error"
    )
  )
})


test_that("fallback errors for cachem::cache_disk() (shared store)", {
  tmp <- withr::local_tempdir()
  disk_store <- cachem::cache_disk(dir = tmp, max_age = 60)
  cli <- make_client_with_store(disk_store)

  state <- "ERR-CACHE-DISK"
  key <- shinyOAuth:::state_cache_key(state)
  ssv <- list(browser_token = "bt", pkce_code_verifier = "cv", nonce = "nn")
  disk_store$set(key, ssv)

  # cache_disk() without $take() must error (fail closed)
  expect_error(
    shinyOAuth:::state_store_get_remove(cli, state),
    class = "shinyOAuth_config_error"
  )
})


test_that("fallback post-check catches no-op remove (exact TOCTOU vector)", {
  # This test reproduces the exact vulnerability reported in the issue:
  # cachem::cache_mem()$remove() returns TRUE even for absent keys.
  # A store where remove() says TRUE but doesn't actually delete must be
  # caught by the post-removal absence check.
  backing <- cachem::cache_mem()
  state <- "NOOP-REMOVE"
  key <- shinyOAuth:::state_cache_key(state)
  ssv <- list(browser_token = "bt_noop", pkce_code_verifier = "cv", nonce = "n")
  backing$set(key, ssv)

  noop_store <- list(
    get = function(key, missing = NULL) backing$get(key, missing = missing),
    set = function(key, value) backing$set(key, value),
    # remove() does nothing but returns TRUE (the vulnerability)
    remove = function(key) TRUE,
    info = function() list(max_age = 300)
  )

  cli <- make_client_with_store(noop_store)

  # Non-cache_mem store without $take() now errors before reaching the
  # fallback path, so we never even get to the no-op remove scenario.
  expect_error(
    shinyOAuth:::state_store_get_remove(cli, state),
    class = "shinyOAuth_config_error"
  )

  # Key is still in backing (nothing was consumed)
  expect_true(!is.null(backing$get(key, missing = NULL)))
})


test_that("OAuthClient rejects state_store with broken $take signature", {
  bad_store <- list(
    get = function(key, missing = NULL) NULL,
    set = function(key, value) invisible(NULL),
    remove = function(key) TRUE,
    # take() doesn't accept 'missing' argument → validator should catch this
    take = function(key) NULL,
    info = function() list(max_age = 60)
  )

  prov <- shinyOAuth::oauth_provider(
    name = "test",
    auth_url = "http://localhost:10097/auth",
    token_url = "http://localhost:10097/token"
  )
  expect_error(
    shinyOAuth::oauth_client(
      provider = prov,
      client_id = "client",
      client_secret = "secret",
      redirect_uri = "http://localhost:8100",
      state_store = bad_store
    ),
    regexp = "state_store\\$take"
  )
})
