# Tests for concurrent state replay prevention across processes
#
# These tests verify that the atomic $take() path prevents two concurrent
# consumers from both successfully consuming the same state entry when
# sharing a backend, and that non-atomic shared stores correctly error
# (fail closed).

# -- Helper: file-backed store with atomic $take() via file.rename() ---------
#
# file.rename() is atomic on POSIX and effectively atomic on NTFS, making this
# a simple but realistic simulation of atomic consume semantics (like Redis
# GETDEL or SQL DELETE ... RETURNING).

make_shared_atomic_store <- function(dir) {
  if (!dir.exists(dir)) {
    dir.create(dir, recursive = TRUE)
  }

  key_path <- function(key) file.path(dir, paste0(key, ".rds"))
  taken_path <- function(key) file.path(dir, paste0(key, ".taken"))

  list(
    get = function(key, missing = NULL) {
      f <- key_path(key)
      if (file.exists(f)) readRDS(f) else missing
    },
    set = function(key, value) {
      saveRDS(value, key_path(key))
      invisible(NULL)
    },
    remove = function(key) {
      f <- key_path(key)
      if (file.exists(f)) file.remove(f) else FALSE
    },
    take = function(key, missing = NULL) {
      f <- key_path(key)
      t <- taken_path(key)
      # Atomic: rename the file so only one process can succeed
      if (file.rename(f, t)) {
        on.exit(unlink(t), add = TRUE)
        readRDS(t)
      } else {
        missing
      }
    },
    info = function() list(max_age = 300)
  )
}


# -- Test: concurrent $take() across parallel workers -----------------------

test_that("atomic $take() prevents concurrent replay across parallel workers", {
  skip_on_cran()
  skip_if(
    identical(.Platform$OS.type, "windows"),
    "file.rename() not reliably atomic on Windows"
  )

  tmp <- withr::local_tempdir()
  store <- make_shared_atomic_store(tmp)

  state <- "CONCURRENT-TAKE"
  key <- shinyOAuth:::state_cache_key(state)
  ssv <- list(
    browser_token = "bt_conc",
    pkce_code_verifier = "cv",
    nonce = "nn"
  )
  store$set(key, ssv)

  # Verify the entry exists before the race
  expect_false(is.null(store$get(key, missing = NULL)))

  # Spin up a 2-worker cluster; each worker attempts to $take() the same key
  cl <- parallel::makePSOCKcluster(2)
  on.exit(parallel::stopCluster(cl), add = TRUE)

  results <- parallel::parLapply(
    cl,
    seq_len(2),
    function(i, dir, key) {
      # Reconstruct the store inside the worker (closures don't serialize)
      key_path <- function(k) file.path(dir, paste0(k, ".rds"))
      # Per-worker unique taken path to avoid destination collision
      taken_path <- function(k) {
        file.path(dir, paste0(k, ".taken.", Sys.getpid()))
      }

      f <- key_path(key)
      t <- taken_path(key)
      if (file.rename(f, t)) {
        val <- tryCatch(readRDS(t), error = function(e) NULL)
        unlink(t)
        list(success = TRUE, value = val)
      } else {
        list(success = FALSE, value = NULL)
      }
    },
    dir = tmp,
    key = key
  )

  # Exactly one worker should have succeeded
  successes <- vapply(results, function(r) isTRUE(r$success), logical(1))
  expect_equal(sum(successes), 1L)

  # The winning worker should have the correct value
  winner <- results[[which(successes)]]
  expect_equal(winner$value$browser_token, "bt_conc")
})


# -- Test: non-atomic shared store errors (fail closed) ---------------------

test_that("shared store without $take() errors at consume time (not just warns)", {
  skip_on_cran()

  # A custom shared-like store without $take() — non-cache_mem
  env <- new.env(parent = emptyenv())
  store <- list(
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
    info = function() list(max_age = 300)
  )

  prov <- shinyOAuth::oauth_provider(
    name = "test",
    auth_url = "http://localhost:10050/auth",
    token_url = "http://localhost:10050/token"
  )
  cli <- shinyOAuth::oauth_client(
    provider = prov,
    client_id = "client",
    client_secret = "secret",
    redirect_uri = "http://localhost:8100",
    state_store = store
  )

  state <- "REPLAY-FAIL-CLOSED"
  key <- shinyOAuth:::state_cache_key(state)
  ssv <- list(browser_token = "bt", pkce_code_verifier = "cv", nonce = "nn")
  store$set(key, ssv)

  # Must error (shinyOAuth_config_error), not just warn
  expect_error(
    shinyOAuth:::state_store_get_remove(cli, state),
    class = "shinyOAuth_config_error"
  )

  # The entry should still be in the store (nothing was consumed)
  expect_false(is.null(store$get(key, missing = NULL)))
})


# -- Test: cache_disk without $take() errors (fail closed) ------------------

test_that("cache_disk() without $take() errors at consume time", {
  skip_on_cran()

  tmp <- withr::local_tempdir()
  disk <- cachem::cache_disk(dir = tmp, max_age = 60)

  prov <- shinyOAuth::oauth_provider(
    name = "test",
    auth_url = "http://localhost:10051/auth",
    token_url = "http://localhost:10051/token"
  )
  cli <- shinyOAuth::oauth_client(
    provider = prov,
    client_id = "client",
    client_secret = "secret",
    redirect_uri = "http://localhost:8100",
    state_store = disk
  )

  state <- "DISK-FAIL-CLOSED"
  key <- shinyOAuth:::state_cache_key(state)
  ssv <- list(browser_token = "bt", pkce_code_verifier = "cv", nonce = "nn")
  disk$set(key, ssv)

  # cache_disk without $take() must error
  expect_error(
    shinyOAuth:::state_store_get_remove(cli, state),
    class = "shinyOAuth_config_error"
  )
})


# -- Test: cache_mem fallback still works (per-process safe) ----------------

test_that("cache_mem fallback works without $take() (per-process safe)", {
  skip_on_cran()

  mem <- cachem::cache_mem(max_age = 60)

  prov <- shinyOAuth::oauth_provider(
    name = "test",
    auth_url = "http://localhost:10052/auth",
    token_url = "http://localhost:10052/token"
  )
  cli <- shinyOAuth::oauth_client(
    provider = prov,
    client_id = "client",
    client_secret = "secret",
    redirect_uri = "http://localhost:8100",
    state_store = mem
  )

  state <- "MEM-FALLBACK-OK"
  key <- shinyOAuth:::state_cache_key(state)
  ssv <- list(browser_token = "bt", pkce_code_verifier = "cv", nonce = "nn")
  mem$set(key, ssv)

  # cache_mem is per-process; fallback is safe, no error
  out <- shinyOAuth:::state_store_get_remove(cli, state)
  expect_equal(out$browser_token, "bt")

  # Second call must fail (single-use consumed)
  expect_error(
    shinyOAuth:::state_store_get_remove(cli, state),
    class = "shinyOAuth_state_error"
  )
})


# -- Tests for allow_non_atomic_state_store option --------------------------

test_that("allow_non_atomic_state_store option enables fallback for shared stores", {
  skip_on_cran()
  rlang::reset_warning_verbosity("shinyOAuth_non_atomic_state_store")

  env <- new.env(parent = emptyenv())
  store <- list(
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
    info = function() list(max_age = 300)
  )

  prov <- shinyOAuth::oauth_provider(
    name = "test",
    auth_url = "http://localhost:10053/auth",
    token_url = "http://localhost:10053/token"
  )
  cli <- shinyOAuth::oauth_client(
    provider = prov,
    client_id = "client",
    client_secret = "secret",
    redirect_uri = "http://localhost:8100",
    state_store = store
  )

  state <- "OPT-IN-FALLBACK"
  key <- shinyOAuth:::state_cache_key(state)
  ssv <- list(browser_token = "bt_opt", pkce_code_verifier = "cv", nonce = "nn")
  store$set(key, ssv)

  # Without the option, must error
  expect_error(
    shinyOAuth:::state_store_get_remove(cli, state),
    class = "shinyOAuth_config_error"
  )

  # Entry should still be there (error happened before consume)
  expect_false(is.null(store$get(key, missing = NULL)))

  # With the option enabled, should succeed with a warning
  withr::local_options(shinyOAuth.allow_non_atomic_state_store = TRUE)
  expect_warning(
    {
      out <- shinyOAuth:::state_store_get_remove(cli, state)
    },
    class = "shinyOAuth_non_atomic_state_store_warning"
  )
  expect_equal(out$browser_token, "bt_opt")

  # Entry should be consumed (removed)
  expect_null(store$get(key, missing = NULL))
})


test_that("allow_non_atomic_state_store option works with cache_disk", {
  skip_on_cran()
  rlang::reset_warning_verbosity("shinyOAuth_non_atomic_state_store")

  tmp <- withr::local_tempdir()
  disk <- cachem::cache_disk(dir = tmp, max_age = 60)

  prov <- shinyOAuth::oauth_provider(
    name = "test",
    auth_url = "http://localhost:10054/auth",
    token_url = "http://localhost:10054/token"
  )
  cli <- shinyOAuth::oauth_client(
    provider = prov,
    client_id = "client",
    client_secret = "secret",
    redirect_uri = "http://localhost:8100",
    state_store = disk
  )

  state <- "DISK-OPT-IN"
  key <- shinyOAuth:::state_cache_key(state)
  ssv <- list(
    browser_token = "bt_disk",
    pkce_code_verifier = "cv",
    nonce = "nn"
  )
  disk$set(key, ssv)

  # Without the option, errors
  expect_error(
    shinyOAuth:::state_store_get_remove(cli, state),
    class = "shinyOAuth_config_error"
  )

  # With option, succeeds with warning
  withr::local_options(shinyOAuth.allow_non_atomic_state_store = TRUE)
  expect_warning(
    {
      out <- shinyOAuth:::state_store_get_remove(cli, state)
    },
    class = "shinyOAuth_non_atomic_state_store_warning"
  )
  expect_equal(out$browser_token, "bt_disk")
})


test_that("allow_non_atomic_state_store = FALSE (explicit) still errors", {
  skip_on_cran()

  env <- new.env(parent = emptyenv())
  store <- list(
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
      }
      TRUE
    },
    info = function() list(max_age = 300)
  )

  prov <- shinyOAuth::oauth_provider(
    name = "test",
    auth_url = "http://localhost:10055/auth",
    token_url = "http://localhost:10055/token"
  )
  cli <- shinyOAuth::oauth_client(
    provider = prov,
    client_id = "client",
    client_secret = "secret",
    redirect_uri = "http://localhost:8100",
    state_store = store
  )

  state <- "EXPLICIT-FALSE"
  key <- shinyOAuth:::state_cache_key(state)
  ssv <- list(browser_token = "bt", pkce_code_verifier = "cv", nonce = "nn")
  store$set(key, ssv)

  withr::local_options(shinyOAuth.allow_non_atomic_state_store = FALSE)

  expect_error(
    shinyOAuth:::state_store_get_remove(cli, state),
    class = "shinyOAuth_config_error"
  )
})


test_that("allow_non_atomic_state_store does not affect stores with $take()", {
  skip_on_cran()

  # A store with $take() should use the atomic path regardless of the option
  env <- new.env(parent = emptyenv())
  store <- list(
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
      }
      TRUE
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
    info = function() list(max_age = 300)
  )

  prov <- shinyOAuth::oauth_provider(
    name = "test",
    auth_url = "http://localhost:10056/auth",
    token_url = "http://localhost:10056/token"
  )
  cli <- shinyOAuth::oauth_client(
    provider = prov,
    client_id = "client",
    client_secret = "secret",
    redirect_uri = "http://localhost:8100",
    state_store = store
  )

  state <- "TAKE-IGNORES-OPT"
  key <- shinyOAuth:::state_cache_key(state)
  ssv <- list(
    browser_token = "bt_take",
    pkce_code_verifier = "cv",
    nonce = "nn"
  )
  store$set(key, ssv)

  # Should succeed via atomic $take(), no warning
  withr::local_options(shinyOAuth.allow_non_atomic_state_store = TRUE)
  expect_no_warning({
    out <- shinyOAuth:::state_store_get_remove(cli, state)
  })
  expect_equal(out$browser_token, "bt_take")
})
