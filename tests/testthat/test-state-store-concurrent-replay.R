# Tests for concurrent state replay prevention across processes
#
# These tests verify that the atomic [["take"]]() path prevents two concurrent
# consumers from both successfully consuming the same state entry when
# sharing a backend, and that non-atomic shared stores correctly error
# (fail closed).

# Test-only shared store: atomic directory creation elects one consumer.
# A barrier makes both callback handlers read the pending record before either
# can consume it. Claim directories remain until the test directory is removed.

make_shared_atomic_store <- function(dir) {
  if (!dir.exists(dir)) {
    dir.create(dir, recursive = TRUE)
  }

  key_path <- function(key) file.path(dir, paste0(key, ".rds"))
  list(
    get = function(key, missing = NULL) {
      f <- key_path(key)
      value <- if (file.exists(f)) readRDS(f) else missing
      if (file.exists(file.path(dir, "barrier"))) {
        file.create(file.path(dir, paste0("ready.", Sys.getpid())))
        deadline <- Sys.time() + 15
        while (length(list.files(dir, pattern = "^ready\\.")) < 2L) {
          if (Sys.time() > deadline) {
            stop("Callback race barrier timed out")
          }
          Sys.sleep(0.01)
        }
      }
      value
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
      if (dir.create(paste0(f, ".claimed"), showWarnings = FALSE)) {
        on.exit(unlink(f), add = TRUE)
        if (file.exists(f)) readRDS(f) else missing
      } else {
        missing
      }
    },
    info = function() list(max_age = 300)
  )
}


# -- Test: real concurrent callbacks across parallel workers --------------------

test_that("concurrent callbacks consume shared state and exchange the code once", {
  skip_on_cran()
  app <- webfakes::new_app()
  app[["locals"]][["exchanges"]] <- 0L
  app[["post"]]("/token", function(req, res) {
    app[["locals"]][["exchanges"]] <- app[["locals"]][["exchanges"]] + 1L
    res[["send_json"]](
      list(
        access_token = "access",
        token_type = "Bearer",
        expires_in = 300
      ),
      auto_unbox = TRUE
    )
  })
  app[["get"]]("/count", function(req, res) {
    res[["send_json"]](app[["locals"]][["exchanges"]], auto_unbox = TRUE)
  })
  server <- webfakes::new_app_process(app)
  on.exit(server[["stop"]](), add = TRUE)
  tmp <- withr::local_tempdir()
  store <- make_shared_atomic_store(tmp)
  make_client <- function(store, url) {
    shinyOAuth::oauth_client(
      shinyOAuth::oauth_provider(
        name = "callback-race",
        auth_url = paste0(url, "/auth"),
        token_url = paste0(url, "/token")
      ),
      client_id = "client",
      client_secret = "secret",
      redirect_uri = "http://localhost:8100",
      state_store = store,
      state_key = paste(rep("test-state-key", 5), collapse = "")
    )
  }
  url <- sub("/$", "", server[["url"]]())
  client <- make_client(store, url)
  browser_token <- paste(rep("ab", 64), collapse = "")
  auth_url <- shinyOAuth:::prepare_call(client, browser_token = browser_token)
  payload <- shiny::parseQueryString(sub("^[^?]*\\?", "", auth_url))[["state"]]
  state <- shinyOAuth:::state_decrypt_gcm(payload, key = client@state_key)[[
    "state"
  ]]
  key <- shinyOAuth:::state_cache_key(state)
  expect_type(store[["get"]](key), "list")
  cl <- parallel::makePSOCKcluster(2)
  on.exit(parallel::stopCluster(cl), add = TRUE)
  parallel::clusterCall(cl, function(lib) .libPaths(lib), .libPaths())
  file.create(file.path(tmp, "barrier"))
  results <- parallel::parLapply(
    cl,
    seq_len(2),
    function(i, dir, url, make_store, make_client, payload, browser_token) {
      options(
        shinyOAuth.skip_browser_token = FALSE,
        shinyOAuth.allow_non_atomic_state_store = FALSE
      )
      tryCatch(
        {
          token <- shinyOAuth::handle_callback(
            make_client(make_store(dir), url),
            code = "authorization-code",
            state = payload,
            browser_token = browser_token
          )
          list(success = TRUE, access_token = token@access_token)
        },
        error = function(e) {
          list(success = FALSE, class = class(e), message = conditionMessage(e))
        }
      )
    },
    dir = tmp,
    url = url,
    make_store = make_shared_atomic_store,
    make_client = make_client,
    payload = payload,
    browser_token = browser_token
  )
  successes <- vapply(results, function(r) isTRUE(r[["success"]]), logical(1))
  expect_equal(
    sum(successes),
    1L,
    info = paste(capture.output(str(results)), collapse = "\n")
  )
  expect_length(list.files(tmp, pattern = "^ready\\."), 2L)
  if (sum(successes) == 1L) {
    expect_identical(results[[which(successes)]][["access_token"]], "access")
    expect_contains(
      results[[which(!successes)]][["class"]],
      "shinyOAuth_state_error"
    )
  }
  expect_equal(
    httr2::resp_body_json(httr2::req_perform(httr2::request(paste0(
      url,
      "/count"
    )))),
    1L
  )
  unlink(file.path(tmp, "barrier"))
  expect_null(store[["get"]](key))
})


# -- Test: non-atomic shared store errors (fail closed) ---------------------

test_that("shared store without $take() errors at consume time (not just warns)", {
  skip_on_cran()

  # A custom shared-like store without [["take"]]() — non-cache_mem
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
  store[["set"]](key, shinyOAuth:::state_store_seal(ssv, cli, state))

  # Must error (shinyOAuth_config_error), not just warn
  expect_error(
    shinyOAuth:::state_store_get_remove(cli, state),
    class = "shinyOAuth_config_error"
  )

  # The entry should still be in the store (nothing was consumed)
  expect_false(is.null(store[["get"]](key, missing = NULL)))
})


# -- Test: cache_disk without [["take"]]() errors (fail closed) ------------------

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
  disk[["set"]](key, shinyOAuth:::state_store_seal(ssv, cli, state))

  # cache_disk without [["take"]]() must error
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
  mem[["set"]](key, ssv)

  # cache_mem is per-process; fallback is safe, no error
  out <- shinyOAuth:::state_store_get_remove(cli, state)
  expect_equal(out[["browser_token"]], "bt")

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
  store[["set"]](key, shinyOAuth:::state_store_seal(ssv, cli, state))

  # Without the option, must error
  expect_error(
    shinyOAuth:::state_store_get_remove(cli, state),
    class = "shinyOAuth_config_error"
  )

  # Entry should still be there (error happened before consume)
  expect_false(is.null(store[["get"]](key, missing = NULL)))

  # With the option enabled, should succeed with a warning
  withr::local_options(shinyOAuth.allow_non_atomic_state_store = TRUE)
  expect_warning(
    {
      out <- shinyOAuth:::state_store_get_remove(cli, state)
    },
    class = "shinyOAuth_non_atomic_state_store_warning"
  )
  expect_equal(out[["browser_token"]], "bt_opt")

  # Entry should be consumed (removed)
  expect_null(store[["get"]](key, missing = NULL))
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
  disk[["set"]](key, shinyOAuth:::state_store_seal(ssv, cli, state))

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
  expect_equal(out[["browser_token"]], "bt_disk")
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
  store[["set"]](key, shinyOAuth:::state_store_seal(ssv, cli, state))

  withr::local_options(shinyOAuth.allow_non_atomic_state_store = FALSE)

  expect_error(
    shinyOAuth:::state_store_get_remove(cli, state),
    class = "shinyOAuth_config_error"
  )
})


test_that("allow_non_atomic_state_store does not affect stores with $take()", {
  skip_on_cran()

  # A store with [["take"]]() should use the atomic path regardless of the option
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
  store[["set"]](key, shinyOAuth:::state_store_seal(ssv, cli, state))

  # Should succeed via atomic [["take"]](), no warning
  withr::local_options(shinyOAuth.allow_non_atomic_state_store = TRUE)
  expect_no_warning({
    out <- shinyOAuth:::state_store_get_remove(cli, state)
  })
  expect_equal(out[["browser_token"]], "bt_take")
})
