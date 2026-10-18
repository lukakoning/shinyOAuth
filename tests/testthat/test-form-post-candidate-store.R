test_that("candidate storage has a per-namespace bound even without backend expiry", {
  client <- make_test_client(response_mode = "form_post")
  backing <- cachem::cache_mem(max_age = Inf, max_n = Inf)
  client@state_store <- form_post_test_atomic_cache(backing)
  # Cover and fill every partition, then overflow a full one. The custom store has
  # neither a key-listing method nor an expiry policy to enforce this for us.
  states <- paste0("candidate-pool-fixture-", seq_len(16384L))
  partitions <- vapply(
    states,
    function(state) {
      shinyOAuth:::oauth_form_post_candidate_slots(state)[[1L]]
    },
    integer(1)
  )
  states <- states[!duplicated(partitions)]
  expect_length(states, 1024L)
  for (state in states) {
    for (i in seq_len(2L)) {
      shinyOAuth:::oauth_form_post_store_set(
        client,
        "auth",
        list(code = "fixture", state = state)
      )
    }
  }
  expect_error(
    shinyOAuth:::oauth_form_post_store_set(
      client, "auth", list(code = "overflow", state = states[[1L]])
    ),
    "partition is full"
  )
  expect_length(backing[["keys"]](), 2048L)
})

test_that("malformed and pre-upgrade handles are rejected before store access", {
  client <- make_test_client(response_mode = "form_post")
  store <- client@state_store
  store[["get"]] <- function(...) {
    testthat::fail("Invalid handles must not query storage")
  }
  client@state_store <- store
  suffix <- shinyOAuth:::random_urlsafe(43)
  for (handle in c(
    suffix,
    "missing-handle",
    paste0("fp1_0000_", suffix),
    paste0("fp1_2049_", suffix),
    paste0("fp1_0001_", suffix, "x")
  )) {
    expect_error(
      shinyOAuth:::oauth_form_post_store_take(client, "auth", handle),
      "Invalid form_post callback handle"
    )
  }
})

test_that("custom callback stores require atomic insertion before writing candidates", {
  client <- make_test_client(response_mode = "form_post")
  backing <- client@state_store
  client@state_store <- custom_cache(
    get = backing[["get"]], set = backing[["set"]], remove = backing[["remove"]],
    take = function(key, missing = NULL) {
      value <- backing[["get"]](key, missing = missing)
      backing[["remove"]](key)
      value
    }
  )
  expect_error(
    shinyOAuth:::oauth_form_post_store_set(
      client, "auth", list(code = "fixture", state = "fixture-state")
    ),
    class = "shinyOAuth_config_error", regexp = "requires atomic.*set_if_absent"
  )
  expect_length(backing[["keys"]](), 0L)
})

test_that("candidate handles have a short expiry independent of store TTL", {
  client <- make_test_client(response_mode = "form_post")
  posted_at <- Sys.time()
  handle <- testthat::with_mocked_bindings(
    Sys.time = function() posted_at,
    .package = "base",
    shinyOAuth:::oauth_form_post_store_set(
      client,
      "auth",
      list(code = "fixture", state = "fixture-state")
    )
  )
  expect_error(
    testthat::with_mocked_bindings(
      Sys.time = function() posted_at + 121,
      .package = "base",
      shinyOAuth:::oauth_form_post_store_take(client, "auth", handle)
    ),
    "form_post callback handle expired"
  )
  expect_error(
    shinyOAuth:::oauth_form_post_store_take(client, "auth", handle),
    "missing or already consumed"
  )
})

test_that("expired and foreign-module handles cannot consume a replacement", {
  client <- make_test_client(response_mode = "form_post")
  # Both candidates remain valid until their own lifetime has elapsed.
  now <- Sys.time()
  local_mocked_bindings(Sys.time = function() now, .package = "base")
  handles <- vapply(
    seq_len(2L),
    function(i) {
      shinyOAuth:::oauth_form_post_store_set(
        client,
        "auth",
        list(code = paste0("response-", i), state = "fixture-state")
      )
    },
    character(1)
  )
  expect_length(unique(handles), 2L)
  expect_error(
    shinyOAuth:::oauth_form_post_store_set(
      client, "auth", list(code = "overflow", state = "fixture-state")
    ),
    "partition is full"
  )
  now <- now + 121
  replacement <- shinyOAuth:::oauth_form_post_store_set(
    client, "auth", list(code = "replacement", state = "fixture-state")
  )
  expect_error(
    shinyOAuth:::oauth_form_post_store_take(client, "auth", handles[[1L]]),
    "handle mismatch"
  )
  expect_error(
    shinyOAuth:::oauth_form_post_store_take(client, "other", replacement),
    "missing or already consumed"
  )
  payload <- shinyOAuth:::oauth_form_post_store_take(
    client,
    "auth",
    replacement
  )
  expect_identical(payload[["code"]], "replacement")
  expect_error(
    shinyOAuth:::oauth_form_post_store_take(client, "auth", replacement),
    "missing or already consumed"
  )
})

test_that("a slot replacement racing atomic take never supplies another response", {
  client <- make_test_client(response_mode = "form_post")
  handle <- shinyOAuth:::oauth_form_post_store_set(
    client,
    "auth",
    list(code = "original", state = "fixture-state")
  )
  key <- shinyOAuth:::oauth_form_post_cache_key("auth", handle, client)
  replacement_handle <- paste0(
    substr(handle, 1L, 9L),
    shinyOAuth:::random_urlsafe(43)
  )
  replacement <- shinyOAuth:::oauth_form_post_seal_payload(
    client,
    "auth",
    replacement_handle,
    list(code = "replacement", state = "fixture-state")
  )
  backing <- client@state_store
  takes <- 0L
  client@state_store <- custom_cache(
    get = backing[["get"]],
    set = backing[["set"]],
    remove = backing[["remove"]],
    take = function(key, missing = NULL) {
      takes <<- takes + 1L
      # Interleave another writer after the preliminary authenticated read.
      backing[["set"]](key, replacement)
      value <- backing[["get"]](key, missing = missing)
      backing[["remove"]](key)
      value
    }
  )
  expect_error(
    shinyOAuth:::oauth_form_post_store_take(client, "auth", handle),
    "handle mismatch"
  )
  expect_identical(takes, 1L)
  expect_null(backing[["get"]](key, missing = NULL))
})

test_that("explicit non-atomic fallback still binds racing candidate identities", {
  local_options(shinyOAuth.allow_non_atomic_state_store = TRUE)
  client <- make_test_client(response_mode = "form_post")
  backing <- client@state_store
  interleave <- TRUE
  concurrent_handle <- NULL
  client@state_store <- custom_cache(
    get = backing[["get"]],
    remove = backing[["remove"]],
    info = backing[["info"]],
    set = function(key, value) {
      if (interleave) {
        interleave <<- FALSE
        concurrent_handle <<- shinyOAuth:::oauth_form_post_store_set(
          client,
          "auth",
          list(code = "concurrent", state = "fixture-state")
        )
      }
      backing[["set"]](key, value)
    },
    take = function(key, missing = NULL) {
      value <- backing[["get"]](key, missing = missing)
      backing[["remove"]](key)
      value
    }
  )
  handle <- shinyOAuth:::oauth_form_post_store_set(
    client,
    "auth",
    list(code = "original", state = "fixture-state")
  )
  expect_false(identical(handle, concurrent_handle))
  expect_length(backing[["keys"]](), 1L)
  expect_error(
    shinyOAuth:::oauth_form_post_store_take(client, "auth", concurrent_handle),
    "handle mismatch"
  )
  expect_identical(
    shinyOAuth:::oauth_form_post_store_take(client, "auth", handle)[["code"]],
    "original"
  )
})

test_that("sibling cleanup preserves other transactions sharing a partition", {
  client <- make_test_client(response_mode = "form_post")
  states <- paste0("cleanup-fixture-", seq_len(1025L))
  partitions <- vapply(
    states,
    function(state) {
      shinyOAuth:::oauth_form_post_candidate_slots(state)[[1L]]
    },
    integer(1)
  )
  shared <- partitions[duplicated(partitions)][[1L]]
  states <- states[partitions == shared][1:2]
  handles <- vapply(
    states,
    function(state) {
      shinyOAuth:::oauth_form_post_store_set(
        client,
        "auth",
        list(code = state, state = state)
      )
    },
    character(1)
  )
  # Attach authentic state metadata as the POST boundary does. No live state
  # is needed for this narrow cleanup test.
  for (i in seq_along(handles)) {
    key <- shinyOAuth:::oauth_form_post_cache_key("auth", handles[[i]], client)
    envelope <- shinyOAuth:::oauth_form_post_candidate_envelope(
      client,
      client@state_store[["get"]](key)
    )
    envelope[["payload"]][["state_payload"]] <- list(state = states[[i]])
    client@state_store[["set"]](
      key,
      shinyOAuth:::state_encrypt_gcm(envelope, client@state_key)
    )
  }
  shinyOAuth:::oauth_form_post_store_remove_siblings(client, states[[1L]])
  expect_error(
    shinyOAuth:::oauth_form_post_store_take(client, "auth", handles[[1L]]),
    "missing or already consumed"
  )
  expect_identical(
    shinyOAuth:::oauth_form_post_store_take(client, "auth", handles[[2L]])[[
      "code"
    ]],
    states[[2L]]
  )
})

test_that("shared sibling cleanup cannot delete a racing replacement", {
  client <- make_test_client(response_mode = "form_post")
  backing <- client@state_store
  handle <- shinyOAuth:::oauth_form_post_store_set(
    client, "auth", list(code = "pending", state = "fixture-state")
  )
  key <- shinyOAuth:::oauth_form_post_cache_key("auth", handle, client)
  original <- backing[["get"]](key)
  store <- form_post_test_atomic_cache(backing)
  client@state_store <- custom_cache(
    get = store[["get"]], set = store[["set"]],
    remove = function(...) stop("unsafe shared cleanup"),
    take = store[["take"]], set_if_absent = store[["set_if_absent"]],
    info = store[["info"]]
  )
  expect_silent(shinyOAuth:::oauth_form_post_store_remove_siblings(
    client, "fixture-state", "auth"
  ))
  expect_identical(backing[["get"]](key), original)
})
