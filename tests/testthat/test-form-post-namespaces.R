test_that("shared callback storage isolates clients, providers, keys and modules", {
  for (difference in c("client", "provider", "key", "module")) {
    first <- make_test_client(response_mode = "form_post")
    second <- first
    second_id <- "auth"
    if (difference == "client") {
      second@client_id <- "another-client"
    }
    if (difference == "provider") {
      second@provider@issuer <- "https://another.example.com"
    }
    if (difference == "key") {
      second@state_key <- strrep("different-key", 4)
    }
    if (difference == "module") {
      second_id <- "another-module"
    }
    backing <- cachem::cache_mem(max_age = Inf, max_n = Inf)
    shared <- custom_cache(
      get = backing$get,
      set = backing$set,
      remove = backing$remove,
      take = function(key, missing = NULL) {
        value <- backing$get(key, missing = missing)
        backing$remove(key)
        value
      },
      info = function() list(max_age = 300)
    )
    first@state_store <- shared
    second@state_store <- shared
    pending <- oauth_form_post_store_set(
      second,
      second_id,
      list(code = "pending", state = "same-partition")
    )
    pending_key <- oauth_form_post_cache_key(second_id, pending, second)
    original <- backing$get(pending_key)
    for (i in seq_len(24L)) {
      oauth_form_post_store_set(
        first,
        "auth",
        list(code = "other", state = "same-partition")
      )
    }
    expect_identical(backing$get(pending_key), original)
    expect_length(backing$keys(), 9L)
    expect_identical(
      oauth_form_post_store_take(second, second_id, pending)$code,
      "pending"
    )
    expect_false(grepl(
      "another-client|another.example|another-module|different-key",
      pending_key
    ))
  }
})

test_that("atomic callback claims preserve concurrent occupants and enforce namespace capacity", {
  client <- make_test_client(response_mode = "form_post")
  backing <- cachem::cache_mem(max_age = Inf)
  calls <- 0L
  client@state_store <- custom_cache(
    get = backing$get,
    set = function(...) stop("non-atomic write"),
    remove = backing$remove,
    take = function(key, missing = NULL) {
      value <- backing$get(key, missing = missing)
      backing$remove(key)
      value
    },
    info = function() list(max_age = 300),
    set_if_absent = function(key, value, ttl = NULL) {
      expect_lte(ttl, 120)
      calls <<- calls + 1L
      if (calls == 1L) {
        backing$set(key, "concurrent-occupant")
      }
      if (!is.null(backing$get(key, missing = NULL))) {
        return(FALSE)
      }
      backing$set(key, value)
      TRUE
    }
  )
  handles <- vapply(
    seq_len(7L),
    function(i) {
      oauth_form_post_store_set(
        client,
        "auth",
        list(code = "pending", state = "one-partition")
      )
    },
    ""
  )
  expect_length(unique(handles), 7L)
  expect_length(backing$keys(), 8L)
  expect_error(
    oauth_form_post_store_set(
      client,
      "auth",
      list(code = "extra", state = "one-partition")
    ),
    "partition is full"
  )
  expect_true(any(vapply(
    backing$keys(),
    function(key) identical(backing$get(key), "concurrent-occupant"),
    logical(1)
  )))
  expect_identical(
    oauth_form_post_store_take(client, "auth", handles[[1L]])$code,
    "pending"
  )
  expect_silent(oauth_form_post_store_set(
    client,
    "auth",
    list(code = "new", state = "one-partition")
  ))
})
