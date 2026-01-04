test_that("state_store_get_remove errors on missing entry and audits lookup failure", {
  # Capture audit events
  events <- list()
  old <- options(shinyOAuth.audit_hook = function(e) {
    events[[length(events) + 1]] <<- e
  })
  on.exit(options(old), add = TRUE)

  prov <- shinyOAuth::oauth_provider_github()
  client <- shinyOAuth::oauth_client(
    prov,
    client_id = "id",
    client_secret = "secret",
    redirect_uri = "http://localhost:8100",
    state_store = cachem::cache_mem(max_age = 60),
    state_key = paste0(
      "0123456789abcdefghijklmnopqrstuvwxyz",
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    )
  )

  # Random state that is not in the store
  st <- paste0("s-", paste(sample(letters, 12, TRUE), collapse = ""))
  expect_error(
    shinyOAuth:::state_store_get_remove(client, st),
    class = "shinyOAuth_state_error"
  )

  # Assert an audit_state_store_lookup_failed event was emitted
  types <- vapply(events, function(e) as.character(e$type), character(1))
  expect_true(any(grepl("^audit_state_store_lookup_failed$", types)))
})

test_that("state_store_get_remove errors when remove fails and audits removal failure", {
  # Capture audit events
  events <- list()
  old <- options(shinyOAuth.audit_hook = function(e) {
    events[[length(events) + 1]] <<- e
  })
  on.exit(options(old), add = TRUE)

  # Backend that throws on remove
  mem <- cachem::cache_mem(max_age = 60)
  removing <- FALSE
  bad_remove <- function(key) {
    stop("remove_failed")
  }
  store <- shinyOAuth::custom_cache(
    get = function(key, missing = NULL) mem$get(key, missing = missing),
    set = function(key, value) mem$set(key, value),
    remove = bad_remove,
    info = function() list(max_age = 60)
  )

  prov <- shinyOAuth::oauth_provider_github()
  client <- shinyOAuth::oauth_client(
    prov,
    client_id = "id",
    client_secret = "secret",
    redirect_uri = "http://localhost:8100",
    state_store = store,
    state_key = paste0(
      "0123456789abcdefghijklmnopqrstuvwxyz",
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    )
  )

  # Put an entry
  st <- "strict-state-1"
  key <- shinyOAuth:::state_cache_key(st)
  mem$set(
    key,
    list(browser_token = "bt", pkce_code_verifier = "cv", nonce = "n")
  )

  # Expect error due to remove failure
  expect_error(
    shinyOAuth:::state_store_get_remove(client, st),
    class = "shinyOAuth_state_error"
  )

  # Assert an audit_state_store_removal_failed event was emitted
  types <- vapply(events, function(e) as.character(e$type), character(1))
  expect_true(any(grepl("^audit_state_store_removal_failed$", types)))
})

test_that("state_store_get_remove errors on malformed stored value and audits lookup failure", {
  # Capture audit events
  events <- list()
  old <- options(shinyOAuth.audit_hook = function(e) {
    events[[length(events) + 1]] <<- e
  })
  on.exit(options(old), add = TRUE)

  prov <- shinyOAuth::oauth_provider_github()
  client <- shinyOAuth::oauth_client(
    prov,
    client_id = "id",
    client_secret = "secret",
    redirect_uri = "http://localhost:8100",
    state_store = cachem::cache_mem(max_age = 60),
    state_key = paste0(
      "0123456789abcdefghijklmnopqrstuvwxyz",
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    )
  )

  st <- "malformed-state-1"
  key <- shinyOAuth:::state_cache_key(st)
  client@state_store$set(key, "not-a-list")

  expect_error(
    shinyOAuth:::state_store_get_remove(client, st),
    class = "shinyOAuth_state_error"
  )

  # Assert an audit_state_store_lookup_failed event was emitted
  types <- vapply(events, function(e) as.character(e$type), character(1))
  expect_true(any(grepl("^audit_state_store_lookup_failed$", types)))
})

test_that("state_store_get_remove errors on missing required fields", {
  # Capture audit events
  events <- list()
  old <- options(shinyOAuth.audit_hook = function(e) {
    events[[length(events) + 1]] <<- e
  })

  on.exit(options(old), add = TRUE)

  prov <- shinyOAuth::oauth_provider_github()
  client <- shinyOAuth::oauth_client(
    prov,
    client_id = "id",
    client_secret = "secret",
    redirect_uri = "http://localhost:8100",
    state_store = cachem::cache_mem(max_age = 60),
    state_key = paste0(
      "0123456789abcdefghijklmnopqrstuvwxyz",
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    )
  )

  # Entry missing all required fields
  st <- "missing-fields-state"
  key <- shinyOAuth:::state_cache_key(st)
  client@state_store$set(key, list(some_other_field = "value"))

  expect_error(
    shinyOAuth:::state_store_get_remove(client, st),
    regexp = "malformed.*missing required fields",
    class = "shinyOAuth_state_error"
  )

  # Entry missing only browser_token
  st2 <- "partial-fields-state"
  key2 <- shinyOAuth:::state_cache_key(st2)
  client@state_store$set(key2, list(pkce_code_verifier = "cv", nonce = "n"))

  expect_error(
    shinyOAuth:::state_store_get_remove(client, st2),
    regexp = "browser_token",
    class = "shinyOAuth_state_error"
  )

  # Assert an audit_state_store_lookup_failed event was emitted
  types <- vapply(events, function(e) as.character(e$type), character(1))
  expect_true(any(grepl("^audit_state_store_lookup_failed$", types)))
})

test_that("state_store_get_remove errors on invalid browser_token value", {
  # Capture audit events
  events <- list()
  old <- options(shinyOAuth.audit_hook = function(e) {
    events[[length(events) + 1]] <<- e
  })
  on.exit(options(old), add = TRUE)

  prov <- shinyOAuth::oauth_provider_github()
  client <- shinyOAuth::oauth_client(
    prov,
    client_id = "id",
    client_secret = "secret",
    redirect_uri = "http://localhost:8100",
    state_store = cachem::cache_mem(max_age = 60),
    state_key = paste0(
      "0123456789abcdefghijklmnopqrstuvwxyz",
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    )
  )

  # Entry with NULL browser_token
  st <- "null-browser-token"
  key <- shinyOAuth:::state_cache_key(st)
  client@state_store$set(
    key,
    list(browser_token = NULL, pkce_code_verifier = "cv", nonce = "n")
  )

  expect_error(
    shinyOAuth:::state_store_get_remove(client, st),
    regexp = "browser_token must be a non-empty string",
    class = "shinyOAuth_state_error"
  )

  # Entry with empty string browser_token
  st2 <- "empty-browser-token"
  key2 <- shinyOAuth:::state_cache_key(st2)
  client@state_store$set(
    key2,
    list(browser_token = "", pkce_code_verifier = "cv", nonce = "n")
  )

  expect_error(
    shinyOAuth:::state_store_get_remove(client, st2),
    regexp = "browser_token must be a non-empty string",
    class = "shinyOAuth_state_error"
  )

  # Assert an audit_state_store_lookup_failed event was emitted
  types <- vapply(events, function(e) as.character(e$type), character(1))
  expect_true(any(grepl("^audit_state_store_lookup_failed$", types)))
})
