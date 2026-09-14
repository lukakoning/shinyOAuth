test_that("structured authorization preserves exact state and ordinary wire semantics", {
  client <- make_test_client(scopes = c("read", "write"))
  prepared <- shinyOAuth:::prepare_authorization(client, valid_browser_token())
  expect_identical(
    prepared$state,
    parse_query_param(prepared$url, "state", TRUE)
  )
  expect_identical(parse_query_param(prepared$url, "scope", TRUE), "read write")
  payload <- shinyOAuth:::state_payload_decrypt_validate(client, prepared$state)
  expect_null(payload$transaction_context_digest)
  expect_identical(
    prepared$state_key,
    shinyOAuth:::state_cache_key(payload$state)
  )
  expect_gt(prepared$expires_at, Sys.time())
  expect_false(grepl(
    prepared$state,
    paste(capture.output(print(prepared)), collapse = ""),
    fixed = TRUE
  ))
})

test_that("managed context is bound to each transaction without changing its client", {
  client <- make_test_client()
  original <- client@provider@extra_auth_params
  context <- list(
    version = 1L,
    target_id = "site-a",
    owner_generation = "generation-a",
    profile = list(id = "oauth", version = 1L),
    resource = "https://api.example/fhir/R4"
  )
  first <- shinyOAuth:::prepare_authorization(
    client,
    valid_browser_token(),
    context
  )
  context$target_id <- "site-b"
  second <- shinyOAuth:::prepare_authorization(
    client,
    valid_browser_token(),
    context
  )
  first_payload <- shinyOAuth:::state_payload_decrypt_validate(
    client,
    first$state
  )
  first_record <- shinyOAuth:::state_store_get(client, first_payload$state)
  expect_identical(
    jsonlite::fromJSON(first_record$transaction_context)$target_id,
    "site-a"
  )
  expect_false(identical(first$state, second$state))
  expect_identical(client@provider@extra_auth_params, original)
  expect_false(grepl("site-a|generation-a|fhir/R4", first$url))
  expect_error(
    shinyOAuth:::state_store_consume_checked(
      client,
      first_payload$state,
      first_record,
      .transaction_context_digest = first_payload$transaction_context_digest
    ),
    "verified transaction context"
  )
  expect_identical(
    shinyOAuth:::state_store_get(client, first_payload$state),
    first_record
  )
  expect_identical(
    shinyOAuth:::state_store_consume_checked(
      client,
      first_payload$state,
      first_record,
      .transaction_context = first_record$transaction_context,
      .transaction_context_digest = first_payload$transaction_context_digest
    ),
    first_record
  )
  expect_error(
    shinyOAuth:::state_store_get(client, first_payload$state),
    class = "shinyOAuth_state_error"
  )
})

test_that("changed context fails before legacy callback exchange", {
  client <- make_test_client()
  prepared <- shinyOAuth:::prepare_authorization(
    client,
    valid_browser_token(),
    list(target = "site-a")
  )
  payload <- shinyOAuth:::state_payload_decrypt_validate(client, prepared$state)
  record <- shinyOAuth:::state_store_get(client, payload$state)
  calls <- 0L
  local_mocked_bindings(
    swap_code_for_token_set = function(...) {
      calls <<- calls + 1L
      stop("unexpected exchange")
    },
    .package = "shinyOAuth"
  )
  expect_error(
    handle_callback(
      client,
      "synthetic-code",
      prepared$state,
      valid_browser_token()
    ),
    class = "shinyOAuth_state_error"
  )
  record$transaction_context <- NULL
  client@state_store$set(prepared$state_key, record)
  expect_error(
    handle_callback(
      client,
      "synthetic-code",
      prepared$state,
      valid_browser_token()
    ),
    class = "shinyOAuth_state_error"
  )
  expect_identical(calls, 0L)
})

test_that("authorization context rejects live objects, duplicate fields and oversized data", {
  for (context in list(
    list(owner = new.env()),
    list(client = make_test_client()),
    list(callback = function() NULL),
    stats::setNames(list(1, 2), c("a", "a")),
    list(target = strrep("x", 4097)),
    list(generation = NA_real_)
  )) {
    expect_error(
      shinyOAuth:::authorization_context_json(context),
      "bounded named data list"
    )
  }
})

test_that("structured PAR preparation exposes state absent from the browser URL", {
  client <- make_test_client()
  client@provider@par_url <- "https://example.com/par"
  pushed <- NULL
  local_mocked_bindings(
    push_authorization_request = function(client, params) {
      pushed <<- params
      list(
        request_uri = "urn:ietf:params:oauth:request_uri:synthetic",
        expires_in = 60,
        expires_at = Sys.time() + 60
      )
    },
    .package = "shinyOAuth"
  )
  prepared <- shinyOAuth:::prepare_authorization(
    client,
    valid_browser_token(),
    list(target = "site-a")
  )
  expect_true(is.na(parse_query_param(prepared$url, "state")))
  expect_identical(prepared$state, pushed$state)
  expect_lte(
    as.numeric(difftime(prepared$expires_at, Sys.time(), units = "secs")),
    60
  )
  expect_null(pushed$transaction_context)
})

test_that("external managed context is sealed and failed publication removes pending state", {
  client <- make_test_client()
  memory <- cachem::cache_mem()
  client@state_store <- custom_cache(
    get = function(key, missing = NULL) memory$get(key, missing = missing),
    set = function(key, value) memory$set(key, value),
    remove = function(key) memory$remove(key),
    take = function(key, missing = NULL) {
      value <- memory$get(key, missing = missing)
      memory$remove(key)
      value
    }
  )
  prepared <- shinyOAuth:::prepare_authorization(
    client,
    valid_browser_token(),
    list(target = "site-a", owner = "synthetic-owner")
  )
  expect_identical(names(memory$get(prepared$state_key)), "sealed_state_record")
  expect_false(grepl(
    "synthetic-owner",
    paste(capture.output(str(memory$get(prepared$state_key))), collapse = "")
  ))
  before <- memory$keys()
  local_mocked_bindings(
    build_prepared_authorization = function(...) stop("publication failed"),
    .package = "shinyOAuth"
  )
  expect_error(
    shinyOAuth:::prepare_authorization(
      client,
      valid_browser_token(),
      list(target = "site-b")
    ),
    "publication failed"
  )
  expect_identical(memory$keys(), before)
})

test_that("literal scope evaluator is versioned and does not infer SMART semantics", {
  expect_identical(
    shinyOAuth:::evaluate_scope_coverage(c("b", "a", "a"), "b a")$status,
    "covered"
  )
  expect_identical(
    shinyOAuth:::evaluate_scope_coverage(
      "patient/Patient.rs",
      c(
        "patient/Patient.r",
        "patient/Patient.s"
      )
    )$missing,
    "patient/Patient.rs"
  )
  expect_error(
    shinyOAuth:::evaluate_scope_coverage("read", "read", profile = "unknown"),
    "Unsupported"
  )
  expect_error(
    shinyOAuth:::evaluate_scope_coverage("read", "read", version = 2L),
    "Unsupported"
  )
})
