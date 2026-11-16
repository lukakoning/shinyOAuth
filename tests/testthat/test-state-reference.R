reference_case <- function(...) {
  provider <- oauth_provider(
    name = "reference",
    auth_url = "https://issuer.example/auth",
    token_url = "https://issuer.example/token",
    issuer = "https://issuer.example",
    infer_oidc_from_issuer = FALSE
  )
  client <- oauth_client(
    provider,
    "client",
    "secret",
    redirect_uri = "https://app.example/callback",
    state_transport = "reference",
    ...
  )
  browser <- valid_browser_token()
  wire <- parse_query_param(
    prepare_call(client, browser),
    "state",
    decode = TRUE
  )
  list(
    client = client,
    browser = browser,
    wire = wire,
    key = state_cache_key(wire)
  )
}

test_that("reference state is bounded and retains an encrypted, bound pending payload", {
  for (entropy in c(22, 64, 128)) {
    case <- reference_case(state_entropy = entropy)
    client <- case[["client"]]
    expect_equal(nchar(case[["wire"]]), entropy)
    expect_match(case[["wire"]], "^[A-Za-z0-9_-]+$")
    record <- client@state_store[["get"]](case[["key"]])
    expect_type(record[["state_payload"]], "character")
    payload <- state_payload_decrypt_validate(client, case[["wire"]])
    expect_identical(payload[["state"]], case[["wire"]])
    expect_identical(payload[["client_id"]], client@client_id)
    expect_identical(payload[["redirect_uri"]], client@redirect_uri)
    expect_match(payload[["reference_payload_digest"]], "^[a-f0-9]{64}$")
    expect_identical(class(payload[["reference_payload_digest"]]), "character")
    cached <- jsonlite::fromJSON(
      jsonlite::toJSON(payload, auto_unbox = TRUE),
      simplifyVector = FALSE
    )
    expect_identical(state_payload_revalidate(client, cached), cached)
    expect_invisible(state_reference_verify_record(client, payload, record))
    expect_true(client@state_store[["exists"]](case[["key"]]))
    expect_identical(state_payload_revalidate(client, payload), payload)
  }
  client <- make_test_client()
  expect_identical(client@state_transport, "encrypted")
  wire <- parse_query_param(
    prepare_call(client, valid_browser_token()),
    "state",
    decode = TRUE
  )
  payload <- state_decrypt_gcm(wire, client@state_key)
  expect_type(payload, "list")
  expect_null(client@state_store[["get"]](state_cache_key(payload[["state"]]))[[
    "state_payload"
  ]])
  expect_error(oauth_client(
    client@provider,
    "client",
    redirect_uri = client@redirect_uri,
    state_transport = "unknown"
  ))
  expect_error({
    client@state_transport <- c("encrypted", "reference")
  })
})

test_that("reference lookup rejects malformed, missing, swapped and expired payloads", {
  case <- reference_case()
  client <- case[["client"]]
  original <- client@state_store[["get"]](case[["key"]])
  for (wire in c(
    "short",
    strrep("a", 129),
    strrep("!", 64),
    random_urlsafe(64)
  )) {
    expect_error(
      state_payload_decrypt_validate(client, wire),
      class = "shinyOAuth_state_error"
    )
  }
  for (mutation in c("missing", "ciphertext", "logical_state", "expiry")) {
    record <- original
    if (mutation == "missing") {
      record[["state_payload"]] <- NULL
    }
    if (mutation == "ciphertext") {
      record[["state_payload"]] <- "not-a-valid-state-envelope"
    }
    if (mutation %in% c("logical_state", "expiry")) {
      payload <- state_decrypt_gcm(
        original[["state_payload"]],
        client@state_key
      )
      if (mutation == "logical_state") {
        payload[["state"]] <- random_urlsafe(64)
      }
      if (mutation == "expiry") {
        payload[["issued_at"]] <- as.numeric(Sys.time()) - 1000
      }
      record[["state_payload"]] <- state_encrypt_gcm(payload, client@state_key)
    }
    client@state_store[["set"]](case[["key"]], record)
    expect_error(
      state_payload_decrypt_validate(client, case[["wire"]]),
      class = "shinyOAuth_state_error",
      info = mutation
    )
    expect_true(client@state_store[["exists"]](case[["key"]]))
  }
})

test_that("reference state binds client, provider, policy and transport before consumption", {
  for (mutation in c(
    "client",
    "provider",
    "redirect",
    "scope",
    "policy",
    "transport",
    "key"
  )) {
    case <- reference_case()
    client <- case[["client"]]
    payload <- state_payload_decrypt_validate(client, case[["wire"]])
    switch(
      mutation,
      client = {
        client@client_id <- "other-client"
      },
      provider = {
        client@provider@token_url <- "https://other.example/token"
      },
      redirect = {
        client@redirect_uri <- "https://app.example/other"
      },
      scope = {
        client@scopes <- "other-scope"
      },
      policy = {
        client@claims_validation <- "strict"
      },
      transport = {
        client@state_transport <- "encrypted"
      },
      key = {
        client@state_key <- openssl::rand_bytes(32)
      }
    )
    expect_error(
      state_payload_decrypt_validate(client, case[["wire"]]),
      class = "shinyOAuth_state_error",
      info = mutation
    )
    expect_error(
      state_payload_revalidate(client, payload),
      class = "shinyOAuth_state_error",
      info = mutation
    )
    expect_true(client@state_store[["exists"]](case[["key"]]))
  }
})

test_that("reference payload changes cannot cross a cached validation or atomic take", {
  case <- reference_case()
  client <- case[["client"]]
  payload <- state_payload_decrypt_validate(client, case[["wire"]])
  record <- state_store_get(client, case[["wire"]])
  replacement <- record
  replacement[["state_payload"]] <- state_encrypt_gcm(
    state_decrypt_gcm(record[["state_payload"]], client@state_key),
    client@state_key
  )
  expect_error(
    state_reference_verify_record(client, payload, replacement),
    class = "shinyOAuth_state_error"
  )
  expect_error(
    state_payload_revalidate(
      client,
      within(payload, rm(reference_payload_digest))
    ),
    class = "shinyOAuth_state_error"
  )
  local_mocked_bindings(
    state_store_get_remove = function(...) replacement,
    .package = "shinyOAuth"
  )
  expect_error(
    state_store_consume_checked(
      client,
      case[["wire"]],
      record,
      .state_payload = payload
    ),
    "record changed",
    class = "shinyOAuth_state_error"
  )
})

test_that("wrong-browser reference callbacks cannot consume or exchange, and replays fail", {
  case <- reference_case()
  client <- case[["client"]]
  calls <- 0L
  local_mocked_bindings(
    swap_code_for_token_set = function(...) {
      calls <<- calls + 1L
      list(access_token = "access", token_type = "Bearer", expires_in = 300)
    },
    .package = "shinyOAuth"
  )
  expect_error(
    handle_callback(
      client,
      "code",
      case[["wire"]],
      browser_token = paste(rep("cd", 64), collapse = "")
    ),
    class = "shinyOAuth_state_error"
  )
  expect_identical(calls, 0L)
  expect_true(client@state_store[["exists"]](case[["key"]]))
  token <- handle_callback(
    client,
    "code",
    case[["wire"]],
    browser_token = case[["browser"]]
  )
  expect_identical(token@access_token, "access")
  expect_identical(calls, 1L)
  expect_error(
    handle_callback(
      client,
      "code",
      case[["wire"]],
      browser_token = case[["browser"]]
    ),
    class = "shinyOAuth_state_error"
  )
  expect_identical(calls, 1L)
})

test_that("reference mode rejects shared stores without atomic take even with legacy opt-in", {
  local_options(shinyOAuth.allow_non_atomic_state_store = TRUE)
  store <- cachem::cache_mem()
  shared <- list(
    get = store[["get"]],
    set = store[["set"]],
    remove = store[["remove"]],
    info = store[["info"]]
  )
  provider <- make_test_provider()
  expect_error(
    oauth_client(
      provider,
      "client",
      redirect_uri = "http://localhost:8100",
      state_transport = "reference",
      state_store = shared
    ),
    "atomic take"
  )
})

test_that("reference POST candidates survive a wrong browser and complete once in either store", {
  for (shared in c(FALSE, TRUE)) {
    for (denied in c(FALSE, TRUE)) {
      provider <- oauth_provider(
        name = "reference-post",
        auth_url = "https://issuer.example/auth",
        token_url = "https://issuer.example/token"
      )
      backing <- cachem::cache_mem(max_age = 300)
      client <- oauth_client(
        provider,
        "client",
        "secret",
        redirect_uri = "http://localhost:8100/",
        state_transport = "reference",
        response_mode = "form_post",
        state_store = if (shared) {
          form_post_test_atomic_cache(backing)
        } else {
          backing
        }
      )
      expect_form_post_candidate_isolation(
        client,
        post_candidate = function(fields) {
          body <- httr2::url_query_build(fields)
          oauth_form_post_handle_request(
            list(
              REQUEST_METHOD = "POST",
              "rook.url_scheme" = "http",
              HTTP_HOST = "localhost:8100",
              PATH_INFO = "/",
              QUERY_STRING = "",
              CONTENT_TYPE = "application/x-www-form-urlencoded",
              CONTENT_LENGTH = as.character(nchar(body, type = "bytes")),
              "rook.input" = list(read = function(n) charToRaw(body))
            ),
            "auth",
            client
          )
        },
        first_error = !denied,
        follow_first = TRUE,
        final_error = denied
      )
    }
  }
})
