test_that("transport and verification consume the response lifetime", {
  client <- make_test_client(use_nonce = FALSE)
  browser <- valid_browser_token()
  state <- parse_query_param(
    prepare_call(client, browser_token = browser),
    "state"
  )
  now <- as.numeric(Sys.time())
  started <- now
  lifetime <- 10
  real_verify <- verify_token_set
  local_mocked_bindings(
    Sys.time = function() as.POSIXct(now, origin = "1970-01-01"),
    .package = "base"
  )
  local_mocked_bindings(
    swap_code_for_token_set = function(...) {
      now <<- now + 2
      list(access_token = "new", token_type = "Bearer", expires_in = lifetime)
    },
    req_with_retry = function(req, ...) {
      now <<- now + 2
      httr2::response(
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw(jsonlite::toJSON(
          list(
            access_token = "new",
            token_type = "Bearer",
            expires_in = lifetime
          ),
          auto_unbox = TRUE
        ))
      )
    },
    verify_token_set = function(...) {
      now <<- now + 3
      real_verify(...)
    },
    .package = "shinyOAuth"
  )
  result <- handle_callback(
    client,
    code = "code",
    payload = state,
    browser_token = browser
  )
  expect_equal(result@expires_at, started + lifetime)
  token <- OAuthToken(access_token = "old", refresh_token = "refresh")
  started <- now
  result <- refresh_token(client, token)
  expect_equal(result@expires_at, started + lifetime)
  # Delivery preserves the absolute deadline through serialization.
  result <- unserialize(serialize(result, NULL))
  now <- result@expires_at + 1
  expect_error(
    validate_token_acceptance_deadline(result),
    "expired before acceptance"
  )
  lifetime <- 1
  expect_error(refresh_token(client, token), "expired before acceptance")
  state <- parse_query_param(
    prepare_call(client, browser_token = browser),
    "state"
  )
  expect_error(
    handle_callback(
      client,
      code = "code",
      payload = state,
      browser_token = browser
    ),
    "expired before acceptance"
  )
})
