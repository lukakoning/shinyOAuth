test_that("oversized queries are rejected before callback scanning on any route", {
  withr::local_options(list(shinyOAuth.callback_max_query_bytes = 64))
  scans <- 0L
  scan <- function(...) {
    scans <<- scans + 1L
    stop("scanner ran")
  }
  testthat::local_mocked_bindings(
    oauth_module_query_has_callback_keys = scan,
    oauth_module_query_raw_values = scan,
    .package = "shinyOAuth"
  )
  shiny::testServer(
    oauth_module_server,
    args = list(
      id = "auth",
      client = make_test_client(),
      auto_redirect = FALSE
    ),
    expr = {
      for (path in c("/", "/wrong-route")) {
        values$.process_query(
          paste0("?code=", strrep("x", 100)),
          current_path = path
        )
        expect_identical(values$error, "invalid_callback_query")
      }
      expect_identical(scans, 0L)
    }
  )
})

test_that("callback query size caps are configurable via options", {
  client <- make_test_client()

  # 1) state payload cap
  old <- options(shinyOAuth.callback_max_state_bytes = 10)
  on.exit(options(old), add = TRUE)

  expect_error(
    handle_callback(
      oauth_client = client,
      code = "abcd",
      payload = paste(rep("x", 20), collapse = ""),
      browser_token = valid_browser_token()
    ),
    class = "shinyOAuth_state_error"
  )
})

test_that("callback browser_token cap is configurable via options", {
  client <- make_test_client()

  old <- options(
    shinyOAuth.callback_max_code_bytes = 4096,
    shinyOAuth.callback_max_state_bytes = 8192,
    shinyOAuth.callback_max_browser_token_bytes = 5
  )
  on.exit(options(old), add = TRUE)

  expect_error(
    handle_callback(
      oauth_client = client,
      code = "abcd",
      payload = "x",
      browser_token = "123456"
    ),
    class = "shinyOAuth_state_error"
  )
})

test_that("callback code cap is configurable via options", {
  client <- make_test_client()

  old <- options(shinyOAuth.callback_max_code_bytes = 3)
  on.exit(options(old), add = TRUE)

  expect_error(
    handle_callback(
      oauth_client = client,
      code = "abcd",
      payload = "x",
      browser_token = "123"
    ),
    class = "shinyOAuth_state_error"
  )
})

test_that("encoded callbacks within an 8000-byte request line reach code exchange", {
  client <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  browser <- valid_browser_token()
  state <- parse_query_param(
    prepare_call(client, browser_token = browser),
    "state"
  )
  overhead <- nchar(
    paste0("GET /?code=&state=", state, " HTTP/1.1\r\n"),
    type = "bytes"
  )
  code <- paste0(strrep("x", 8000L - overhead - 300L), strrep("+", 100L))
  expect_gt(nchar(code, type = "bytes"), 4096L)
  query <- paste0(
    "code=",
    utils::URLencode(code, reserved = TRUE),
    "&state=",
    state
  )
  expect_equal(
    nchar(paste0("GET /?", query, " HTTP/1.1\r\n"), type = "bytes"),
    8000L
  )
  expect_identical(
    oauth_get_parse_query(query, oauth_callback_limits(), client)$code,
    code
  )
  expect_identical(oauth_form_post_parse_body(query)$code, code)
  exchanged <- NULL
  testthat::local_mocked_bindings(
    swap_code_for_token_set = function(client, code, code_verifier) {
      exchanged <<- code
      list(access_token = "access", token_type = "Bearer", expires_in = 3600)
    },
    .package = "shinyOAuth"
  )
  token <- handle_callback(client, code, state, browser)
  expect_s7_class(token, OAuthToken)
  expect_identical(exchanged, code)
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))
  shiny::testServer(
    oauth_module_server,
    args = list(id = "auth", client = client, auto_redirect = FALSE),
    {
      state <- parse_query_param(values$build_auth_url(), "state")
      values$.process_query(paste0(
        "?code=",
        utils::URLencode(code, reserved = TRUE),
        "&state=",
        state
      ))
      session$flushReact()
      expect_true(values$authenticated)
      expect_identical(exchanged, code)
    }
  )
})

test_that("callback and JARM field budgets share one resolver and honor overrides", {
  client <- make_test_client(use_nonce = TRUE)
  claims <- list(
    iss = client@provider@issuer,
    aud = client@client_id,
    exp = as.numeric(Sys.time()) + 60,
    state = "state",
    code = strrep("a", 8192)
  )
  expect_equal(oauth_callback_limits()$code, 8192)
  expect_identical(validate_jarm_claims(client, claims)$code, claims$code)
  query <- paste0("code=", claims$code, "&state=state")
  expect_identical(oauth_form_post_parse_body(query)$code, claims$code)
  withr::local_options(list(shinyOAuth.callback_max_code_bytes = 4096))
  expect_error(validate_jarm_claims(client, claims), "maximum length")
  expect_error(oauth_form_post_parse_body(query), "maximum length")
  expect_error(
    handle_callback(client, claims$code, "state", valid_browser_token()),
    "maximum length"
  )
  withr::local_options(list(
    shinyOAuth.callback_max_code_bytes = 10000,
    shinyOAuth.callback_max_query_bytes = 200
  ))
  expect_equal(oauth_callback_limits()$code, 10000)
  expect_equal(oauth_callback_limits()$query, 200)
  expect_error(
    validate_untrusted_query_string(
      query,
      max_bytes = oauth_callback_limits()$query
    ),
    "maximum length"
  )
})
