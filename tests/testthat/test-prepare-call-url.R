test_that("prepare_call builds URL with correct params and drops NULLs", {
  # With PKCE and nonce
  cli <- make_test_client(use_pkce = TRUE, use_nonce = TRUE)
  tok <- valid_browser_token()
  url <- shinyOAuth:::prepare_call(cli, browser_token = tok)
  expect_match(url, ".*code_challenge=", perl = TRUE)
  expect_match(url, ".*code_challenge_method=S256", perl = TRUE)
  expect_match(url, ".*nonce=", perl = TRUE)
  expect_match(url, ".*state=", perl = TRUE)

  # Without nonce
  cli2 <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  url2 <- shinyOAuth:::prepare_call(cli2, browser_token = tok)
  expect_false(grepl("[?&]nonce=", url2))
})

test_that("prepare_call checks generated state against callback and envelope limits before PAR", {
  client <- make_test_client(
    use_pkce = TRUE,
    use_nonce = FALSE,
    scopes = paste0("https://api.example/permissions/read-", seq_len(10))
  )
  client@provider@token_auth_style <- "public"
  browser <- valid_browser_token()
  state <- parse_query_param(
    prepare_call(client, browser),
    "state",
    decode = TRUE
  )
  expect_gt(nchar(state, type = "bytes"), 1024)
  expect_lt(nchar(state, type = "bytes"), 8192)
  initial_keys <- client@state_store$keys()
  pushed <- 0L
  local_mocked_bindings(push_authorization_request = function(...) {
    pushed <<- pushed + 1L
    stop("must reject state before PAR")
  })
  withr::local_options(shinyOAuth.callback_max_state_bytes = 1024)
  for (par in c(FALSE, TRUE)) {
    client@provider@par_url <- if (par) {
      "https://example.com/par"
    } else {
      NA_character_
    }
    for (defer in c(FALSE, TRUE)) {
      expect_error(
        prepare_call(client, browser, .defer_build = defer),
        "Generated state exceeds shinyOAuth.callback_max_state_bytes",
        class = "shinyOAuth_config_error"
      )
      expect_setequal(client@state_store$keys(), initial_keys)
    }
  }
  withr::local_options(
    shinyOAuth.callback_max_state_bytes = 8192,
    shinyOAuth.state_max_token_chars = 1024,
    shinyOAuth.state_fail_delay_ms = 0
  )
  expect_error(prepare_call(client, browser), class = "shinyOAuth_state_error")
  expect_identical(pushed, 0L)
  expect_setequal(client@state_store$keys(), initial_keys)
})

test_that("authorization queries preserve fixed bytes and deduplicate managed values", {
  url <- "https://example.com/auth?fixed=a%20b&CLIENT_ID=extension&client%5fid=abc&resource=one"
  result <- shinyOAuth:::authorization_url_append(
    url,
    list(
      client_id = "abc",
      response_type = "code",
      resource = c("two", "three")
    )
  )
  expect_identical(
    result,
    paste0(url, "&response_type=code&resource=two&resource=three")
  )
  expect_error(
    shinyOAuth:::authorization_url_append(url, list(client_id = "different")),
    "conflicts with managed",
    class = "shinyOAuth_config_error"
  )
  for (query in c("state=a&state=a", "scope=a&sc%6fpe=b", "client%00id=x")) {
    expect_error(
      shinyOAuth:::authorization_url_append(
        paste0("https://example.com/auth?", query),
        list()
      ),
      "Authorization",
      class = "shinyOAuth_config_error"
    )
  }
})

test_that("prepare_call validates configured authorization query against generated values", {
  client <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  client@provider@auth_url <- paste0(
    client@provider@auth_url,
    "?response_type=code&fixed=a%2Bb"
  )
  url <- prepare_call(client, browser_token = valid_browser_token())
  fields <- shinyOAuth:::decode_form_pairs(shinyOAuth:::url_raw_query(url))
  expect_equal(sum(names(fields) == "response_type"), 1L)
  expect_identical(fields$fixed, "a+b")
  client@provider@auth_url <- "https://example.com/auth?response_type=unexpected"
  expect_error(
    prepare_call(client, browser_token = valid_browser_token()),
    "conflicts with managed"
  )
  expect_error(
    {
      client@provider@auth_url <- "https://example.com/auth?client_id=a&client_id=b"
    },
    "repeated managed"
  )
})

test_that("PAR and JAR outer requests share authorization query composition", {
  client <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  client@provider@auth_url <- paste0(
    "https://example.com/auth?client_id=",
    client@client_id,
    "&fixed=keep"
  )
  client@provider@par_url <- "https://example.com/par"
  pushed <- 0L
  testthat::local_mocked_bindings(
    push_authorization_request = function(...) {
      pushed <<- pushed + 1L
      list(request_uri = "urn:example:request", expires_in = 90)
    },
    .package = "shinyOAuth"
  )
  build <- function(x) {
    shinyOAuth:::build_auth_url(
      x,
      payload = "state",
      scopes = character(),
      pkce_code_challenge = "challenge",
      pkce_method = "S256",
      nonce = NULL,
      .request_object = "signed-object"
    )
  }
  par_url <- build(client)
  expect_equal(
    sum(
      names(shinyOAuth:::decode_form_pairs(shinyOAuth:::url_raw_query(
        par_url
      ))) ==
        "client_id"
    ),
    1L
  )
  expect_match(par_url, "fixed=keep", fixed = TRUE)
  expect_equal(pushed, 1L)
  client@provider@auth_url <- "https://example.com/auth?client_id=conflicting"
  expect_error(build(client), "conflicts with managed")
  expect_equal(pushed, 1L)

  client@provider@auth_url <- paste0(
    "https://example.com/auth?client_id=",
    client@client_id
  )
  client@provider@par_url <- NA_character_
  client@client_secret <- strrep("s", 32)
  client@request_object_audience <- "https://example.com"
  client@request_object_mode <- "request"
  jar_url <- build(client)
  fields <- shinyOAuth:::decode_form_pairs(shinyOAuth:::url_raw_query(jar_url))
  expect_equal(sum(names(fields) == "client_id"), 1L)
  expect_identical(fields$request, "signed-object")
})
