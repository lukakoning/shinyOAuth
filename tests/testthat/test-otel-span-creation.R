# Tests for otel span creation in login/callback/userinfo flows

testthat::test_that("prepare_call creates shinyOAuth.login.request span", {
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))

  span_names <- character()
  span_attrs <- list()

  testthat::with_mocked_bindings(
    with_otel_span = function(
      name,
      code,
      attributes = NULL,
      options = NULL,
      mark_ok = TRUE
    ) {
      span_names <<- c(span_names, name)
      span_attrs[[name]] <<- attributes
      eval.parent(substitute(code))
    },
    emit_trace_event = function(event) invisible(NULL),
    .package = "shinyOAuth",
    {
      cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
      btok <- valid_browser_token()
      url <- shinyOAuth::prepare_call(cli, browser_token = btok)
    }
  )

  testthat::expect_true("shinyOAuth.login.request" %in% span_names)

  login_attrs <- span_attrs[["shinyOAuth.login.request"]]
  testthat::expect_identical(login_attrs$oauth.phase, "login.request")
  testthat::expect_identical(login_attrs$oauth.used_pkce, TRUE)
  testthat::expect_identical(login_attrs$oauth.nonce_enabled, FALSE)
  testthat::expect_identical(login_attrs$oauth.provider.name, "example")
})

testthat::test_that("handle_callback creates shinyOAuth.callback span", {
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))

  span_names <- character()

  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  btok <- valid_browser_token()

  # Prepare a valid state
  url <- testthat::with_mocked_bindings(
    with_otel_span = function(
      name,
      code,
      attributes = NULL,
      options = NULL,
      mark_ok = TRUE
    ) {
      eval.parent(substitute(code))
    },
    emit_trace_event = function(event) invisible(NULL),
    .package = "shinyOAuth",
    {
      shinyOAuth::prepare_call(cli, browser_token = btok)
    }
  )
  enc <- parse_query_param(url, "state")

  testthat::with_mocked_bindings(
    with_otel_span = function(
      name,
      code,
      attributes = NULL,
      options = NULL,
      mark_ok = TRUE
    ) {
      span_names <<- c(span_names, name)
      eval.parent(substitute(code))
    },
    emit_trace_event = function(event) invisible(NULL),
    swap_code_for_token_set = function(client, code, code_verifier) {
      list(access_token = "test_at", expires_in = 3600)
    },
    .package = "shinyOAuth",
    {
      tok <- shinyOAuth::handle_callback(
        cli,
        code = "test_code",
        payload = enc,
        browser_token = btok
      )
    }
  )

  testthat::expect_true("shinyOAuth.callback" %in% span_names)
  # Callback validation sub-spans
  testthat::expect_true(
    any(grepl("shinyOAuth.callback.validate", span_names)),
    info = "Expected callback.validate sub-spans"
  )
  # Token verification span (swap_code_for_token_set is mocked, so
  # shinyOAuth.token.exchange itself doesn't fire, but verify does)
  testthat::expect_true("shinyOAuth.token.verify" %in% span_names)
})

testthat::test_that("get_userinfo creates shinyOAuth.userinfo span", {
  span_names <- character()

  cli <- make_test_client()
  cli@provider@userinfo_url <- "https://example.com/userinfo"

  testthat::with_mocked_bindings(
    with_otel_span = function(
      name,
      code,
      attributes = NULL,
      options = NULL,
      mark_ok = TRUE
    ) {
      span_names <<- c(span_names, name)
      eval.parent(substitute(code))
    },
    emit_trace_event = function(event) invisible(NULL),
    req_with_retry = function(req, ...) {
      httr2::response(
        url = "https://example.com/userinfo",
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw('{"sub":"user123","name":"Test User"}')
      )
    },
    .package = "shinyOAuth",
    {
      ui <- shinyOAuth::get_userinfo(cli, token = "test_access_token")
    }
  )

  testthat::expect_true("shinyOAuth.userinfo" %in% span_names)
  testthat::expect_true("shinyOAuth.userinfo.http" %in% span_names)
  testthat::expect_identical(ui$sub, "user123")
})

testthat::test_that("refresh_token creates shinyOAuth.refresh span (sync)", {
  span_names <- character()

  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  tok <- OAuthToken(
    access_token = "old_at",
    refresh_token = "old_rt",
    expires_at = as.numeric(Sys.time()) + 60,
    id_token = NA_character_
  )

  testthat::with_mocked_bindings(
    with_otel_span = function(
      name,
      code,
      attributes = NULL,
      options = NULL,
      mark_ok = TRUE
    ) {
      span_names <<- c(span_names, name)
      eval.parent(substitute(code))
    },
    emit_trace_event = function(event) invisible(NULL),
    req_with_retry = function(req, ...) {
      httr2::response(
        url = as.character(req$url),
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw(
          '{"access_token":"new_at","expires_in":3600,"token_type":"bearer"}'
        )
      )
    },
    .package = "shinyOAuth",
    {
      new_tok <- shinyOAuth::refresh_token(cli, tok, async = FALSE)
    }
  )

  testthat::expect_true("shinyOAuth.refresh" %in% span_names)
  testthat::expect_true("shinyOAuth.token.exchange.http" %in% span_names)
  testthat::expect_true("shinyOAuth.token.verify" %in% span_names)
})
