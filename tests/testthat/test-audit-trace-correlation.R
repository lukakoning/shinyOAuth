testthat::test_that("successful redirect and callback share one flow trace_id", {
  withr::local_options(list(
    shinyOAuth.skip_browser_token = TRUE,
    shinyOAuth.otel_logging_enabled = FALSE,
    shinyOAuth.otel_tracing_enabled = FALSE
  ))

  events <- list()
  old <- options(shinyOAuth.audit_hook = function(event) {
    events[[length(events) + 1L]] <<- event
  })
  on.exit(options(old), add = TRUE)

  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  btok <- valid_browser_token()

  url <- shinyOAuth::prepare_call(cli, browser_token = btok)
  enc <- parse_query_param(url, "state")

  testthat::with_mocked_bindings(
    swap_code_for_token_set = function(client, code, code_verifier) {
      list(access_token = "at", expires_in = 3600)
    },
    .package = "shinyOAuth",
    {
      shinyOAuth::handle_callback(
        cli,
        code = "ok",
        payload = enc,
        browser_token = btok
      )
    }
  )

  wanted <- c(
    "audit_redirect_issued",
    "audit_callback_validation_success",
    "audit_callback_received",
    "audit_token_exchange",
    "audit_login_success"
  )
  types <- vapply(events, function(e) e$type %||% "", character(1))
  matched <- events[match(wanted, types)]
  trace_ids <- vapply(matched, function(e) e$trace_id %||% "", character(1))

  testthat::expect_true(all(wanted %in% types))
  testthat::expect_true(all(nzchar(trace_ids)))
  testthat::expect_length(unique(trace_ids), 1L)
})

testthat::test_that("async pre-dispatch callback failures retain specific phase", {
  withr::local_options(list(
    shinyOAuth.skip_browser_token = TRUE,
    shinyOAuth.otel_logging_enabled = FALSE,
    shinyOAuth.otel_tracing_enabled = FALSE
  ))

  events <- list()
  old <- options(shinyOAuth.audit_hook = function(event) {
    events[[length(events) + 1L]] <<- event
  })
  on.exit(options(old), add = TRUE)

  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  enc <- parse_query_param(
    shinyOAuth::prepare_call(cli, browser_token = "__SKIPPED__"),
    "state"
  )
  payload <- shinyOAuth:::state_decrypt_gcm(enc, key = cli@state_key)
  cli@state_store$remove(shinyOAuth:::state_cache_key(payload$state))

  shiny::testServer(
    app = oauth_module_server,
    args = list(
      id = "auth",
      client = cli,
      auto_redirect = FALSE,
      async = TRUE,
      indefinite_session = TRUE
    ),
    expr = {
      values$.process_query(paste0("?code=bad&state=", enc))
      session$flushReact()
    }
  )

  types <- vapply(events, function(e) e$type %||% "", character(1))
  failed <- events[[match("audit_login_failed", types)]]

  testthat::expect_false(is.null(failed))
  testthat::expect_identical(failed$phase, "async_state_store_lookup")
})

testthat::test_that("error callback state consumption keeps flow trace and logical state digest", {
  withr::local_options(list(
    shinyOAuth.skip_browser_token = TRUE,
    shinyOAuth.otel_logging_enabled = FALSE,
    shinyOAuth.otel_tracing_enabled = FALSE
  ))

  events <- list()
  old <- options(shinyOAuth.audit_hook = function(event) {
    events[[length(events) + 1L]] <<- event
  })
  on.exit(options(old), add = TRUE)

  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)

  shiny::testServer(
    app = oauth_module_server,
    args = list(
      id = "auth",
      client = cli,
      auto_redirect = FALSE
    ),
    expr = {
      url <- values$build_auth_url()
      enc <- parse_query_param(url, "state")
      payload <- shinyOAuth:::state_payload_decrypt_validate(cli, enc)
      plain_digest <- shinyOAuth:::string_digest(payload$state)
      encrypted_digest <- shinyOAuth:::string_digest(enc)

      values$.process_query(paste0("?error=access_denied&state=", enc))
      session$flushReact()

      types <- vapply(events, function(e) e$type %||% "", character(1))
      redirect_event <- events[[match("audit_redirect_issued", types)]]
      consumed_event <- events[[match("audit_error_state_consumed", types)]]

      testthat::expect_false(is.null(redirect_event))
      testthat::expect_false(is.null(consumed_event))
      testthat::expect_identical(
        consumed_event$trace_id %||% "",
        redirect_event$trace_id %||% ""
      )
      testthat::expect_identical(consumed_event$state_digest, plain_digest)
      testthat::expect_false(identical(consumed_event$state_digest, encrypted_digest))
    }
  )
})

testthat::test_that("error callback state consumption failure keeps flow trace and logical state digest", {
  withr::local_options(list(
    shinyOAuth.skip_browser_token = TRUE,
    shinyOAuth.otel_logging_enabled = FALSE,
    shinyOAuth.otel_tracing_enabled = FALSE
  ))

  events <- list()
  old <- options(shinyOAuth.audit_hook = function(event) {
    events[[length(events) + 1L]] <<- event
  })
  on.exit(options(old), add = TRUE)

  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)

  shiny::testServer(
    app = oauth_module_server,
    args = list(
      id = "auth",
      client = cli,
      auto_redirect = FALSE
    ),
    expr = {
      url <- values$build_auth_url()
      enc <- parse_query_param(url, "state")
      payload <- shinyOAuth:::state_payload_decrypt_validate(cli, enc)
      key <- shinyOAuth:::state_cache_key(payload$state)
      plain_digest <- shinyOAuth:::string_digest(payload$state)
      encrypted_digest <- shinyOAuth:::string_digest(enc)

      cli@state_store$remove(key)
      values$.process_query(paste0("?error=server_error&state=", enc))
      session$flushReact()

      types <- vapply(events, function(e) e$type %||% "", character(1))
      redirect_event <- events[[match("audit_redirect_issued", types)]]
      failed_event <- events[[match("audit_error_state_consumption_failed", types)]]

      testthat::expect_false(is.null(redirect_event))
      testthat::expect_false(is.null(failed_event))
      testthat::expect_identical(
        failed_event$trace_id %||% "",
        redirect_event$trace_id %||% ""
      )
      testthat::expect_identical(failed_event$state_digest, plain_digest)
      testthat::expect_false(identical(failed_event$state_digest, encrypted_digest))
    }
  )
})
