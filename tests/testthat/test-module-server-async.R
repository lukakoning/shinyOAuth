testthat::test_that("async login flow resolves token and sets flags", {
  testthat::skip_on_cran()
  testthat::skip_if_not_installed("promises")
  testthat::skip_if_not_installed("future")
  testthat::skip_if_not_installed("later")

  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))

  # Use in-process futures so mocks apply within future_promise
  old_plan <- NULL
  if (requireNamespace("future", quietly = TRUE)) {
    old_plan <- tryCatch(future::plan(), error = function(...) NULL)
    try(future::plan(future::sequential), silent = TRUE)
    withr::defer({
      if (!is.null(old_plan)) try(future::plan(old_plan), silent = TRUE)
    })
  }

  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)

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
      testthat::expect_true(values$has_browser_token())

      # Build the authorization URL and capture encoded state
      url <- values$build_auth_url()
      enc <- parse_query_param(url, "state")
      testthat::expect_true(is.character(enc) && nzchar(enc))

      # Mock token exchange to avoid HTTP; resolve with a short-lived token
      token <- testthat::with_mocked_bindings(
        swap_code_for_token_set = function(client, code, code_verifier) {
          list(access_token = "t-async", expires_in = 3600)
        },
        .package = "shinyOAuth",
        {
          values$.process_query(paste0("?code=ok&state=", enc))
          # Allow promise handlers to run
          deadline <- Sys.time() + 3
          while (is.null(values$token) && Sys.time() < deadline) {
            later::run_now(0.05)
            session$flushReact()
            Sys.sleep(0.01)
          }
          values$token
        }
      )

      testthat::expect_false(is.null(token))
      session$flushReact()
      testthat::expect_true(isTRUE(values$last_login_async_used))
      testthat::expect_true(isTRUE(values$authenticated))
      testthat::expect_null(values$error)
      testthat::expect_null(values$error_description)
      # Cookie should be cleared after successful login
      testthat::expect_null(values$browser_token)
    }
  )
})

testthat::test_that("async login failure surfaces error and keeps authenticated FALSE", {
  testthat::skip_on_cran()
  testthat::skip_if_not_installed("promises")
  testthat::skip_if_not_installed("future")
  testthat::skip_if_not_installed("later")

  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))

  # Ensure in-process future so the mock applies
  old_plan <- NULL
  if (requireNamespace("future", quietly = TRUE)) {
    old_plan <- tryCatch(future::plan(), error = function(...) NULL)
    try(future::plan(future::sequential), silent = TRUE)
    withr::defer({
      if (!is.null(old_plan)) try(future::plan(old_plan), silent = TRUE)
    })
  }

  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)

  shiny::testServer(
    app = oauth_module_server,
    args = list(
      id = "auth",
      client = cli,
      auto_redirect = FALSE,
      async = TRUE,
      indefinite_session = FALSE
    ),
    expr = {
      testthat::expect_true(values$has_browser_token())
      url <- values$build_auth_url()
      enc <- parse_query_param(url, "state")

      # Force token exchange to fail inside handle_callback
      testthat::with_mocked_bindings(
        swap_code_for_token_set = function(client, code, code_verifier) {
          stop("exchange_failed")
        },
        .package = "shinyOAuth",
        {
          values$.process_query(paste0("?code=bad&state=", enc))
          deadline <- Sys.time() + 3
          while (is.null(values$error) && Sys.time() < deadline) {
            later::run_now(0.05)
            session$flushReact()
            Sys.sleep(0.01)
          }
        }
      )

      testthat::expect_identical(values$error, "token_exchange_error")
      testthat::expect_match(
        values$error_description %||% "",
        "exchange|token|error",
        ignore.case = TRUE
      )
      testthat::expect_false(isTRUE(values$authenticated))
      testthat::expect_true(is.null(values$token))
    }
  )
})

testthat::test_that("pending callback resumes after cookie arrives (async)", {
  testthat::skip_on_cran()
  testthat::skip_if_not_installed("promises")
  testthat::skip_if_not_installed("future")
  testthat::skip_if_not_installed("later")

  # Do not skip cookie handling; we want to exercise pending_callback path
  withr::local_options(list(shinyOAuth.skip_browser_token = FALSE))

  # Use a deterministic valid browser token and pre-build a state payload
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  btok <- valid_browser_token()
  url_pre <- prepare_call(cli, browser_token = btok)
  enc <- parse_query_param(url_pre, "state")
  testthat::expect_true(is.character(enc) && nzchar(enc))

  # Ensure in-process futures
  old_plan <- NULL
  if (requireNamespace("future", quietly = TRUE)) {
    old_plan <- tryCatch(future::plan(), error = function(...) NULL)
    try(future::plan(future::sequential), silent = TRUE)
    withr::defer({
      if (!is.null(old_plan)) try(future::plan(old_plan), silent = TRUE)
    })
  }

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
      # Initially there's no cookie -> callback is deferred
      testthat::expect_false(values$has_browser_token())
      values$.process_query(paste0("?code=ok&state=", enc))
      session$flushReact()
      testthat::expect_type(values$pending_callback, "list")

      # Once cookie is provided, module should resume the pending callback
      token <- testthat::with_mocked_bindings(
        swap_code_for_token_set = function(client, code, code_verifier) {
          list(access_token = "t-async2", expires_in = 3600)
        },
        .package = "shinyOAuth",
        {
          session$setInputs(shinyOAuth_sid = btok)
          # Process async resolution
          deadline <- Sys.time() + 3
          while (is.null(values$token) && Sys.time() < deadline) {
            later::run_now(0.05)
            session$flushReact()
            Sys.sleep(0.01)
          }
          values$token
        }
      )

      testthat::expect_false(is.null(token))
      testthat::expect_null(values$pending_callback)
      testthat::expect_true(isTRUE(values$authenticated))
    }
  )
})
