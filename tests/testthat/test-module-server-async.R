testthat::test_that("async login flow resolves token and sets flags", {
  testthat::skip_on_cran()
  testthat::skip_if_not_installed("promises")
  testthat::skip_if_not_installed("future")
  testthat::skip_if_not_installed("later")

  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))

  # Disable mirai so async_dispatch uses future (mocks work with sequential)
  if (rlang::is_installed("mirai")) {
    tryCatch(mirai::daemons(0), error = function(...) NULL)
  }

  # Use future::sequential so mocks apply (future runs in-process)
  old_plan <- future::plan()
  future::plan(future::sequential)
  withr::defer(future::plan(old_plan))

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
  # Skip: mocking doesn't work reliably with future::sequential because future
  # captures the environment before mocks are applied. Error handling is tested
  # in synchronous module tests.
  testthat::skip(
    "Mocking async error paths is unreliable with future::sequential"
  )

  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))

  # Disable mirai so async_dispatch uses future (mocks work with sequential)
  if (rlang::is_installed("mirai")) {
    tryCatch(mirai::daemons(0), error = function(...) NULL)
  }

  # Use future::sequential so mocks apply (future runs in-process)
  old_plan <- future::plan()
  future::plan(future::sequential)
  withr::defer(future::plan(old_plan))

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

  # Disable mirai so async_dispatch uses future (mocks work with sequential)
  if (rlang::is_installed("mirai")) {
    tryCatch(mirai::daemons(0), error = function(...) NULL)
  }

  # Use future::sequential so mocks apply (future runs in-process)
  old_plan <- future::plan()
  future::plan(future::sequential)
  withr::defer(future::plan(old_plan))

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

testthat::test_that("async_dispatch returns promise when future is fallback", {
  testthat::skip_on_cran()
  testthat::skip_if_not_installed("promises")
  testthat::skip_if_not_installed("future")

  # Ensure mirai is NOT configured
  if (rlang::is_installed("mirai")) {
    tryCatch(mirai::daemons(0), error = function(...) NULL)
  }

  # Use future sequential plan
  future::plan(future::sequential)
  withr::defer(future::plan(future::sequential))

  # Test that async_dispatch returns a promise when falling back to future
  p <- shinyOAuth:::async_dispatch(
    expr = quote({
      x + y
    }),
    args = list(x = 5, y = 10)
  )

  testthat::expect_s3_class(p, "promise")
})

testthat::test_that("async_dispatch returns mirai object when mirai is configured", {
  testthat::skip_on_cran()
  testthat::skip_if_not_installed("promises")
  testthat::skip_if_not_installed("mirai")
  testthat::skip_if_not_installed("later")

  # Use mirai synchronous mode so the test runs in-process
  mirai::daemons(sync = TRUE)
  withr::defer(mirai::daemons(0))

  # Test that async_dispatch returns a mirai object when mirai is configured
  m <- shinyOAuth:::async_dispatch(
    expr = quote({
      x + y
    }),
    args = list(x = 5, y = 10)
  )

  # Should be a mirai object (recvAio)
  testthat::expect_true(inherits(m, "mirai"))

  # Should be usable with promises::then via as.promise coercion
  result <- NULL
  p <- m |>
    promises::then(function(x) {
      result <<- x
    })

  # Wait for resolution
  deadline <- Sys.time() + 3
  while (is.null(result) && Sys.time() < deadline) {
    later::run_now(0.05)
    Sys.sleep(0.01)
  }

  testthat::expect_equal(result, 15)
})
