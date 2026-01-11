testthat::test_that("audit hook is called from async worker when options are propagated", {
  testthat::skip_on_cran()
  testthat::skip_if_not_installed("promises")
  testthat::skip_if_not_installed("future")
  testthat::skip_if_not_installed("later")

  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))

  # Use multisession to test true cross-process option propagation.
  # Note: on systems where multisession isn't available, this will

  # fall back to sequential (which still validates the code path).
  old_plan <- tryCatch(future::plan(), error = function(...) NULL)
  tryCatch(
    future::plan(future::multisession, workers = 2),
    error = function(...) {
      try(future::plan(future::sequential), silent = TRUE)
    }
  )
  withr::defer({
    if (!is.null(old_plan)) try(future::plan(old_plan), silent = TRUE)
  })

  # Capture audit events via the audit hook. This hook is set in the main

  # process and should be propagated to async workers.
  audit_events <- list()
  withr::local_options(list(
    shinyOAuth.audit_hook = function(event) {
      # Record the event along with the current process ID to verify
      # that events from workers are correctly routed back
      event$.captured_in_pid <- Sys.getpid()
      audit_events <<- c(audit_events, list(event))
    }
  ))

  # Verify capture_async_options includes the audit hook
  captured <- capture_async_options()
  testthat::expect_true(is.function(captured[["shinyOAuth.audit_hook"]]))
  testthat::expect_true(
    is.numeric(captured[[".shinyOAuth.main_process_id"]])
  )

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

      # Mock token exchange to avoid HTTP
      testthat::with_mocked_bindings(
        swap_code_for_token_set = function(
          client,
          code,
          code_verifier,
          shiny_session = NULL
        ) {
          list(access_token = "t-async-options", expires_in = 3600)
        },
        .package = "shinyOAuth",
        {
          values$.process_query(paste0("?code=ok&state=", enc))

          # Allow promise handlers to run
          deadline <- Sys.time() + 5
          while (is.null(values$token) && Sys.time() < deadline) {
            later::run_now(0.05)
            session$flushReact()
            Sys.sleep(0.01)
          }
        }
      )

      # Wait for audit hook events to arrive
      deadline <- Sys.time() + 5
      while (length(audit_events) == 0 && Sys.time() < deadline) {
        later::run_now(0.05)
        session$flushReact()
        Sys.sleep(0.01)
      }

      testthat::expect_true(
        length(audit_events) > 0,
        info = "Expected at least one audit event to be captured"
      )

      # Check that at least one event has is_async = TRUE (indicating it came
      # from an async worker context)
      async_events <- Filter(
        function(e) {
          isTRUE((e$shiny_session %||% list())$is_async)
        },
        audit_events
      )

      testthat::expect_true(
        length(async_events) > 0,
        info = "Expected at least one audit event with is_async = TRUE"
      )

      # Verify async events include process_id information
      for (evt in async_events) {
        sess <- evt$shiny_session
        testthat::expect_true(
          !is.null(sess$main_process_id),
          info = "Async event should include main_process_id"
        )
      }
    }
  )
})

testthat::test_that("with_async_options correctly restores options in worker", {
  # Unit test for the with_async_options helper
  # First, ensure we have a clean slate for our test option

  old_timeout <- getOption("shinyOAuth.timeout")
  on.exit(options(shinyOAuth.timeout = old_timeout), add = TRUE)
  options(shinyOAuth.timeout = NULL)

  captured <- list(
    shinyOAuth.timeout = 99,
    shinyOAuth.audit_hook = function(e) "test",
    ".shinyOAuth.main_process_id" = 12345L
  )

  # Options should not be set before (we cleared it above)
  testthat::expect_null(getOption("shinyOAuth.timeout"))

  result <- shinyOAuth:::with_async_options(captured, {
    # Inside the block, options should be set
    list(
      timeout = getOption("shinyOAuth.timeout"),
      hook_is_fn = is.function(getOption("shinyOAuth.audit_hook"))
    )
  })

  testthat::expect_equal(result$timeout, 99)
  testthat::expect_true(result$hook_is_fn)

  # After the block, options should be restored (NULL in this case)
  testthat::expect_null(getOption("shinyOAuth.timeout"))
})

testthat::test_that("capture_async_options captures all current options", {
  # Set some test options
  withr::local_options(list(
    shinyOAuth.audit_hook = function(e) "hook",
    shinyOAuth.trace_hook = function(e) "trace",
    shinyOAuth.timeout = 42,
    shinyOAuth.leeway = 60,
    my.custom.option = "custom_value"
  ))

  captured <- shinyOAuth:::capture_async_options()

  # Should capture shinyOAuth options
  testthat::expect_true(is.function(captured[["shinyOAuth.audit_hook"]]))
  testthat::expect_true(is.function(captured[["shinyOAuth.trace_hook"]]))
  testthat::expect_equal(captured[["shinyOAuth.timeout"]], 42)

  testthat::expect_equal(captured[["shinyOAuth.leeway"]], 60)

  # Should also capture other options (all options are now captured)
  testthat::expect_equal(captured[["my.custom.option"]], "custom_value")

  # Should include main process ID marker
  testthat::expect_true(!is.null(captured[[".shinyOAuth.main_process_id"]]))
})

testthat::test_that("is_async_worker correctly detects worker context", {
  main_pid <- Sys.getpid()

  # When captured_opts has same PID, not in async worker
  same_pid_opts <- list(".shinyOAuth.main_process_id" = main_pid)
  testthat::expect_false(shinyOAuth:::is_async_worker(same_pid_opts))

  # When captured_opts has different PID, in async worker
  diff_pid_opts <- list(".shinyOAuth.main_process_id" = main_pid + 999L)
  testthat::expect_true(shinyOAuth:::is_async_worker(diff_pid_opts))

  # When captured_opts is NULL, returns NA
  testthat::expect_true(is.na(shinyOAuth:::is_async_worker(NULL)))
})

testthat::test_that("all options are propagated to async workers via future_promise", {
  testthat::skip_on_cran()
  testthat::skip_if_not_installed("promises")
  testthat::skip_if_not_installed("future")
  testthat::skip_if_not_installed("later")

  # Use sequential plan so the test runs in-process (mocks apply)
  old_plan <- tryCatch(future::plan(), error = function(...) NULL)
  try(future::plan(future::sequential), silent = TRUE)
  withr::defer({
    if (!is.null(old_plan)) try(future::plan(old_plan), silent = TRUE)
  })

  # Set a variety of options: shinyOAuth options, custom options, and functions
  custom_fn_called <- FALSE
  withr::local_options(list(
    # shinyOAuth options
    shinyOAuth.timeout = 123,
    shinyOAuth.leeway = 456,
    shinyOAuth.custom_test = "shinyOAuth_value",
    # Arbitrary custom options (not shinyOAuth prefixed)
    my.app.setting = "my_setting_value",
    my.app.number = 999,
    my.app.list = list(a = 1, b = 2),
    # A function option
    my.app.callback = function(x) {
      custom_fn_called <<- TRUE
      x * 2
    }
  ))

  # Capture options on main thread
  captured_opts <- shinyOAuth:::capture_async_options()

  # Verify capture includes all our options
  testthat::expect_equal(captured_opts[["shinyOAuth.timeout"]], 123)
  testthat::expect_equal(captured_opts[["shinyOAuth.leeway"]], 456)
  testthat::expect_equal(
    captured_opts[["shinyOAuth.custom_test"]],
    "shinyOAuth_value"
  )
  testthat::expect_equal(captured_opts[["my.app.setting"]], "my_setting_value")
  testthat::expect_equal(captured_opts[["my.app.number"]], 999)
  testthat::expect_equal(captured_opts[["my.app.list"]], list(a = 1, b = 2))
  testthat::expect_true(is.function(captured_opts[["my.app.callback"]]))

  # Simulate what happens in a future_promise: options are restored in worker
  # Clear the options first to simulate a fresh worker environment
  withr::local_options(list(
    shinyOAuth.timeout = NULL,
    my.app.setting = NULL,
    my.app.number = NULL,
    my.app.callback = NULL
  ))

  # Now use with_async_options to restore them (simulating worker behavior)
  result <- shinyOAuth:::with_async_options(captured_opts, {
    # Inside the worker, all options should be available
    list(
      timeout = getOption("shinyOAuth.timeout"),
      leeway = getOption("shinyOAuth.leeway"),
      custom_test = getOption("shinyOAuth.custom_test"),
      setting = getOption("my.app.setting"),
      number = getOption("my.app.number"),
      app_list = getOption("my.app.list"),
      callback_result = getOption("my.app.callback")(21)
    )
  })

  # Verify all options were available inside the "worker"
  testthat::expect_equal(result$timeout, 123)
  testthat::expect_equal(result$leeway, 456)
  testthat::expect_equal(result$custom_test, "shinyOAuth_value")
  testthat::expect_equal(result$setting, "my_setting_value")
  testthat::expect_equal(result$number, 999)
  testthat::expect_equal(result$app_list, list(a = 1, b = 2))
  testthat::expect_equal(result$callback_result, 42)
  testthat::expect_true(custom_fn_called)
})

testthat::test_that("options propagation works with actual future_promise", {
  testthat::skip_on_cran()
  testthat::skip_if_not_installed("promises")
  testthat::skip_if_not_installed("future")
  testthat::skip_if_not_installed("later")

  # Use sequential so we can verify behavior without true parallelism
  old_plan <- tryCatch(future::plan(), error = function(...) NULL)
  try(future::plan(future::sequential), silent = TRUE)
  withr::defer({
    if (!is.null(old_plan)) try(future::plan(old_plan), silent = TRUE)
  })

  # Set custom options
  withr::local_options(list(
    test.async.value = "hello_from_main",
    test.async.number = 42,
    test.async.fn = function() "function_result"
  ))

  # Capture options before spawning the future
  captured_opts <- shinyOAuth:::capture_async_options()
  main_pid <- Sys.getpid()

  # Create a future_promise that checks options inside the worker
  promise_result <- NULL
  p <- promises::future_promise({
    shinyOAuth:::with_async_options(captured_opts, {
      list(
        value = getOption("test.async.value"),
        number = getOption("test.async.number"),
        fn_result = getOption("test.async.fn")(),
        worker_pid = Sys.getpid(),
        main_pid_from_opts = captured_opts[[".shinyOAuth.main_process_id"]]
      )
    })
  })

  # Wait for promise to resolve
  promises::then(p, function(result) {
    promise_result <<- result
  })

  # Poll until resolved
  deadline <- Sys.time() + 5
  while (is.null(promise_result) && Sys.time() < deadline) {
    later::run_now(0.05)
    Sys.sleep(0.01)
  }

  testthat::expect_false(is.null(promise_result))
  testthat::expect_equal(promise_result$value, "hello_from_main")
  testthat::expect_equal(promise_result$number, 42)
  testthat::expect_equal(promise_result$fn_result, "function_result")
  testthat::expect_equal(promise_result$main_pid_from_opts, main_pid)
})
