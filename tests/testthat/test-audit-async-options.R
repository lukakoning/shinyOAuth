testthat::test_that("audit hook options propagate to async workers with async session context", {
  testthat::skip_on_cran()
  testthat::skip_if_not_installed("promises")
  testthat::skip_if_not_installed("mirai")
  testthat::skip_if_not_installed("later")

  ok <- tryCatch(
    {
      mirai::daemons(2, rs = "--vanilla")
      TRUE
    },
    error = function(...) FALSE
  )
  testthat::skip_if(!ok, "Could not start mirai daemons")
  withr::defer(mirai::daemons(0))

  main_pid <- Sys.getpid()
  withr::local_options(list(
    shinyOAuth.audit_hook = local({
      worker_events <- list()
      function(event) {
        worker_events <<- c(worker_events, list(event))
        invisible(NULL)
      }
    })
  ))

  captured <- shinyOAuth:::capture_async_options()
  testthat::expect_true(is.function(captured[["shinyOAuth.audit_hook"]]))
  testthat::expect_true(
    is.numeric(captured[[".shinyOAuth.main_process_id"]])
  )
  resolved <- NULL
  ctx <- list(
    token = "session-token-from-main",
    is_async = TRUE,
    main_process_id = main_pid
  )
  promise <- shinyOAuth:::async_dispatch(
    expr = quote({
      .ns <- asNamespace("shinyOAuth")
      .ns$with_async_options(captured_opts, {
        .ns$with_async_session_context(ctx, {
          .ns$audit_event("test_async_worker")
        })
        hook <- getOption("shinyOAuth.audit_hook")
        get("worker_events", envir = environment(hook), inherits = FALSE)
      })
    }),
    args = list(
      captured_opts = captured,
      ctx = ctx
    )
  )
  promises::then(promises::as.promise(promise), function(value) {
    resolved <<- value
  })
  poll_for_async(function() !is.null(resolved), timeout = 10)

  worker_events <- shinyOAuth:::replay_async_conditions(resolved)
  testthat::expect_true(length(worker_events) > 0)

  async_events <- Filter(
    function(e) isTRUE((e$shiny_session %||% list())$is_async),
    worker_events
  )
  testthat::expect_true(length(async_events) > 0)

  event <- async_events[[1]]
  testthat::expect_identical(event$type, "audit_test_async_worker")
  testthat::expect_identical(event$shiny_session$token, ctx$token)
  testthat::expect_identical(
    as.integer(event$shiny_session$main_process_id),
    as.integer(main_pid)
  )
  testthat::expect_true(!is.null(event$shiny_session$process_id))
  testthat::expect_false(
    identical(
      as.integer(event$shiny_session$process_id),
      as.integer(main_pid)
    )
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

testthat::test_that("with_async_options restores captured otel env vars", {
  withr::local_envvar(c(
    OTEL_TRACES_EXPORTER = "http",
    OTEL_EXPORTER_OTLP_ENDPOINT = "http://localhost:4318"
  ))

  captured <- list(
    ".shinyOAuth.otel_envvars" = c(
      OTEL_TRACES_EXPORTER = "none",
      OTEL_EXPORTER_OTLP_ENDPOINT = NA_character_
    )
  )

  result <- shinyOAuth:::with_async_options(captured, {
    Sys.getenv(
      c("OTEL_TRACES_EXPORTER", "OTEL_EXPORTER_OTLP_ENDPOINT"),
      unset = NA_character_
    )
  })

  testthat::expect_identical(result[["OTEL_TRACES_EXPORTER"]], "none")
  testthat::expect_true(is.na(result[["OTEL_EXPORTER_OTLP_ENDPOINT"]]))
  testthat::expect_identical(Sys.getenv("OTEL_TRACES_EXPORTER"), "http")
  testthat::expect_identical(
    Sys.getenv("OTEL_EXPORTER_OTLP_ENDPOINT"),
    "http://localhost:4318"
  )
})

testthat::test_that("with_async_options clears stale worker otel vars missing from capture", {
  withr::local_envvar(c(
    OTEL_R_TRACES_EXPORTER = "none",
    OTEL_TRACES_EXPORTER = "none",
    OTEL_EXPORTER_OTLP_TRACES_FILE = "stale-worker.jsonl"
  ))

  captured <- list(
    ".shinyOAuth.otel_envvars" = c(
      OTEL_R_TRACES_EXPORTER = "none",
      OTEL_TRACES_EXPORTER = "none"
    )
  )

  result <- shinyOAuth:::with_async_options(captured, {
    Sys.getenv(
      c(
        "OTEL_R_TRACES_EXPORTER",
        "OTEL_TRACES_EXPORTER",
        "OTEL_EXPORTER_OTLP_TRACES_FILE"
      ),
      unset = NA_character_
    )
  })

  testthat::expect_identical(result[["OTEL_R_TRACES_EXPORTER"]], "none")
  testthat::expect_identical(result[["OTEL_TRACES_EXPORTER"]], "none")
  testthat::expect_true(is.na(result[["OTEL_EXPORTER_OTLP_TRACES_FILE"]]))
  testthat::expect_identical(
    Sys.getenv("OTEL_EXPORTER_OTLP_TRACES_FILE"),
    "stale-worker.jsonl"
  )
})

testthat::test_that("with_async_options rebuilds cached otel providers", {
  testthat::skip_if_not_installed("otel")

  old_otel_state <- capture_test_otel_state()
  withr::defer(restore_test_otel_state(old_otel_state))

  otel_ns <- asNamespace("otel")
  withr::local_envvar(c(
    OTEL_R_TRACES_EXPORTER = "none",
    OTEL_TRACES_EXPORTER = "none",
    OTEL_R_LOGS_EXPORTER = "none",
    OTEL_LOGS_EXPORTER = "none"
  ))

  get("otel_clean_cache", envir = otel_ns)()
  get("setup_default_tracer_provider", envir = otel_ns)()
  testthat::expect_false(otel::is_tracing_enabled())

  result <- shinyOAuth:::with_async_options(
    list(
      ".shinyOAuth.otel_envvars" = c(
        OTEL_R_TRACES_EXPORTER = "console",
        OTEL_TRACES_EXPORTER = "console",
        OTEL_R_LOGS_EXPORTER = "none",
        OTEL_LOGS_EXPORTER = "none"
      )
    ),
    {
      list(
        tracing_enabled = otel::is_tracing_enabled(),
        traces_exporter = Sys.getenv(
          "OTEL_R_TRACES_EXPORTER",
          unset = NA_character_
        )
      )
    }
  )

  testthat::expect_true(isTRUE(result$tracing_enabled))
  testthat::expect_identical(result$traces_exporter, "console")
})

testthat::test_that("with_async_options rebuilds cached otel providers when exporters are disabled", {
  testthat::skip_if_not_installed("otel")

  old_otel_state <- capture_test_otel_state()
  withr::defer(restore_test_otel_state(old_otel_state))

  otel_ns <- asNamespace("otel")
  withr::local_envvar(c(
    OTEL_R_TRACES_EXPORTER = "console",
    OTEL_TRACES_EXPORTER = "console",
    OTEL_R_LOGS_EXPORTER = "console",
    OTEL_LOGS_EXPORTER = "console"
  ))

  get("otel_clean_cache", envir = otel_ns)()
  get("setup_default_tracer_provider", envir = otel_ns)()
  get("setup_default_logger_provider", envir = otel_ns)()
  testthat::expect_true(otel::is_tracing_enabled())
  testthat::expect_true(otel::is_logging_enabled())

  result <- shinyOAuth:::with_async_options(
    list(
      ".shinyOAuth.otel_envvars" = c(
        OTEL_R_TRACES_EXPORTER = "none",
        OTEL_TRACES_EXPORTER = "none",
        OTEL_R_LOGS_EXPORTER = "none",
        OTEL_LOGS_EXPORTER = "none"
      )
    ),
    {
      list(
        tracing_enabled = otel::is_tracing_enabled(),
        logging_enabled = otel::is_logging_enabled(),
        traces_exporter = Sys.getenv(
          "OTEL_R_TRACES_EXPORTER",
          unset = NA_character_
        ),
        logs_exporter = Sys.getenv(
          "OTEL_R_LOGS_EXPORTER",
          unset = NA_character_
        )
      )
    }
  )

  testthat::expect_false(isTRUE(result$tracing_enabled))
  testthat::expect_false(isTRUE(result$logging_enabled))
  testthat::expect_identical(result$traces_exporter, "none")
  testthat::expect_identical(result$logs_exporter, "none")
})

testthat::test_that("with_async_options clears cached otel providers after restoring unset env", {
  testthat::skip_if_not_installed("otel")

  old_otel_state <- capture_test_otel_state()
  withr::defer(restore_test_otel_state(old_otel_state))

  otel_ns <- asNamespace("otel")
  unset_env <- c(
    OTEL_R_TRACES_EXPORTER = NA_character_,
    OTEL_TRACES_EXPORTER = NA_character_,
    OTEL_R_LOGS_EXPORTER = NA_character_,
    OTEL_LOGS_EXPORTER = NA_character_
  )
  withr::local_envvar(unset_env)

  get("otel_clean_cache", envir = otel_ns)()
  get("setup_default_tracer_provider", envir = otel_ns)()
  get("setup_default_logger_provider", envir = otel_ns)()
  testthat::expect_false(isTRUE(otel::is_tracing_enabled()))
  testthat::expect_false(isTRUE(otel::is_logging_enabled()))

  result <- shinyOAuth:::with_async_options(
    list(
      ".shinyOAuth.otel_envvars" = c(
        OTEL_R_TRACES_EXPORTER = "console",
        OTEL_TRACES_EXPORTER = "console",
        OTEL_R_LOGS_EXPORTER = "none",
        OTEL_LOGS_EXPORTER = "none"
      )
    ),
    {
      list(
        tracing_enabled = otel::is_tracing_enabled(),
        traces_exporter = Sys.getenv(
          "OTEL_R_TRACES_EXPORTER",
          unset = NA_character_
        )
      )
    }
  )

  testthat::expect_true(isTRUE(result$tracing_enabled))
  testthat::expect_identical(result$traces_exporter, "console")
  testthat::expect_true(is.na(Sys.getenv(
    "OTEL_R_TRACES_EXPORTER",
    unset = NA_character_
  )))
  testthat::expect_true(is.na(Sys.getenv(
    "OTEL_TRACES_EXPORTER",
    unset = NA_character_
  )))
  testthat::expect_false(isTRUE(otel::is_tracing_enabled()))
})

testthat::test_that("with_async_options restores captured digest key cache", {
  ns <- asNamespace("shinyOAuth")
  key_env <- get("audit_digest_key_env", envir = ns)
  old_key <- key_env$key
  on.exit(
    {
      key_env$key <- old_key
    },
    add = TRUE
  )

  withr::local_options(list(shinyOAuth.audit_digest_key = NULL))
  key_env$key <- NULL

  main_digest <- shinyOAuth:::string_digest("hello")
  captured <- shinyOAuth:::capture_async_options()

  key_env$key <- NULL
  worker_digest <- shinyOAuth:::with_async_options(captured, {
    get("string_digest", envir = asNamespace("shinyOAuth"))("hello")
  })

  testthat::expect_identical(worker_digest, main_digest)
})

testthat::test_that("capture_async_options captures only shinyOAuth options", {
  # Set some test options - both shinyOAuth and non-shinyOAuth
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

  # Should NOT capture non-shinyOAuth options (avoids serialization warnings)
  testthat::expect_null(captured[["my.custom.option"]])

  # Should include main process ID marker
  testthat::expect_true(!is.null(captured[[".shinyOAuth.main_process_id"]]))
  testthat::expect_true(!is.null(captured[[".shinyOAuth.otel_envvars"]]))
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

testthat::test_that("augment_with_shiny_context normalizes borrowed async context", {
  main_pid <- Sys.getpid()
  event <- list(
    type = "audit_test",
    shiny_session = list(
      token = "tok",
      is_async = TRUE,
      main_process_id = main_pid
    )
  )

  normalized <- shinyOAuth:::augment_with_shiny_context(event)

  testthat::expect_false(isTRUE(normalized$shiny_session$is_async))
  testthat::expect_identical(
    as.integer(normalized$shiny_session$process_id),
    as.integer(main_pid)
  )
})

testthat::test_that("augment_with_shiny_context fills worker process_id from async context", {
  ctx <- list(
    token = "tok",
    is_async = TRUE,
    main_process_id = 12345L,
    process_id = Sys.getpid()
  )

  shinyOAuth:::with_async_session_context(ctx, {
    event <- list(
      type = "audit_test",
      shiny_session = list(
        token = "tok",
        is_async = TRUE,
        main_process_id = 12345L
      )
    )

    normalized <- shinyOAuth:::augment_with_shiny_context(event)
    testthat::expect_true(isTRUE(normalized$shiny_session$is_async))
    testthat::expect_identical(
      as.integer(normalized$shiny_session$process_id),
      as.integer(Sys.getpid())
    )
  })
})

testthat::test_that("shinyOAuth options are propagated to async workers via mirai", {
  testthat::skip_on_cran()
  testthat::skip_if_not_installed("promises")
  testthat::skip_if_not_installed("mirai")
  testthat::skip_if_not_installed("later")

  # Use mirai sync mode so the test runs in-process (mocks apply)
  mirai::daemons(sync = TRUE)
  withr::defer(mirai::daemons(0))

  # Set a variety of options: shinyOAuth options and non-shinyOAuth options
  withr::local_options(list(
    # shinyOAuth options (should be captured)
    shinyOAuth.timeout = 123,
    shinyOAuth.leeway = 456,
    shinyOAuth.custom_test = "shinyOAuth_value",
    # Arbitrary custom options (not shinyOAuth prefixed - should NOT be captured)
    my.app.setting = "my_setting_value",
    my.app.number = 999
  ))

  # Capture options on main thread
  captured_opts <- shinyOAuth:::capture_async_options()

  # Verify capture includes only shinyOAuth.* options (not arbitrary app options)
  testthat::expect_equal(captured_opts[["shinyOAuth.timeout"]], 123)
  testthat::expect_equal(captured_opts[["shinyOAuth.leeway"]], 456)
  testthat::expect_equal(
    captured_opts[["shinyOAuth.custom_test"]],
    "shinyOAuth_value"
  )
  # Non-shinyOAuth options should NOT be captured (avoids serialization warnings)
  testthat::expect_null(captured_opts[["my.app.setting"]])
  testthat::expect_null(captured_opts[["my.app.number"]])

  # Simulate what happens in a mirai: options are restored in worker
  # Clear the options first to simulate a fresh worker environment
  withr::local_options(list(
    shinyOAuth.timeout = NULL,
    shinyOAuth.leeway = NULL,
    shinyOAuth.custom_test = NULL
  ))

  # Now use with_async_options to restore them (simulating worker behavior)
  result <- shinyOAuth:::with_async_options(captured_opts, {
    # Inside the worker, shinyOAuth options should be available
    list(
      timeout = getOption("shinyOAuth.timeout"),
      leeway = getOption("shinyOAuth.leeway"),
      custom_test = getOption("shinyOAuth.custom_test")
    )
  })

  # Verify shinyOAuth options were available inside the "worker"
  testthat::expect_equal(result$timeout, 123)
  testthat::expect_equal(result$leeway, 456)
  testthat::expect_equal(result$custom_test, "shinyOAuth_value")
})

testthat::test_that("options propagation works with actual mirai", {
  testthat::skip_on_cran()
  testthat::skip_if_not_installed("promises")
  testthat::skip_if_not_installed("mirai")
  testthat::skip_if_not_installed("later")

  # Use sync mode so we can verify behavior without true parallelism
  mirai::daemons(sync = TRUE)
  withr::defer(mirai::daemons(0))

  # Set shinyOAuth options (only these are propagated to avoid serialization warnings)
  withr::local_options(list(
    shinyOAuth.async.value = "hello_from_main",
    shinyOAuth.async.number = 42
  ))

  # Capture options before spawning the mirai
  captured_opts <- shinyOAuth:::capture_async_options()
  main_pid <- Sys.getpid()

  # Capture the function for use in mirai
  .with_async_options <- shinyOAuth:::with_async_options

  # Create a mirai that checks options inside the worker
  promise_result <- NULL
  m <- mirai::mirai(
    {
      .with_async_options(captured_opts, {
        list(
          value = getOption("shinyOAuth.async.value"),
          number = getOption("shinyOAuth.async.number"),
          worker_pid = Sys.getpid(),
          main_pid_from_opts = captured_opts[[".shinyOAuth.main_process_id"]]
        )
      })
    },
    .args = list(
      .with_async_options = .with_async_options,
      captured_opts = captured_opts
    )
  )

  # Wait for mirai to resolve
  p <- promises::as.promise(m)
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
  testthat::expect_equal(promise_result$main_pid_from_opts, main_pid)
})

testthat::test_that("otel env vars propagate to actual mirai workers", {
  testthat::skip_on_cran()
  testthat::skip_if_not_installed("promises")
  testthat::skip_if_not_installed("mirai")
  testthat::skip_if_not_installed("later")

  ok <- tryCatch(
    {
      mirai::daemons(2, rs = "--vanilla")
      TRUE
    },
    error = function(...) FALSE
  )
  if (!ok) {
    mirai::daemons(sync = TRUE)
  }
  withr::defer(mirai::daemons(0))

  withr::local_envvar(c(
    OTEL_TRACES_EXPORTER = "none",
    OTEL_LOGS_EXPORTER = "none",
    OTEL_METRICS_EXPORTER = "none",
    OTEL_EXPORTER_OTLP_ENDPOINT = NA_character_
  ))

  captured_opts <- shinyOAuth:::capture_async_options()
  promise_result <- NULL
  .with_async_options <- shinyOAuth:::with_async_options

  m <- mirai::mirai(
    {
      .with_async_options(captured_opts, {
        Sys.getenv(
          c(
            "OTEL_TRACES_EXPORTER",
            "OTEL_LOGS_EXPORTER",
            "OTEL_METRICS_EXPORTER",
            "OTEL_EXPORTER_OTLP_ENDPOINT"
          ),
          unset = NA_character_
        )
      })
    },
    .args = list(
      .with_async_options = .with_async_options,
      captured_opts = captured_opts
    )
  )

  promises::then(promises::as.promise(m), function(result) {
    promise_result <<- result
  })

  deadline <- Sys.time() + 5
  while (is.null(promise_result) && Sys.time() < deadline) {
    later::run_now(0.05)
    Sys.sleep(0.01)
  }

  testthat::expect_false(is.null(promise_result))
  testthat::expect_identical(promise_result[["OTEL_TRACES_EXPORTER"]], "none")
  testthat::expect_identical(promise_result[["OTEL_LOGS_EXPORTER"]], "none")
  testthat::expect_identical(promise_result[["OTEL_METRICS_EXPORTER"]], "none")
  testthat::expect_true(is.na(promise_result[["OTEL_EXPORTER_OTLP_ENDPOINT"]]))
})

testthat::test_that("reused async workers honor otel exporter disable transitions", {
  testthat::skip_on_cran()
  testthat::skip_if_not_installed("otel")
  testthat::skip_if_not_installed("promises")
  testthat::skip_if_not_installed("mirai")
  testthat::skip_if_not_installed("later")

  old_otel_state <- capture_test_otel_state()
  withr::defer(restore_test_otel_state(old_otel_state))

  ok <- tryCatch(
    {
      mirai::daemons(1, rs = "--vanilla")
      TRUE
    },
    error = function(...) FALSE
  )
  testthat::skip_if(!ok, "Could not start mirai daemons")
  withr::defer(mirai::daemons(0))

  dispatch_state <- function() {
    resolved <- NULL
    promises::then(
      promises::as.promise(
        shinyOAuth:::async_dispatch(
          expr = quote({
            .otel_ns <- asNamespace("otel")
            get("setup_default_tracer_provider", envir = .otel_ns)()
            get("setup_default_logger_provider", envir = .otel_ns)()
            list(
              pid = Sys.getpid(),
              tracing_enabled = otel::is_tracing_enabled(),
              logging_enabled = otel::is_logging_enabled(),
              traces_exporter = Sys.getenv(
                "OTEL_R_TRACES_EXPORTER",
                unset = NA_character_
              ),
              logs_exporter = Sys.getenv(
                "OTEL_R_LOGS_EXPORTER",
                unset = NA_character_
              )
            )
          }),
          args = list()
        )
      ),
      function(value) {
        resolved <<- value
        invisible(NULL)
      }
    )

    poll_for_async(function() !is.null(resolved), timeout = 10)
    testthat::expect_false(is.null(resolved))
    shinyOAuth:::replay_async_conditions(resolved)
  }

  withr::local_envvar(c(
    OTEL_R_TRACES_EXPORTER = "console",
    OTEL_TRACES_EXPORTER = "console",
    OTEL_R_LOGS_EXPORTER = "console",
    OTEL_LOGS_EXPORTER = "console",
    OTEL_R_METRICS_EXPORTER = "none",
    OTEL_METRICS_EXPORTER = "none"
  ))
  first_result <- dispatch_state()

  withr::local_envvar(c(
    OTEL_R_TRACES_EXPORTER = "none",
    OTEL_TRACES_EXPORTER = "none",
    OTEL_R_LOGS_EXPORTER = "none",
    OTEL_LOGS_EXPORTER = "none",
    OTEL_R_METRICS_EXPORTER = "none",
    OTEL_METRICS_EXPORTER = "none"
  ))
  second_result <- dispatch_state()

  testthat::expect_true(isTRUE(first_result$tracing_enabled))
  testthat::expect_true(isTRUE(first_result$logging_enabled))
  testthat::expect_identical(first_result$traces_exporter, "console")
  testthat::expect_identical(first_result$logs_exporter, "console")
  testthat::expect_identical(second_result$pid, first_result$pid)
  testthat::expect_false(isTRUE(second_result$tracing_enabled))
  testthat::expect_false(isTRUE(second_result$logging_enabled))
  testthat::expect_identical(second_result$traces_exporter, "none")
  testthat::expect_identical(second_result$logs_exporter, "none")
})

testthat::test_that("emit_trace_event surfaces trace_hook errors as warnings", {
  withr::local_options(list(
    shinyOAuth.trace_hook = function(event) stop("trace hook boom"),
    shinyOAuth.audit_hook = NULL
  ))

  testthat::expect_warning(
    shinyOAuth:::emit_trace_event(list(type = "test")),
    "trace_hook error: trace hook boom"
  )
})

testthat::test_that("emit_trace_event surfaces audit_hook errors as warnings", {
  withr::local_options(list(
    shinyOAuth.trace_hook = NULL,
    shinyOAuth.audit_hook = function(event) stop("audit hook boom")
  ))

  testthat::expect_warning(
    shinyOAuth:::emit_trace_event(list(type = "test")),
    "audit_hook error: audit hook boom"
  )
})

testthat::test_that("hook errors in async workers propagate to main process", {
  testthat::skip_on_cran()
  testthat::skip_if_not_installed("promises")
  testthat::skip_if_not_installed("mirai")
  testthat::skip_if_not_installed("later")

  ok <- tryCatch(
    {
      mirai::daemons(2, rs = "--vanilla")
      TRUE
    },
    error = function(...) FALSE
  )
  testthat::skip_if(!ok, "Could not start mirai daemons")
  withr::defer(mirai::daemons(0))

  # Set an audit hook that always errors
  withr::local_options(list(
    shinyOAuth.audit_hook = function(event) stop("broken hook"),
    shinyOAuth.trace_hook = NULL
  ))

  m <- shinyOAuth:::async_dispatch(
    expr = quote({
      .ns <- asNamespace("shinyOAuth")
      .ns$with_async_options(captured_opts, {
        .ns$audit_event("test_hook_error", context = list(a = 1))
      })
      "done"
    }),
    args = list(captured_opts = shinyOAuth:::capture_async_options())
  )

  resolved <- NULL
  p <- m |>
    promises::then(function(x) {
      resolved <<- x
    })
  poll_for_async(function() !is.null(resolved))

  # The hook error should have been captured as a warning
  testthat::expect_length(resolved$warnings, 1)
  testthat::expect_match(
    conditionMessage(resolved$warnings[[1]]),
    "audit_hook error: broken hook"
  )

  # replay_async_conditions should re-emit the warning on the main thread
  testthat::expect_warning(
    val <- shinyOAuth:::replay_async_conditions(resolved),
    "audit_hook error: broken hook"
  )
  testthat::expect_equal(val, "done")
})

# --- True async (real daemon) tests ------------------------------------------
# These tests use mirai::daemons(2) to verify behaviour across real separate
# worker processes, NOT sync mode. They are skipped on CRAN and when daemons
# cannot be launched.

testthat::test_that("true-async: conditions captured in daemon worker are replayed on main", {
  testthat::skip_on_cran()
  testthat::skip_if_not_installed("promises")
  testthat::skip_if_not_installed("mirai")
  testthat::skip_if_not_installed("later")

  ok <- tryCatch(
    {
      mirai::daemons(2, rs = "--vanilla")
      TRUE
    },
    error = function(...) FALSE
  )
  testthat::skip_if(!ok, "Could not start mirai daemons")
  withr::defer(mirai::daemons(0))

  m <- shinyOAuth:::async_dispatch(
    expr = quote({
      message("daemon msg alpha")
      warning("daemon warn beta", call. = FALSE)
      message("daemon msg gamma")
      warning("daemon warn delta", call. = FALSE)
      list(pid = Sys.getpid(), val = 99)
    }),
    args = list()
  )

  resolved <- NULL
  promises::then(promises::as.promise(m), function(x) {
    resolved <<- x
  })
  poll_for_async(function() !is.null(resolved), timeout = 10)

  testthat::expect_true(isTRUE(resolved$.shinyOAuth_async_wrapped))
  testthat::expect_equal(resolved$value$val, 99)
  # Worker ran in a different process
  testthat::expect_false(resolved$value$pid == Sys.getpid())
  testthat::expect_length(resolved$warnings, 2)
  testthat::expect_length(resolved$messages, 2)
  testthat::expect_match(
    conditionMessage(resolved$warnings[[1]]),
    "daemon warn beta"
  )
  testthat::expect_match(
    conditionMessage(resolved$warnings[[2]]),
    "daemon warn delta"
  )
  testthat::expect_match(
    conditionMessage(resolved$messages[[1]]),
    "daemon msg alpha"
  )
  testthat::expect_match(
    conditionMessage(resolved$messages[[2]]),
    "daemon msg gamma"
  )

  # Replay re-emits all 4 conditions
  testthat::expect_warning(
    testthat::expect_warning(
      testthat::expect_message(
        testthat::expect_message(
          {
            val <- shinyOAuth:::replay_async_conditions(resolved)
          },
          "daemon msg alpha"
        ),
        "daemon msg gamma"
      ),
      "daemon warn beta"
    ),
    "daemon warn delta"
  )
  testthat::expect_equal(val$val, 99)
})

testthat::test_that("true-async: hook errors surface as warnings from daemon worker", {
  testthat::skip_on_cran()
  testthat::skip_if_not_installed("promises")
  testthat::skip_if_not_installed("mirai")
  testthat::skip_if_not_installed("later")

  ok <- tryCatch(
    {
      mirai::daemons(2, rs = "--vanilla")
      TRUE
    },
    error = function(...) FALSE
  )
  testthat::skip_if(!ok, "Could not start mirai daemons")
  withr::defer(mirai::daemons(0))

  # Set hooks that error - these get serialized and sent to the daemon
  withr::local_options(list(
    shinyOAuth.trace_hook = function(event) stop("trace kaboom"),
    shinyOAuth.audit_hook = function(event) stop("audit kaboom")
  ))

  captured_opts <- shinyOAuth:::capture_async_options()

  m <- shinyOAuth:::async_dispatch(
    expr = quote({
      .ns <- asNamespace("shinyOAuth")
      .ns$with_async_options(captured_opts, {
        .ns$emit_trace_event(list(type = "test_from_daemon"))
      })
      "hook_test_done"
    }),
    args = list(captured_opts = captured_opts)
  )

  resolved <- NULL
  promises::then(promises::as.promise(m), function(x) {
    resolved <<- x
  })
  poll_for_async(function() !is.null(resolved), timeout = 10)

  testthat::expect_true(isTRUE(resolved$.shinyOAuth_async_wrapped))
  testthat::expect_equal(resolved$value, "hook_test_done")
  # Both hook errors should have been captured as warnings
  testthat::expect_true(length(resolved$warnings) >= 2)
  msgs <- vapply(resolved$warnings, conditionMessage, character(1))
  testthat::expect_true(any(grepl("trace_hook error: trace kaboom", msgs)))
  testthat::expect_true(any(grepl("audit_hook error: audit kaboom", msgs)))

  # Replay surfaces them on main thread
  w_captured <- list()
  val <- withCallingHandlers(
    shinyOAuth:::replay_async_conditions(resolved),
    warning = function(w) {
      w_captured[[length(w_captured) + 1L]] <<- w
      tryInvokeRestart("muffleWarning")
    }
  )
  testthat::expect_equal(val, "hook_test_done")
  w_msgs <- vapply(w_captured, conditionMessage, character(1))
  testthat::expect_true(any(grepl("trace kaboom", w_msgs)))
  testthat::expect_true(any(grepl("audit kaboom", w_msgs)))
})

testthat::test_that("true-async: hook warnings and messages are captured from daemon worker", {
  testthat::skip_on_cran()
  testthat::skip_if_not_installed("promises")
  testthat::skip_if_not_installed("mirai")
  testthat::skip_if_not_installed("later")

  ok <- tryCatch(
    {
      mirai::daemons(2, rs = "--vanilla")
      TRUE
    },
    error = function(...) FALSE
  )
  testthat::skip_if(!ok, "Could not start mirai daemons")
  withr::defer(mirai::daemons(0))

  # Hooks that emit warnings and messages (but do NOT error)
  withr::local_options(list(
    shinyOAuth.trace_hook = function(event) {
      warning("trace hook user warning", call. = FALSE)
      message("trace hook user message")
    },
    shinyOAuth.audit_hook = function(event) {
      warning("audit hook user warning", call. = FALSE)
      message("audit hook user message")
    }
  ))

  captured_opts <- shinyOAuth:::capture_async_options()

  m <- shinyOAuth:::async_dispatch(
    expr = quote({
      .ns <- asNamespace("shinyOAuth")
      .ns$with_async_options(captured_opts, {
        .ns$emit_trace_event(list(type = "hook_condition_test"))
      })
      "hook_conditions_done"
    }),
    args = list(captured_opts = captured_opts)
  )

  resolved <- NULL
  promises::then(promises::as.promise(m), function(x) {
    resolved <<- x
  })
  poll_for_async(function() !is.null(resolved), timeout = 10)

  testthat::expect_true(isTRUE(resolved$.shinyOAuth_async_wrapped))
  testthat::expect_equal(resolved$value, "hook_conditions_done")

  # Both hooks emit 1 warning each -> at least 2 warnings
  testthat::expect_true(length(resolved$warnings) >= 2)
  w_msgs <- vapply(resolved$warnings, conditionMessage, character(1))
  testthat::expect_true(any(grepl("trace hook user warning", w_msgs)))
  testthat::expect_true(any(grepl("audit hook user warning", w_msgs)))

  # Both hooks emit 1 message each -> at least 2 messages
  testthat::expect_true(length(resolved$messages) >= 2)
  m_msgs <- vapply(resolved$messages, conditionMessage, character(1))
  testthat::expect_true(any(grepl("trace hook user message", m_msgs)))
  testthat::expect_true(any(grepl("audit hook user message", m_msgs)))

  # Replay surfaces all conditions on the main thread
  replayed_w <- list()
  replayed_m <- list()
  val <- withCallingHandlers(
    shinyOAuth:::replay_async_conditions(resolved),
    warning = function(w) {
      replayed_w[[length(replayed_w) + 1L]] <<- w
      tryInvokeRestart("muffleWarning")
    },
    message = function(m) {
      replayed_m[[length(replayed_m) + 1L]] <<- m
      tryInvokeRestart("muffleMessage")
    }
  )
  testthat::expect_equal(val, "hook_conditions_done")
  rw_msgs <- vapply(replayed_w, conditionMessage, character(1))
  rm_msgs <- vapply(replayed_m, conditionMessage, character(1))
  testthat::expect_true(any(grepl("trace hook user warning", rw_msgs)))
  testthat::expect_true(any(grepl("audit hook user warning", rw_msgs)))
  testthat::expect_true(any(grepl("trace hook user message", rm_msgs)))
  testthat::expect_true(any(grepl("audit hook user message", rm_msgs)))
})

testthat::test_that("shinyOAuth.replay_async_conditions = FALSE suppresses replay", {
  testthat::skip_on_cran()
  testthat::skip_if_not_installed("promises")
  testthat::skip_if_not_installed("mirai")
  testthat::skip_if_not_installed("later")

  ok <- tryCatch(
    {
      mirai::daemons(2, rs = "--vanilla")
      TRUE
    },
    error = function(...) FALSE
  )
  testthat::skip_if(!ok, "Could not start mirai daemons")
  withr::defer(mirai::daemons(0))

  m <- shinyOAuth:::async_dispatch(
    expr = quote({
      message("should be suppressed")
      warning("also suppressed", call. = FALSE)
      "suppressed_result"
    }),
    args = list()
  )

  resolved <- NULL
  promises::then(promises::as.promise(m), function(x) {
    resolved <<- x
  })
  poll_for_async(function() !is.null(resolved), timeout = 10)

  # Conditions were captured
  testthat::expect_length(resolved$warnings, 1)
  testthat::expect_length(resolved$messages, 1)

  # With the option FALSE, replay should NOT emit them
  withr::local_options(list(shinyOAuth.replay_async_conditions = FALSE))

  # Capture any conditions that might leak
  leaked_warnings <- list()
  leaked_messages <- list()
  withCallingHandlers(
    {
      val <- shinyOAuth:::replay_async_conditions(resolved)
    },
    warning = function(w) {
      leaked_warnings[[length(leaked_warnings) + 1L]] <<- w
      tryInvokeRestart("muffleWarning")
    },
    message = function(m) {
      leaked_messages[[length(leaked_messages) + 1L]] <<- m
      tryInvokeRestart("muffleMessage")
    }
  )

  testthat::expect_equal(val, "suppressed_result")
  testthat::expect_length(leaked_warnings, 0)
  testthat::expect_length(leaked_messages, 0)
})

testthat::test_that("shinyOAuth.replay_async_conditions defaults to TRUE", {
  # Ensure the option is unset
  withr::local_options(list(shinyOAuth.replay_async_conditions = NULL))

  wrapped <- list(
    .shinyOAuth_async_wrapped = TRUE,
    value = "default_test",
    warnings = list(simpleWarning("w1", call = NULL)),
    messages = list(simpleMessage("m1\n", call = NULL))
  )

  # Without the option set, conditions should be replayed (default = TRUE)
  testthat::expect_warning(
    testthat::expect_message(
      {
        val <- shinyOAuth:::replay_async_conditions(wrapped)
      },
      "m1"
    ),
    "w1"
  )
  testthat::expect_equal(val, "default_test")
})

testthat::test_that("shinyOAuth.replay_async_conditions = TRUE explicitly enables replay", {
  withr::local_options(list(shinyOAuth.replay_async_conditions = TRUE))

  wrapped <- list(
    .shinyOAuth_async_wrapped = TRUE,
    value = "explicit_true",
    warnings = list(simpleWarning("explicit_w", call = NULL)),
    messages = list(simpleMessage("explicit_m\n", call = NULL))
  )

  testthat::expect_warning(
    testthat::expect_message(
      {
        val <- shinyOAuth:::replay_async_conditions(wrapped)
      },
      "explicit_m"
    ),
    "explicit_w"
  )
  testthat::expect_equal(val, "explicit_true")
})
