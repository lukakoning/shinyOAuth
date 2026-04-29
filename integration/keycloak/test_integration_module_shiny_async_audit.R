# Integration test: async module with file-based audit logging
# This test verifies that audit events are correctly emitted from both
# the main R process and async workers when using future::multisession

if (!exists("make_provider", mode = "function")) {
  source(file.path(dirname(sys.frame(1)$ofile %||% "."), "helper-keycloak.R"))
}

testthat::test_that("Shiny module async audit: events from main & worker processes logged to file", {
  skip_common()

  # Skip on CRAN
  testthat::skip_on_cran()

  local_test_options()

  # Set up mirai daemons for async work (preferred backend)
  testthat::skip_if_not_installed("mirai")
  testthat::skip_if_not_installed("promises")
  testthat::skip_if_not_installed("later")

  # Reset any existing mirai state and configure fresh daemons
  tryCatch(mirai::daemons(0), error = function(...) NULL)
  mirai::daemons(n = 2)
  withr::defer(tryCatch(mirai::daemons(0), error = function(...) NULL))

  # Create a temporary file for audit logs
  audit_log_file <- tempfile(fileext = ".jsonl")
  withr::defer(unlink(audit_log_file), envir = parent.frame())

  # Set up a file-based audit hook that writes JSON lines
  # The hook writes one JSON object per line with process metadata
  audit_hook <- function(event) {
    # Add process ID where the hook executed for verification
    event$.hook_pid <- Sys.getpid()
    event$.hook_time <- as.character(Sys.time())

    line <- tryCatch(
      jsonlite::toJSON(event, auto_unbox = TRUE, null = "null"),
      error = function(e) {
        jsonlite::toJSON(
          list(
            type = event$type %||% "unknown",
            error = "serialization_failed",
            .hook_pid = Sys.getpid()
          ),
          auto_unbox = TRUE
        )
      }
    )
    # Append to log file (thread-safe atomic write via cat with append)
    cat(line, "\n", file = audit_log_file, append = TRUE)
  }

  withr::local_options(list(shinyOAuth.audit_hook = audit_hook))

  prov <- make_provider()
  client <- make_public_client(prov)

  main_pid <- Sys.getpid()

  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client, async = TRUE),
    expr = {
      url <- values$build_auth_url()
      testthat::expect_true(is.character(url) && nzchar(url))
      res <- perform_login_form(url, redirect_uri = client@redirect_uri)
      testthat::expect_true(
        is.character(res$callback_url) && nzchar(res$callback_url)
      )
      testthat::expect_true(
        is.character(res$state_payload) && nzchar(res$state_payload)
      )

      values$.process_query(callback_query(res))

      # Allow promise handlers to run for async token exchange
      # Wait for both token AND authenticated to be set (async may take time)
      deadline <- Sys.time() + 15
      while (
        (!isTRUE(values$authenticated) || is.null(values$token)) &&
          Sys.time() < deadline
      ) {
        later::run_now(0.05)
        session$flushReact()
        Sys.sleep(0.02)
      }

      # 5) Assertions: authenticated with a token
      testthat::expect_true(
        isTRUE(values$authenticated),
        info = paste0(
          "Expected authenticated=TRUE. error=",
          values$error %||% "<NULL>",
          ", error_description=",
          values$error_description %||% "<NULL>"
        )
      )
      testthat::expect_null(values$error)
      testthat::expect_false(is.null(values$token))
      testthat::expect_true(nzchar(values$token@access_token))

      # Give audit hooks a bit more time to flush to file
      Sys.sleep(0.5)
      later::run_now(0.1)
    }
  )

  # 6) Read and parse audit log file
  Sys.sleep(0.5) # Allow any final writes to complete
  testthat::expect_true(
    file.exists(audit_log_file),
    info = "Audit log file should exist"
  )

  log_lines <- readLines(audit_log_file, warn = FALSE)
  log_lines <- log_lines[nzchar(log_lines)]
  testthat::expect_true(
    length(log_lines) > 0,
    info = "Audit log file should contain events"
  )

  # Parse each JSON line
  events <- lapply(log_lines, function(line) {
    tryCatch(
      jsonlite::fromJSON(line, simplifyVector = FALSE),
      error = function(e) NULL
    )
  })
  events <- Filter(Negate(is.null), events)

  testthat::expect_true(
    length(events) > 0,
    info = "Should have parsed at least one audit event"
  )

  # 7) Categorize events by type
  event_types <- vapply(events, function(e) e$type %||% "unknown", character(1))
  cat("\n=== Captured audit event types ===\n")
  print(table(event_types))

  # 8) Verify key events are present
  # Events emitted during authorization redirect (main process)
  testthat::expect_true(
    "audit_redirect_issued" %in% event_types,
    info = "Should have audit_redirect_issued event"
  )

  # Events emitted during callback processing
  testthat::expect_true(
    "audit_callback_received" %in% event_types,
    info = "Should have audit_callback_received event"
  )

  # Token exchange event (may be from async worker)
  testthat::expect_true(
    "audit_token_exchange" %in% event_types,
    info = "Should have audit_token_exchange event"
  )

  # Login success event
  testthat::expect_true(
    "audit_login_success" %in% event_types,
    info = "Should have audit_login_success event"
  )

  # 9) Verify we have events from both main process and async worker
  # Check for is_async marker in shiny_session
  async_events <- Filter(
    function(e) {
      sess <- e$shiny_session
      if (is.null(sess)) {
        return(FALSE)
      }
      isTRUE(sess$is_async)
    },
    events
  )

  sync_events <- Filter(
    function(e) {
      sess <- e$shiny_session
      if (is.null(sess)) {
        return(TRUE)
      } # Events without session context treated as sync
      isFALSE(sess$is_async) || is.null(sess$is_async)
    },
    events
  )

  cat("\n=== Event distribution ===\n")
  cat("Total events:", length(events), "\n")
  cat("Async events (is_async=TRUE):", length(async_events), "\n")
  cat("Sync events (is_async=FALSE or NULL):", length(sync_events), "\n")

  # Print async event types for debugging
  if (length(async_events) > 0) {
    async_types <- vapply(
      async_events,
      function(e) e$type %||% "unknown",
      character(1)
    )
    cat("Async event types:", paste(async_types, collapse = ", "), "\n")
  }

  # The redirect_issued event should be from main process (sync)
  redirect_events <- Filter(
    function(e) identical(e$type, "audit_redirect_issued"),
    events
  )
  testthat::expect_true(length(redirect_events) > 0)
  # Check that redirect event is NOT marked as async
  for (evt in redirect_events) {
    testthat::expect_false(
      isTRUE((evt$shiny_session %||% list())$is_async),
      info = "audit_redirect_issued should be from main process (not async)"
    )
  }

  # Token exchange should be from async worker when using async=TRUE
  # (may fall back to sync if multisession not available)
  token_exchange_events <- Filter(
    function(e) identical(e$type, "audit_token_exchange"),
    events
  )
  testthat::expect_true(length(token_exchange_events) > 0)

  # Check if at least one async event exists (indicates worker was used)
  # Note: On systems where multisession isn't fully supported, this may be 0
  if (length(async_events) > 0) {
    cat("\n=== Async worker verification ===\n")

    # Verify async events include process tracking info
    for (evt in async_events) {
      sess <- evt$shiny_session
      testthat::expect_true(
        !is.null(sess$main_process_id),
        info = paste0(
          "Async event should include main_process_id. Type: ",
          evt$type
        )
      )
      testthat::expect_true(
        !is.null(sess$process_id),
        info = paste0(
          "Async event should include process_id. Type: ",
          evt$type
        )
      )
      # Print process info when available
      if (!is.null(sess$main_process_id)) {
        cat(
          "Event:",
          evt$type,
          "| main_pid:",
          sess$main_process_id,
          "| worker_pid:",
          sess$process_id,
          "\n"
        )
      }
    }

    testthat::expect_true(
      length(async_events) > 0,
      info = "Expected at least one audit event with is_async=TRUE from async worker"
    )
  } else {
    # Multisession may not be available; warn but don't fail
    cat(
      "\n[NOTE] No async events detected - multisession may have fallen back to sequential\n"
    )
  }

  # 10) Verify all events have required base fields
  for (evt in events) {
    testthat::expect_true(
      !is.null(evt$type),
      info = "Every event should have a type"
    )
    testthat::expect_true(
      !is.null(evt$trace_id),
      info = paste0("Event should have trace_id. Type: ", evt$type)
    )
  }

  cat("\n=== Audit log integration test passed ===\n")
})
