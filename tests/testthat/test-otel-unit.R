# Unit tests for otel helper functions: attribute processing, severity mapping,
# key translation, log emission, and error/span status helpers.

reset_test_otel_cache()
withr::defer(reset_test_otel_cache())

# ===========================================================================
# otel_scalar_attribute
# ===========================================================================

testthat::test_that("otel_scalar_attribute handles basic scalars", {
  testthat::expect_identical(
    shinyOAuth:::otel_scalar_attribute("hello"),
    "hello"
  )
  testthat::expect_identical(shinyOAuth:::otel_scalar_attribute(TRUE), TRUE)
  testthat::expect_identical(shinyOAuth:::otel_scalar_attribute(42L), 42L)
  testthat::expect_identical(shinyOAuth:::otel_scalar_attribute(3.14), 3.14)
})

testthat::test_that("otel_scalar_attribute returns NULL for empty/NA/null", {
  testthat::expect_null(shinyOAuth:::otel_scalar_attribute(NULL))
  testthat::expect_null(shinyOAuth:::otel_scalar_attribute(character(0)))
  testthat::expect_null(shinyOAuth:::otel_scalar_attribute(NA_character_))
  testthat::expect_null(shinyOAuth:::otel_scalar_attribute(NA))
  testthat::expect_null(shinyOAuth:::otel_scalar_attribute(""))
  testthat::expect_null(shinyOAuth:::otel_scalar_attribute(NA_integer_))
  testthat::expect_null(shinyOAuth:::otel_scalar_attribute(NA_real_))
})

testthat::test_that("otel_scalar_attribute handles lists and multi-element vectors", {
  testthat::expect_null(shinyOAuth:::otel_scalar_attribute(list(1, 2)))
  testthat::expect_identical(
    shinyOAuth:::otel_scalar_attribute(c("a", "b")),
    "a"
  )
})

testthat::test_that("otel_scalar_attribute handles POSIXt", {
  ts <- as.POSIXct("2025-01-01 12:00:00", tz = "UTC")
  result <- shinyOAuth:::otel_scalar_attribute(ts)
  testthat::expect_type(result, "character")
  testthat::expect_true(nzchar(result))
})

testthat::test_that("otel_scalar_attribute handles non-finite numeric", {
  testthat::expect_null(shinyOAuth:::otel_scalar_attribute(Inf))
  testthat::expect_null(shinyOAuth:::otel_scalar_attribute(-Inf))
  testthat::expect_null(shinyOAuth:::otel_scalar_attribute(NaN))
})

# ===========================================================================
# otel_event_severity
# ===========================================================================

testthat::test_that("otel_event_severity maps event types correctly", {
  # Info events
  testthat::expect_identical(
    shinyOAuth:::otel_event_severity("audit_login_success"),
    "info"
  )
  testthat::expect_identical(
    shinyOAuth:::otel_event_severity("audit_session_started"),
    "info"
  )

  # Warning events
  for (evt in c(
    "audit_callback_validation_failed",
    "audit_invalid_browser_token",
    "audit_browser_cookie_error",
    "audit_callback_iss_mismatch",
    "audit_callback_query_rejected",
    "audit_refresh_failed_but_kept_session",
    "audit_state_parse_failure",
    "audit_state_store_lookup_failed",
    "audit_state_store_removal_failed",
    "audit_error_state_consumption_failed"
  )) {
    testthat::expect_identical(
      shinyOAuth:::otel_event_severity(evt),
      "warn",
      info = paste("Expected 'warn' for", evt)
    )
  }

  # Error events
  for (evt in c(
    "error",
    "http_error",
    "transport_error",
    "audit_token_exchange_error",
    "audit_login_failed"
  )) {
    testthat::expect_identical(
      shinyOAuth:::otel_event_severity(evt),
      "error",
      info = paste("Expected 'error' for", evt)
    )
  }

  # Default/unknown
  testthat::expect_identical(
    shinyOAuth:::otel_event_severity("something_unknown"),
    "info"
  )

  # Generic fallback: types ending in _error or _failed get "warn"
  testthat::expect_identical(
    shinyOAuth:::otel_event_severity("audit_some_new_error"),
    "warn"
  )
  testthat::expect_identical(
    shinyOAuth:::otel_event_severity("audit_future_op_failed"),
    "warn"
  )

  # NULL/NA/empty
  testthat::expect_identical(shinyOAuth:::otel_event_severity(NULL), "info")
  testthat::expect_identical(shinyOAuth:::otel_event_severity(NA), "info")
  testthat::expect_identical(shinyOAuth:::otel_event_severity(""), "info")
})

testthat::test_that("otel_event_severity considers status for multi-outcome events", {
  testthat::expect_identical(
    shinyOAuth:::otel_event_severity("audit_userinfo", status = "ok"),
    "info"
  )
  testthat::expect_identical(
    shinyOAuth:::otel_event_severity(
      "audit_userinfo",
      status = "parse_error"
    ),
    "error"
  )
  testthat::expect_identical(
    shinyOAuth:::otel_event_severity(
      "audit_token_introspection",
      status = "introspection_unsupported"
    ),
    "info"
  )
  testthat::expect_identical(
    shinyOAuth:::otel_event_severity(
      "audit_token_introspection",
      status = "invalid_json"
    ),
    "warn"
  )
  testthat::expect_identical(
    shinyOAuth:::otel_event_severity(
      "audit_token_revocation",
      status = "http_503"
    ),
    "warn"
  )
  testthat::expect_identical(
    shinyOAuth:::otel_event_severity(
      "audit_session_cleared",
      reason = "refresh_failed_async"
    ),
    "error"
  )
  testthat::expect_identical(
    shinyOAuth:::otel_event_severity(
      "audit_session_cleared",
      reason = "token_expired"
    ),
    "info"
  )
})

# ===========================================================================
# otel_translate_event_key
# ===========================================================================

testthat::test_that("otel_translate_event_key maps known keys correctly", {
  expected <- list(
    provider = "oauth.provider.name",
    client_provider = "oauth.provider.name",
    issuer = "oauth.provider.issuer",
    client_issuer = "oauth.provider.issuer",
    client_id_digest = "oauth.client_id_digest",
    module_id = "shiny.module_id",
    phase = "oauth.phase",
    trace_id = "shinyoauth.trace_id",
    type = "event.type",
    status = "oauth.status"
  )
  for (nm in names(expected)) {
    testthat::expect_identical(
      shinyOAuth:::otel_translate_event_key(nm),
      expected[[nm]],
      info = paste("Key:", nm)
    )
  }
})

testthat::test_that("otel_translate_event_key passes through unknown keys", {
  testthat::expect_identical(
    shinyOAuth:::otel_translate_event_key("custom_field"),
    "custom_field"
  )
})

testthat::test_that("otel_translate_event_key returns NULL for invalid input", {
  testthat::expect_null(shinyOAuth:::otel_translate_event_key(NULL))
  testthat::expect_null(shinyOAuth:::otel_translate_event_key(NA))
  testthat::expect_null(shinyOAuth:::otel_translate_event_key(""))
})

# ===========================================================================
# otel_event_attributes
# ===========================================================================

testthat::test_that("otel_event_attributes filters sensitive fields", {
  event <- list(
    type = "audit_login_success",
    trace_id = "abc123",
    provider = "github",
    access_token = "secret_token",
    refresh_token = "secret_refresh",
    id_token = "secret_id",
    code = "secret_code",
    state = "secret_state",
    browser_token = "secret_bt",
    status = "ok"
  )

  attrs <- shinyOAuth:::otel_event_attributes(event)

  for (key in c(
    "access_token",
    "refresh_token",
    "id_token",
    "code",
    "state",
    "browser_token"
  )) {
    testthat::expect_false(
      key %in% names(attrs),
      info = paste0("Sensitive key '", key, "' should be filtered")
    )
  }

  testthat::expect_identical(attrs[["event.type"]], "audit_login_success")
  testthat::expect_identical(attrs[["oauth.provider.name"]], "github")
  testthat::expect_identical(attrs[["oauth.status"]], "ok")
})

testthat::test_that("otel_event_attributes skips timestamp and shiny_session", {
  event <- list(
    type = "audit_session_started",
    timestamp = Sys.time(),
    shiny_session = list(token = "tok")
  )

  attrs <- shinyOAuth:::otel_event_attributes(event)
  testthat::expect_false("timestamp" %in% names(attrs))
  testthat::expect_false("shiny_session" %in% names(attrs))
})

testthat::test_that("otel_event_attributes returns NULL for empty/null input", {
  testthat::expect_null(shinyOAuth:::otel_event_attributes(NULL))
  testthat::expect_null(shinyOAuth:::otel_event_attributes(list()))
})

# ===========================================================================
# otel_http_attributes
# ===========================================================================

testthat::test_that("otel_http_attributes extracts host from URL", {
  attrs <- shinyOAuth:::otel_http_attributes(
    method = "POST",
    url = "https://example.com/token"
  )
  testthat::expect_identical(attrs$http.request.method, "POST")
  testthat::expect_identical(attrs$server.address, "example.com")
})

testthat::test_that("otel_http_attributes extracts from httr2 response", {
  resp <- httr2::response(
    url = "https://provider.example.com/token",
    status = 200,
    headers = list("content-type" = "application/json"),
    body = charToRaw("{}")
  )

  attrs <- shinyOAuth:::otel_http_attributes(resp = resp)
  testthat::expect_identical(attrs$http.response.status_code, 200L)
  testthat::expect_identical(attrs$server.address, "provider.example.com")
})

# ===========================================================================
# otel_client_attributes
# ===========================================================================

testthat::test_that("otel_client_attributes includes expected fields", {
  cli <- make_test_client()
  attrs <- shinyOAuth:::otel_client_attributes(
    client = cli,
    module_id = "my_auth",
    async = TRUE,
    phase = "callback"
  )

  testthat::expect_identical(attrs$oauth.provider.name, "example")
  testthat::expect_identical(attrs$shiny.module_id, "my_auth")
  testthat::expect_identical(attrs$oauth.async, TRUE)
  testthat::expect_identical(attrs$oauth.phase, "callback")
  testthat::expect_true(is.character(attrs$oauth.client_id_digest))
  testthat::expect_true(nzchar(attrs$oauth.client_id_digest))
})

testthat::test_that("otel_client_attributes handles NULL client", {
  attrs <- shinyOAuth:::otel_client_attributes(
    client = NULL,
    module_id = "test",
    phase = "init"
  )

  testthat::expect_null(attrs$oauth.provider.name)
  testthat::expect_null(attrs$oauth.client_id_digest)
  testthat::expect_identical(attrs$shiny.module_id, "test")
  testthat::expect_identical(attrs$oauth.phase, "init")
})

# ===========================================================================
# otel_runtime_enabled
# ===========================================================================

testthat::test_that("otel_runtime_enabled reflects active tracing or logging", {
  withr::local_options(list(
    shinyOAuth.otel_tracing_enabled = TRUE,
    shinyOAuth.otel_logging_enabled = TRUE
  ))

  testthat::with_mocked_bindings(
    is_tracing_enabled = function(...) TRUE,
    is_logging_enabled = function(...) FALSE,
    .package = "otel",
    {
      testthat::expect_true(shinyOAuth:::otel_runtime_enabled())
    }
  )

  testthat::with_mocked_bindings(
    is_tracing_enabled = function(...) FALSE,
    is_logging_enabled = function(...) TRUE,
    .package = "otel",
    {
      testthat::expect_true(shinyOAuth:::otel_runtime_enabled())
    }
  )

  testthat::with_mocked_bindings(
    is_tracing_enabled = function(...) FALSE,
    is_logging_enabled = function(...) FALSE,
    .package = "otel",
    {
      testthat::expect_false(shinyOAuth:::otel_runtime_enabled())
    }
  )
})

testthat::test_that("otel_runtime_enabled respects shinyOAuth option gates", {
  withr::local_options(list(
    shinyOAuth.otel_tracing_enabled = FALSE,
    shinyOAuth.otel_logging_enabled = FALSE
  ))

  testthat::with_mocked_bindings(
    is_tracing_enabled = function(...) TRUE,
    is_logging_enabled = function(...) TRUE,
    .package = "otel",
    {
      testthat::expect_false(shinyOAuth:::otel_runtime_enabled())
    }
  )
})

# ===========================================================================
# warn_about_async_otel_workers
# ===========================================================================

testthat::test_that("warn_about_async_otel_workers warns only when otel active", {
  testthat::with_mocked_bindings(
    otel_runtime_enabled = function() TRUE,
    .package = "shinyOAuth",
    {
      testthat::expect_warning(
        shinyOAuth:::warn_about_async_otel_workers(),
        "configured in async workers"
      )
    }
  )

  testthat::with_mocked_bindings(
    otel_runtime_enabled = function() FALSE,
    .package = "shinyOAuth",
    {
      testthat::expect_no_warning(
        shinyOAuth:::warn_about_async_otel_workers()
      )
    }
  )
})

# ===========================================================================
# otel_emit_log
# ===========================================================================

testthat::test_that("otel_emit_log calls otel::log with correct severity", {
  withr::local_options(list(shinyOAuth.otel_logging_enabled = TRUE))
  log_calls <- list()

  testthat::with_mocked_bindings(
    log = function(msg, severity, ...) {
      log_calls[[length(log_calls) + 1L]] <<- list(
        msg = msg,
        severity = severity
      )
    },
    .package = "otel",
    {
      shinyOAuth:::otel_emit_log(list(
        type = "audit_login_success",
        trace_id = "abc123",
        provider = "github"
      ))
    }
  )

  testthat::expect_length(log_calls, 1L)
  testthat::expect_identical(log_calls[[1]]$severity, "info")
  testthat::expect_identical(log_calls[[1]]$msg, "audit_login_success")
})

testthat::test_that("otel_emit_log uses error severity for error events", {
  withr::local_options(list(shinyOAuth.otel_logging_enabled = TRUE))
  log_calls <- list()

  testthat::with_mocked_bindings(
    log = function(msg, severity, ...) {
      log_calls[[length(log_calls) + 1L]] <<- list(
        msg = msg,
        severity = severity
      )
    },
    .package = "otel",
    {
      shinyOAuth:::otel_emit_log(list(
        type = "audit_token_exchange_error",
        message = "Token exchange failed"
      ))
    }
  )

  testthat::expect_length(log_calls, 1L)
  testthat::expect_identical(log_calls[[1]]$severity, "error")
  testthat::expect_identical(log_calls[[1]]$msg, "Token exchange failed")
})

testthat::test_that("otel_emit_log uses status-aware severity for multi-outcome events", {
  withr::local_options(list(shinyOAuth.otel_logging_enabled = TRUE))
  log_calls <- list()

  testthat::with_mocked_bindings(
    log = function(msg, severity, ...) {
      log_calls[[length(log_calls) + 1L]] <<- list(
        msg = msg,
        severity = severity
      )
    },
    .package = "otel",
    {
      shinyOAuth:::otel_emit_log(list(
        type = "audit_userinfo",
        status = "parse_error"
      ))
      shinyOAuth:::otel_emit_log(list(
        type = "audit_token_introspection",
        status = "invalid_json"
      ))
      shinyOAuth:::otel_emit_log(list(
        type = "audit_session_cleared",
        reason = "refresh_failed_async"
      ))
    }
  )

  testthat::expect_length(log_calls, 3L)
  testthat::expect_identical(log_calls[[1]]$severity, "error")
  testthat::expect_identical(log_calls[[2]]$severity, "warn")
  testthat::expect_identical(log_calls[[3]]$severity, "error")
})

testthat::test_that("otel_emit_log does not call otel::log for empty events", {
  withr::local_options(list(shinyOAuth.otel_logging_enabled = TRUE))
  log_called <- FALSE
  testthat::with_mocked_bindings(
    log = function(...) log_called <<- TRUE,
    .package = "otel",
    {
      shinyOAuth:::otel_emit_log(NULL)
      shinyOAuth:::otel_emit_log(list())
    }
  )
  testthat::expect_false(log_called)
})

testthat::test_that("otel_emit_log does not include sensitive fields", {
  withr::local_options(list(shinyOAuth.otel_logging_enabled = TRUE))
  captured_attrs <- NULL

  testthat::with_mocked_bindings(
    log = function(msg, severity, attributes = NULL, ...) {
      captured_attrs <<- attributes
    },
    .package = "otel",
    {
      shinyOAuth:::otel_emit_log(list(
        type = "audit_login_success",
        provider = "github",
        access_token = "secret_at",
        refresh_token = "secret_rt",
        id_token = "secret_id",
        code = "secret_code",
        state = "secret_state",
        browser_token = "secret_bt"
      ))
    }
  )

  if (!is.null(captured_attrs)) {
    attr_names <- names(captured_attrs)
    for (key in c(
      "access_token",
      "refresh_token",
      "id_token",
      "code",
      "state",
      "browser_token"
    )) {
      testthat::expect_false(
        key %in% attr_names,
        info = paste0(
          "Sensitive key '",
          key,
          "' in otel log attributes"
        )
      )
    }
  }
})

# ===========================================================================
# otel_note_error
# ===========================================================================

testthat::test_that("otel_note_error sets error status and adds exception event", {
  withr::local_options(list(shinyOAuth.otel_tracing_enabled = TRUE))

  add_event_calls <- list()
  set_status_calls <- list()

  mock_span <- list(
    set_attribute = function(nm, val) {},
    add_event = function(name, attributes = NULL) {
      add_event_calls[[length(add_event_calls) + 1L]] <<- list(
        name = name,
        attrs = attributes
      )
    },
    set_status = function(status, description = NULL) {
      set_status_calls[[length(set_status_calls) + 1L]] <<- list(
        status = status,
        description = description
      )
    }
  )

  err <- simpleError("something went wrong")
  shinyOAuth:::otel_note_error(err, span = mock_span)

  testthat::expect_true(length(add_event_calls) >= 1L)
  testthat::expect_identical(add_event_calls[[1]]$name, "exception")

  testthat::expect_true(length(set_status_calls) >= 1L)
  testthat::expect_identical(set_status_calls[[1]]$status, "error")
  testthat::expect_identical(
    set_status_calls[[1]]$description,
    "something went wrong"
  )
})

# ===========================================================================
# otel_end_async_parent
# ===========================================================================

testthat::test_that("otel_end_async_parent marks ok or error correctly", {
  withr::local_options(list(shinyOAuth.otel_tracing_enabled = TRUE))

  mock_span <- list(
    set_status = function(...) {},
    add_event = function(...) {},
    set_attribute = function(...) {}
  )

  # ok path
  ok_calls <- list()
  err_calls <- list()

  testthat::with_mocked_bindings(
    otel_mark_span_ok = function(span) {
      ok_calls[[length(ok_calls) + 1L]] <<- TRUE
    },
    otel_note_error = function(error, span, ...) {
      err_calls[[length(err_calls) + 1L]] <<- conditionMessage(error)
    },
    .package = "shinyOAuth",
    {
      shinyOAuth:::otel_end_async_parent(
        list(span = mock_span),
        status = "ok"
      )
    }
  )
  testthat::expect_length(ok_calls, 1L)
  testthat::expect_length(err_calls, 0L)

  # error path
  ok_calls <- list()
  err_calls <- list()
  testthat::with_mocked_bindings(
    otel_mark_span_ok = function(span) {
      ok_calls[[length(ok_calls) + 1L]] <<- TRUE
    },
    otel_note_error = function(error, span, ...) {
      err_calls[[length(err_calls) + 1L]] <<- conditionMessage(error)
    },
    .package = "shinyOAuth",
    {
      shinyOAuth:::otel_end_async_parent(
        list(span = mock_span),
        status = "error",
        error = simpleError("async failure")
      )
    }
  )
  testthat::expect_length(ok_calls, 0L)
  testthat::expect_length(err_calls, 1L)
  testthat::expect_identical(err_calls[[1]], "async failure")
})

# ===========================================================================
# emit_trace_event bridge
# ===========================================================================

testthat::test_that("emit_trace_event calls otel_emit_log", {
  withr::local_options(list(shinyOAuth.otel_logging_enabled = TRUE))
  log_called <- FALSE

  testthat::with_mocked_bindings(
    otel_emit_log = function(event) log_called <<- TRUE,
    augment_with_shiny_context = function(event) event,
    .package = "shinyOAuth",
    {
      shinyOAuth:::emit_trace_event(list(
        type = "audit_test",
        trace_id = "t1"
      ))
    }
  )

  testthat::expect_true(log_called)
})

testthat::test_that("emit_trace_event warns on otel_emit_log failure", {
  withr::local_options(list(shinyOAuth.otel_logging_enabled = TRUE))

  testthat::with_mocked_bindings(
    otel_emit_log = function(event) stop("otel log error"),
    augment_with_shiny_context = function(event) event,
    .package = "shinyOAuth",
    {
      testthat::expect_warning(
        shinyOAuth:::emit_trace_event(list(type = "test")),
        "otel telemetry error"
      )
    }
  )
})

testthat::test_that("otel_telemetry_warning uses rlang::warn", {
  testthat::expect_warning(
    shinyOAuth:::otel_telemetry_warning(
      "test context",
      simpleError("boom")
    ),
    "OpenTelemetry test context disabled"
  )
})

# ===========================================================================
# with_otel_span error paths (mock-based)
# ===========================================================================

testthat::test_that("with_otel_span marks span ok on success", {
  withr::local_options(list(shinyOAuth.otel_tracing_enabled = TRUE))
  marked_ok <- FALSE
  noted_error <- FALSE

  testthat::with_mocked_bindings(
    otel_mark_span_ok = function(span = NULL) marked_ok <<- TRUE,
    otel_note_error = function(error, span = NULL, attributes = list()) {
      noted_error <<- TRUE
    },
    .package = "shinyOAuth",
    {
      result <- shinyOAuth:::with_otel_span("test.span", 42)
    }
  )

  testthat::expect_equal(result, 42)
  testthat::expect_true(marked_ok)
  testthat::expect_false(noted_error)
})

testthat::test_that("with_otel_span forwards an explicit parent option", {
  withr::local_options(list(shinyOAuth.otel_tracing_enabled = TRUE))
  captured_parent <- "unset"

  testthat::with_mocked_bindings(
    start_local_active_span = function(
      name,
      attributes = NULL,
      options = NULL,
      activation_scope = parent.frame(),
      ...
    ) {
      captured_parent <<- options$parent
      invisible(NULL)
    },
    .package = "otel",
    {
      result <- shinyOAuth:::with_otel_span(
        "test.parent",
        42,
        mark_ok = FALSE,
        parent = NA
      )
      testthat::expect_identical(result, 42)
    }
  )

  testthat::expect_true(is.na(captured_parent))
})

testthat::test_that("with_otel_span notes error and re-throws on failure", {
  withr::local_options(list(shinyOAuth.otel_tracing_enabled = TRUE))
  marked_ok <- FALSE
  noted_error <- FALSE

  testthat::with_mocked_bindings(
    otel_mark_span_ok = function(span = NULL) marked_ok <<- TRUE,
    otel_note_error = function(error, span = NULL, attributes = list()) {
      noted_error <<- TRUE
      testthat::expect_true(inherits(error, "error"))
      testthat::expect_match(conditionMessage(error), "test failure")
    },
    .package = "shinyOAuth",
    {
      testthat::expect_error(
        shinyOAuth:::with_otel_span("test.span", stop("test failure")),
        "test failure"
      )
    }
  )

  testthat::expect_false(marked_ok)
  testthat::expect_true(noted_error)
})
