# Tests for internal telemetry helper functions

# --- otel_scalar_attribute ---------------------------------------------------

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
  # Multi-element vector: takes first element
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

# --- otel_event_severity -----------------------------------------------------

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
  testthat::expect_identical(
    shinyOAuth:::otel_event_severity("audit_callback_validation_failed"),
    "warn"
  )
  testthat::expect_identical(
    shinyOAuth:::otel_event_severity("audit_invalid_browser_token"),
    "warn"
  )
  testthat::expect_identical(
    shinyOAuth:::otel_event_severity("audit_browser_cookie_error"),
    "warn"
  )
  testthat::expect_identical(
    shinyOAuth:::otel_event_severity("audit_callback_iss_mismatch"),
    "warn"
  )
  testthat::expect_identical(
    shinyOAuth:::otel_event_severity("audit_callback_query_rejected"),
    "warn"
  )
  testthat::expect_identical(
    shinyOAuth:::otel_event_severity("audit_refresh_failed_but_kept_session"),
    "warn"
  )
  testthat::expect_identical(
    shinyOAuth:::otel_event_severity("audit_state_parse_failure"),
    "warn"
  )
  testthat::expect_identical(
    shinyOAuth:::otel_event_severity("audit_state_store_lookup_failed"),
    "warn"
  )
  testthat::expect_identical(
    shinyOAuth:::otel_event_severity("audit_state_store_removal_failed"),
    "warn"
  )
  testthat::expect_identical(
    shinyOAuth:::otel_event_severity("audit_error_state_consumption_failed"),
    "warn"
  )

  # Error events
  testthat::expect_identical(
    shinyOAuth:::otel_event_severity("error"),
    "error"
  )
  testthat::expect_identical(
    shinyOAuth:::otel_event_severity("http_error"),
    "error"
  )
  testthat::expect_identical(
    shinyOAuth:::otel_event_severity("transport_error"),
    "error"
  )
  testthat::expect_identical(
    shinyOAuth:::otel_event_severity("audit_token_exchange_error"),
    "error"
  )
  testthat::expect_identical(
    shinyOAuth:::otel_event_severity("audit_login_failed"),
    "error"
  )

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
    shinyOAuth:::otel_event_severity("audit_userinfo", status = "parse_error"),
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

# --- otel_translate_event_key ------------------------------------------------

testthat::test_that("otel_translate_event_key maps known keys correctly", {
  testthat::expect_identical(
    shinyOAuth:::otel_translate_event_key("provider"),
    "oauth.provider.name"
  )
  testthat::expect_identical(
    shinyOAuth:::otel_translate_event_key("client_provider"),
    "oauth.provider.name"
  )
  testthat::expect_identical(
    shinyOAuth:::otel_translate_event_key("issuer"),
    "oauth.provider.issuer"
  )
  testthat::expect_identical(
    shinyOAuth:::otel_translate_event_key("client_issuer"),
    "oauth.provider.issuer"
  )
  testthat::expect_identical(
    shinyOAuth:::otel_translate_event_key("client_id_digest"),
    "oauth.client_id_digest"
  )
  testthat::expect_identical(
    shinyOAuth:::otel_translate_event_key("module_id"),
    "shiny.module_id"
  )
  testthat::expect_identical(
    shinyOAuth:::otel_translate_event_key("phase"),
    "oauth.phase"
  )
  testthat::expect_identical(
    shinyOAuth:::otel_translate_event_key("trace_id"),
    "shinyoauth.trace_id"
  )
  testthat::expect_identical(
    shinyOAuth:::otel_translate_event_key("type"),
    "event.type"
  )
  testthat::expect_identical(
    shinyOAuth:::otel_translate_event_key("status"),
    "oauth.status"
  )
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

# --- otel_event_attributes ---------------------------------------------------

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

  # Sensitive fields must NOT be present
  sensitive_otel_keys <- c(
    "access_token",
    "refresh_token",
    "id_token",
    "code",
    "state",
    "browser_token"
  )
  for (key in sensitive_otel_keys) {
    testthat::expect_false(
      key %in% names(attrs),
      info = paste0("Sensitive key '", key, "' should be filtered")
    )
  }

  # Non-sensitive fields should be present (translated)
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

# --- otel_http_attributes ----------------------------------------------------

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

# --- otel_client_attributes --------------------------------------------------

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

# --- otel_runtime_enabled / async warning ------------------------------------

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

testthat::test_that("warn_about_async_otel_workers warns only when otel is active", {
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
