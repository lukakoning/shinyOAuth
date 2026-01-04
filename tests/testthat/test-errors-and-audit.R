local_with_options <- function(opts, code) {
  old <- options(opts)
  on.exit(options(old), add = TRUE)
  force(code)
}

test_that("sanitize_body truncates and strips newlines", {
  s <- "line1\nline2\rline3"
  out <- shinyOAuth:::sanitize_body(s, max_chars = 10)
  expect_false(grepl("\n|\r", out))
  expect_true(endsWith(out, "[truncated]") || nchar(out) <= 10)
})

test_that("string_digest returns hex digest or NA for bad inputs", {
  d <- shinyOAuth:::string_digest("hello")
  expect_match(d, "^[0-9a-f]+$")
  expect_true(nchar(d) >= 10)
  expect_true(is.na(shinyOAuth:::string_digest(NA_character_)))
  # simulate openssl error by passing a raw connection (sha256 expects raw)
  expect_true(is.na(shinyOAuth:::string_digest(structure(
    list(),
    class = "not-char"
  ))))
})

test_that("string_digest keying is controlled by shinyOAuth.audit_digest_key", {
  hex <- function(raw) paste0(sprintf("%02x", as.integer(raw)), collapse = "")

  # FALSE disables keying (legacy deterministic SHA-256) and should not warn
  local_with_options(list(shinyOAuth.audit_digest_key = FALSE), {
    expect_warning(d1 <- shinyOAuth:::string_digest("hello"), NA)
    expect_identical(d1, hex(openssl::sha256(charToRaw("hello"))))
  })

  # A fixed key yields deterministic HMAC digests
  local_with_options(list(shinyOAuth.audit_digest_key = "test-key"), {
    d2 <- shinyOAuth:::string_digest("hello")
    d3 <- shinyOAuth:::string_digest("hello")
    expect_identical(d2, d3)
    expect_identical(
      d2,
      hex(openssl::sha256(charToRaw("hello"), key = charToRaw("test-key")))
    )
  })

  # Default behavior (option unset) should be keyed (HMAC), i.e. not equal to
  # the unkeyed SHA-256 digest.
  local_with_options(list(shinyOAuth.audit_digest_key = NULL), {
    d_default <- shinyOAuth:::string_digest("hello")
    expect_false(identical(d_default, hex(openssl::sha256(charToRaw("hello")))))
  })
})

test_that("err_abort/err_pkce attach classes and trace ids", {
  expect_error(shinyOAuth:::err_pkce("boom"), class = "shinyOAuth_pkce_error")
  e <- tryCatch(shinyOAuth:::err_pkce("boom2"), error = identity)
  expect_true(is.character(e$trace_id) && nzchar(e$trace_id))
})

test_that("err_http includes status and optional body when exposure enabled", {
  # Call err_http with NULL resp and ensure it still works
  expect_error(
    shinyOAuth:::err_http("msg", resp = NULL),
    class = "shinyOAuth_http_error"
  )

  # Now enable body exposure; since resp is NULL, body won't be shown but path is covered
  local_with_options(list(shinyOAuth.expose_error_body = TRUE), {
    expect_error(
      shinyOAuth:::err_http("msg2", resp = NULL),
      class = "shinyOAuth_http_error"
    )
  })
})

test_that("audit_event emits audit_ events via trace hook", {
  events <- list()
  local_with_options(
    list(shinyOAuth.trace_hook = function(ev) {
      events[[length(events) + 1]] <<- ev
    }),
    {
      id <- shinyOAuth:::audit_event(
        "token_exchange",
        context = list(foo = "bar")
      )
      expect_true(is.character(id) && nzchar(id))
    }
  )
  # Check at least one event captured
  expect_true(length(events) >= 1)
  expect_identical(events[[1]]$type, "audit_token_exchange")
  expect_identical(events[[1]]$foo, "bar")
})

test_that("log_condition prints when enabled but remains silent otherwise", {
  # By default should be silent
  e <- tryCatch(shinyOAuth:::err_pkce("x"), error = identity)
  expect_invisible(shinyOAuth:::log_condition(e))

  # When enabled, still should not error
  local_with_options(
    list(shinyOAuth.print_errors = TRUE, shinyOAuth.print_traceback = FALSE),
    {
      expect_invisible(shinyOAuth:::log_condition(e))
    }
  )
})

test_that("normalize_bullets preserves named types and defaults unnamed", {
  b <- shinyOAuth:::normalize_bullets(c("i" = "a", "b"))
  expect_identical(unname(b), c("a", "b"))
  expect_identical(names(b), c("i", "!"))

  # Lists are flattened and names preserved
  b2 <- shinyOAuth:::normalize_bullets(list("i" = "a", "b"))
  expect_identical(unname(b2), c("a", "b"))
  expect_identical(names(b2), c("i", "!"))

  # NA names also default to '!'
  v <- c("a", "b")
  names(v) <- c(NA_character_, "i")
  b3 <- shinyOAuth:::normalize_bullets(v)
  expect_identical(names(b3), c("!", "i"))
})

# HTTP summary sanitization tests -----------------------------------------

test_that("redact_query_string redacts sensitive OAuth params", {
  qs <- "code=abc123&state=xyz789&redirect_uri=http://example.com"
  result <- shinyOAuth:::redact_query_string(qs)

  # Check redacted params

  expect_match(result, "code=%5BREDACTED%5D")
  expect_match(result, "state=%5BREDACTED%5D")
  # Non-sensitive params should remain
  expect_match(result, "redirect_uri=")
  expect_no_match(result, "abc123")
  expect_no_match(result, "xyz789")
})

test_that("redact_query_string handles all sensitive param types", {
  qs <- paste(
    "access_token=tok1",
    "refresh_token=tok2",
    "id_token=tok3",
    "token=tok4",
    "session_state=sess1",
    "code_verifier=cv1",
    "nonce=n1",
    "safe_param=keep_me",
    sep = "&"
  )
  result <- shinyOAuth:::redact_query_string(qs)

  # All sensitive params should be redacted
  expect_no_match(result, "tok1")
  expect_no_match(result, "tok2")
  expect_no_match(result, "tok3")
  expect_no_match(result, "tok4")
  expect_no_match(result, "sess1")
  expect_no_match(result, "cv1")
  expect_no_match(result, "n1")
  # Safe param should remain
  expect_match(result, "keep_me")
})

test_that("redact_query_string handles empty/null input gracefully", {
  expect_null(shinyOAuth:::redact_query_string(NULL))
  expect_equal(shinyOAuth:::redact_query_string(""), "")
})

test_that("redact_query_string handles repeated keys", {
  qs <- "code=a&code=b&state=x&state=y&safe=1&safe=2"

  expect_no_error({
    result <- shinyOAuth:::redact_query_string(qs)
  })

  result <- shinyOAuth:::redact_query_string(qs)

  # Should not leak sensitive values
  expect_false(grepl("code=a", result, fixed = TRUE))
  expect_false(grepl("code=b", result, fixed = TRUE))
  expect_false(grepl("state=x", result, fixed = TRUE))
  expect_false(grepl("state=y", result, fixed = TRUE))

  # Should redact each occurrence
  code_hits <- gregexpr("code=%5BREDACTED%5D", result, fixed = TRUE)[[1]]
  state_hits <- gregexpr("state=%5BREDACTED%5D", result, fixed = TRUE)[[1]]
  expect_equal(if (code_hits[[1]] == -1) 0 else length(code_hits), 2)
  expect_equal(if (state_hits[[1]] == -1) 0 else length(state_hits), 2)

  # Non-sensitive repeated params should remain
  expect_match(result, "safe=1")
  expect_match(result, "safe=2")
})

test_that("redact_headers removes cookie and authorization", {
  hdrs <- list(
    cookie = "session=abc123",
    authorization = "Bearer secret",
    user_agent = "TestClient/1.0",
    accept = "application/json"
  )
  result <- shinyOAuth:::redact_headers(hdrs)

  # Sensitive headers should be removed
  expect_null(result$cookie)
  expect_null(result$authorization)
  # Safe headers should remain
  expect_equal(result$user_agent, "TestClient/1.0")
  expect_equal(result$accept, "application/json")
})

test_that("redact_headers redacts x_ prefixed headers", {
  hdrs <- list(
    x_forwarded_for = "192.168.1.1",
    x_real_ip = "10.0.0.1",
    x_request_id = "req123",
    user_agent = "TestClient/1.0"
  )
  result <- shinyOAuth:::redact_headers(hdrs)

  # x_ headers should be redacted (not removed)
  expect_equal(result$x_forwarded_for, "[REDACTED]")
  expect_equal(result$x_real_ip, "[REDACTED]")
  expect_equal(result$x_request_id, "[REDACTED]")
  # Safe headers should remain unchanged
  expect_equal(result$user_agent, "TestClient/1.0")
})

test_that("redact_headers handles empty/null input gracefully", {
  expect_null(shinyOAuth:::redact_headers(NULL))
  expect_equal(shinyOAuth:::redact_headers(list()), list())
})

test_that("sanitize_http_summary sanitizes both query_string and headers", {
  summary <- list(
    method = "GET",
    path = "/callback",
    query_string = "code=secret&state=abc",
    host = "example.com",
    headers = list(
      cookie = "session=xyz",
      user_agent = "Test/1.0",
      x_forwarded_for = "1.2.3.4"
    )
  )
  result <- shinyOAuth:::sanitize_http_summary(summary)

  # Query string should be sanitized
  expect_no_match(result$query_string, "secret")
  expect_match(result$query_string, "REDACTED")
  # Headers should be sanitized
  expect_null(result$headers$cookie)
  expect_equal(result$headers$user_agent, "Test/1.0")
  expect_equal(result$headers$x_forwarded_for, "[REDACTED]")
  # Other fields should remain
  expect_equal(result$method, "GET")
  expect_equal(result$path, "/callback")
  expect_equal(result$host, "example.com")
})

test_that("sanitize_http_summary handles NULL input", {
  expect_null(shinyOAuth:::sanitize_http_summary(NULL))
})

test_that("build_http_summary returns sanitized output", {
  # Create a mock request object
  req <- list(
    REQUEST_METHOD = "GET",
    PATH_INFO = "/callback",
    QUERY_STRING = "code=authcode123&state=mystate",
    HTTP_HOST = "example.com",
    HTTP_COOKIE = "session=secret123",
    HTTP_AUTHORIZATION = "Bearer token123",
    HTTP_PROXY_AUTHORIZATION = "Basic proxysecret123",
    HTTP_WWW_AUTHENTICATE = "Bearer realm=example",
    HTTP_USER_AGENT = "TestClient/1.0",
    HTTP_X_FORWARDED_FOR = "192.168.1.1"
  )
  result <- shinyOAuth:::build_http_summary(req)

  # Sensitive values should be redacted
  expect_no_match(result$query_string, "authcode123")
  expect_no_match(result$query_string, "mystate")
  expect_null(result$headers$cookie)
  expect_null(result$headers$authorization)
  expect_null(result$headers$proxy_authorization)
  expect_null(result$headers$www_authenticate)
  expect_equal(result$headers$x_forwarded_for, "[REDACTED]")
  # Safe values should remain
  expect_equal(result$headers$user_agent, "TestClient/1.0")
  expect_equal(result$method, "GET")
  expect_equal(result$path, "/callback")
})

test_that("build_http_summary respects shinyOAuth.audit_redact_http option", {
  req <- list(
    REQUEST_METHOD = "GET",
    PATH_INFO = "/callback",
    QUERY_STRING = "code=authcode123&state=mystate",
    HTTP_HOST = "example.com",
    HTTP_COOKIE = "session=secret123",
    HTTP_AUTHORIZATION = "Bearer token123",
    HTTP_PROXY_AUTHORIZATION = "Basic proxysecret123",
    HTTP_WWW_AUTHENTICATE = "Bearer realm=example",
    HTTP_USER_AGENT = "TestClient/1.0",
    HTTP_X_FORWARDED_FOR = "192.168.1.1"
  )

  # When option is FALSE, raw values should be returned
  withr::with_options(list(shinyOAuth.audit_redact_http = FALSE), {
    result <- shinyOAuth:::build_http_summary(req)

    # Sensitive values should NOT be redacted
    expect_match(result$query_string, "authcode123")
    expect_match(result$query_string, "mystate")
    expect_equal(result$headers$cookie, "session=secret123")
    expect_equal(result$headers$authorization, "Bearer token123")
    expect_equal(result$headers$proxy_authorization, "Basic proxysecret123")
    expect_equal(result$headers$www_authenticate, "Bearer realm=example")
    expect_equal(result$headers$x_forwarded_for, "192.168.1.1")
    expect_equal(result$headers$user_agent, "TestClient/1.0")
  })

  # When option is TRUE (explicit), should still redact

  withr::with_options(list(shinyOAuth.audit_redact_http = TRUE), {
    result <- shinyOAuth:::build_http_summary(req)
    expect_no_match(result$query_string, "authcode123")
    expect_null(result$headers$cookie)
  })
})


# is_async tracking in audit events ---------------------------------------

test_that("capture_shiny_session_context sets is_async = TRUE", {
  # When capturing context for async workers, is_async should be TRUE
  # because the context will be used in an async worker
  shiny::testServer(
    app = function(input, output, session) {
      ctx <- shinyOAuth:::capture_shiny_session_context()
      # Context should be captured (or NULL if no session info)
      if (!is.null(ctx)) {
        expect_true(isTRUE(ctx$is_async))
      }
    },
    expr = {}
  )
})

test_that("augment_with_shiny_context sets is_async = FALSE for main thread events", {
  # Events augmented on the main thread should have is_async = FALSE
  shiny::testServer(
    app = function(input, output, session) {
      event <- list(type = "test_event", trace_id = "abc123")
      augmented <- shinyOAuth:::augment_with_shiny_context(event)
      # Should have shiny_session with is_async = FALSE
      if (!is.null(augmented$shiny_session)) {
        expect_false(isTRUE(augmented$shiny_session$is_async))
      }
    },
    expr = {}
  )
})

test_that("augment_with_shiny_context preserves pre-captured is_async = TRUE", {
  # When shiny_session is already set (from capture_shiny_session_context),

  # augment should not override it
  shiny::testServer(
    app = function(input, output, session) {
      # Simulate pre-captured context from async worker
      pre_captured <- list(
        token = "test-token",
        http = NULL,
        is_async = TRUE
      )
      event <- list(
        type = "test_event",
        trace_id = "abc123",
        shiny_session = pre_captured
      )
      augmented <- shinyOAuth:::augment_with_shiny_context(event)
      # Should preserve the pre-captured context with is_async = TRUE
      expect_true(isTRUE(augmented$shiny_session$is_async))
      expect_equal(augmented$shiny_session$token, "test-token")
    },
    expr = {}
  )
})

test_that("audit_event includes is_async in shiny_session when captured", {
  events <- list()
  old <- options(shinyOAuth.trace_hook = function(ev) {
    events[[length(events) + 1]] <<- ev
  })
  on.exit(options(old), add = TRUE)

  shiny::testServer(
    app = function(input, output, session) {
      # Emit an event with pre-captured session (simulating async worker)
      captured <- shinyOAuth:::capture_shiny_session_context()
      shinyOAuth:::audit_event(
        "test_async",
        context = list(foo = "bar"),
        shiny_session = captured
      )

      # Emit an event without pre-captured session (main thread)
      shinyOAuth:::audit_event(
        "test_sync",
        context = list(baz = "qux")
      )
    },
    expr = {}
  )

  # Find our test events
  async_event <- Filter(function(e) e$type == "audit_test_async", events)
  sync_event <- Filter(function(e) e$type == "audit_test_sync", events)

  expect_length(async_event, 1)
  expect_length(sync_event, 1)

  # Async event should have is_async = TRUE (from pre-captured context)
  if (!is.null(async_event[[1]]$shiny_session)) {
    expect_true(isTRUE(async_event[[1]]$shiny_session$is_async))
  }

  # Sync event should have is_async = FALSE (from augment on main thread)
  if (!is.null(sync_event[[1]]$shiny_session)) {
    expect_false(isTRUE(sync_event[[1]]$shiny_session$is_async))
  }
})


# with_async_session_context for errors -----------------------------------

test_that("with_async_session_context makes errors include async session info", {
  events <- list()
  old <- options(shinyOAuth.trace_hook = function(ev) {
    events[[length(events) + 1]] <<- ev
  })
  on.exit(options(old), add = TRUE)

  # Create a mock captured session context (simulating async worker)
  captured_ctx <- list(
    token = "mock-session-token",
    http = NULL,
    is_async = TRUE
  )

  # Error thrown inside with_async_session_context should pick up the context
  tryCatch(
    shinyOAuth:::with_async_session_context(captured_ctx, {
      shinyOAuth:::err_token("Test error in async context")
    }),
    error = function(e) NULL
  )

  # Find the error trace event
  error_events <- Filter(function(e) e$type == "error", events)
  expect_length(error_events, 1)

  # Error should have the async session context
  expect_equal(error_events[[1]]$shiny_session$token, "mock-session-token")
  expect_true(isTRUE(error_events[[1]]$shiny_session$is_async))
})

test_that("errors on main thread have is_async = FALSE", {
  events <- list()
  old <- options(shinyOAuth.trace_hook = function(ev) {
    events[[length(events) + 1]] <<- ev
  })
  on.exit(options(old), add = TRUE)

  shiny::testServer(
    app = function(input, output, session) {
      # Error thrown on main thread (inside reactive domain)
      tryCatch(
        shinyOAuth:::err_token("Test error on main thread"),
        error = function(e) NULL
      )
    },
    expr = {}
  )

  # Find the error trace event
  error_events <- Filter(function(e) e$type == "error", events)
  expect_length(error_events, 1)

  # Error should have is_async = FALSE (main thread)
  if (!is.null(error_events[[1]]$shiny_session)) {
    expect_false(isTRUE(error_events[[1]]$shiny_session$is_async))
  }
})
