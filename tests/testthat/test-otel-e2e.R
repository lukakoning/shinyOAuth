# End-to-end OpenTelemetry tests using otelsdk to capture real spans and logs.
# These tests run actual shinyOAuth operations with mocked HTTP backends and
# verify that OTel signals are emitted correctly through the full stack.

reset_test_otel_cache()
withr::defer(reset_test_otel_cache())

otel_e2e <- function(desc, code) {
  testthat::test_that(desc, {
    testthat::skip_if_not_installed("otelsdk")
    withr::local_options(list(
      shinyOAuth.otel_tracing_enabled = TRUE,
      shinyOAuth.otel_logging_enabled = TRUE,
      shinyOAuth.skip_browser_token = TRUE,
      shinyOAuth.audit_hook = NULL,
      shinyOAuth.trace_hook = NULL
    ))
    force(code)
  })
}

# ---------------------------------------------------------------------------
# Span basics
# ---------------------------------------------------------------------------

otel_e2e("with_otel_span creates span with ok status on success", {
  r <- otelsdk::with_otel_record({
    shinyOAuth:::with_otel_span("shinyOAuth.test.ok", 42)
  })
  testthat::expect_identical(r$value, 42)
  testthat::expect_true("shinyOAuth.test.ok" %in% names(r$traces))
  testthat::expect_identical(r$traces[["shinyOAuth.test.ok"]]$status, "ok")
})

otel_e2e("with_otel_span marks span as error on failure", {
  r <- otelsdk::with_otel_record({
    tryCatch(
      shinyOAuth:::with_otel_span("shinyOAuth.test.err", stop("boom")),
      error = function(e) NULL
    )
  })
  s <- r$traces[["shinyOAuth.test.err"]]
  testthat::expect_identical(s$status, "error")
  testthat::expect_true(length(s$events) > 0)
})

otel_e2e("with_otel_span records user-supplied attributes", {
  r <- otelsdk::with_otel_record({
    shinyOAuth:::with_otel_span(
      "shinyOAuth.test.attrs",
      42,
      attributes = list(
        oauth.provider.name = "github",
        oauth.phase = "test"
      )
    )
  })
  s <- r$traces[["shinyOAuth.test.attrs"]]
  testthat::expect_identical(s$attributes[["oauth.provider.name"]], "github")
  testthat::expect_identical(s$attributes[["oauth.phase"]], "test")
})

otel_e2e("nested spans have correct parent-child relationship", {
  r <- otelsdk::with_otel_record({
    shinyOAuth:::with_otel_span("shinyOAuth.test.parent", {
      shinyOAuth:::with_otel_span("shinyOAuth.test.child", 42)
    })
  })
  parent <- r$traces[["shinyOAuth.test.parent"]]
  child <- r$traces[["shinyOAuth.test.child"]]
  testthat::expect_false(is.null(parent))
  testthat::expect_false(is.null(child))
  testthat::expect_identical(child$parent, parent$span_id)
  testthat::expect_identical(child$trace_id, parent$trace_id)
})

# ---------------------------------------------------------------------------
# Async parent / worker span propagation
# ---------------------------------------------------------------------------

otel_e2e("async parent span propagates context via headers", {
  r <- otelsdk::with_otel_record({
    parent <- shinyOAuth:::otel_start_async_parent(
      "shinyOAuth.test.async.parent",
      attributes = list(oauth.phase = "test")
    )
    testthat::expect_false(is.null(parent$span))
    testthat::expect_true("traceparent" %in% names(parent$headers))

    worker <- shinyOAuth:::otel_restore_parent_in_worker(
      parent$headers,
      "shinyOAuth.test.async.worker",
      attributes = list(oauth.phase = "test.worker")
    )
    shinyOAuth:::otel_end_async_parent(list(span = worker), status = "ok")
    shinyOAuth:::otel_end_async_parent(parent, status = "ok")
  })
  parent <- r$traces[["shinyOAuth.test.async.parent"]]
  worker <- r$traces[["shinyOAuth.test.async.worker"]]
  testthat::expect_identical(worker$trace_id, parent$trace_id)
  testthat::expect_identical(worker$parent, parent$span_id)
})

otel_e2e("async parent span honors an explicit parent context", {
  r <- otelsdk::with_otel_record({
    login_headers <- shinyOAuth:::with_otel_span(
      "shinyOAuth.test.async.login",
      {
        shinyOAuth:::otel_capture_context()
      },
      parent = NA
    )

    shinyOAuth:::with_otel_span("reactive_update.async", {
      parent <- shinyOAuth:::otel_start_async_parent(
        "shinyOAuth.test.async.explicit",
        parent = shinyOAuth:::otel_span_context_from_headers(login_headers)
      )
      shinyOAuth:::otel_end_async_parent(parent, status = "ok")
    })
  })

  login <- r$traces[["shinyOAuth.test.async.login"]]
  outer <- r$traces[["reactive_update.async"]]
  parent <- r$traces[["shinyOAuth.test.async.explicit"]]

  testthat::expect_identical(parent$trace_id, login$trace_id)
  testthat::expect_identical(parent$parent, login$span_id)
  testthat::expect_false(identical(parent$parent, outer$span_id))
})

# ---------------------------------------------------------------------------
# prepare_call() — full span emission
# ---------------------------------------------------------------------------

otel_e2e("prepare_call emits login.request span with attributes", {
  r <- otelsdk::with_otel_record({
    cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
    shinyOAuth::prepare_call(cli, browser_token = valid_browser_token())
  })
  s <- r$traces[["shinyOAuth.login.request"]]
  testthat::expect_false(is.null(s))
  testthat::expect_identical(s$status, "ok")
  testthat::expect_identical(s$attributes[["oauth.provider.name"]], "example")
  testthat::expect_identical(s$attributes[["oauth.phase"]], "login.request")
  testthat::expect_true(nzchar(s$attributes[["shinyoauth.trace_id"]] %||% ""))
})

# ---------------------------------------------------------------------------
# prepare_call + handle_callback — shared trace_id and span hierarchy
# ---------------------------------------------------------------------------

otel_e2e("prepare_call and callback share shinyOAuth trace_id", {
  r <- otelsdk::with_otel_record({
    cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
    btok <- valid_browser_token()
    url <- shinyOAuth::prepare_call(cli, browser_token = btok)
    enc <- parse_query_param(url, "state")

    testthat::with_mocked_bindings(
      swap_code_for_token_set = function(client, code, code_verifier) {
        list(access_token = "test_at", expires_in = 3600)
      },
      .package = "shinyOAuth",
      {
        shinyOAuth::handle_callback(
          cli,
          code = "test_code",
          payload = enc,
          browser_token = btok
        )
      }
    )
  })
  login_span <- r$traces[["shinyOAuth.login.request"]]
  callback_span <- r$traces[["shinyOAuth.callback"]]

  tid <- login_span$attributes[["shinyoauth.trace_id"]]
  testthat::expect_true(nzchar(tid))
  testthat::expect_identical(
    callback_span$attributes[["shinyoauth.trace_id"]],
    tid
  )
  # token.verify is a child of callback
  verify_span <- r$traces[["shinyOAuth.token.verify"]]
  testthat::expect_false(is.null(verify_span))
})

otel_e2e("prepare_call roots itself and callback parents to login span", {
  r <- otelsdk::with_otel_record({
    cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
    btok <- valid_browser_token()

    url <- shinyOAuth:::with_otel_span("reactive_update.login", {
      shinyOAuth::prepare_call(cli, browser_token = btok)
    })
    enc <- parse_query_param(url, "state")

    testthat::with_mocked_bindings(
      swap_code_for_token_set = function(client, code, code_verifier) {
        list(access_token = "test_at", expires_in = 3600)
      },
      .package = "shinyOAuth",
      {
        shinyOAuth:::with_otel_span("reactive_update.callback", {
          shinyOAuth::handle_callback(
            cli,
            code = "test_code",
            payload = enc,
            browser_token = btok
          )
        })
      }
    )
  })

  outer_login <- r$traces[["reactive_update.login"]]
  outer_callback <- r$traces[["reactive_update.callback"]]
  login_span <- r$traces[["shinyOAuth.login.request"]]
  callback_span <- r$traces[["shinyOAuth.callback"]]

  testthat::expect_identical(login_span$parent, "0000000000000000")
  testthat::expect_identical(callback_span$parent, login_span$span_id)
  testthat::expect_identical(callback_span$trace_id, login_span$trace_id)
  testthat::expect_false(identical(login_span$parent, outer_login$span_id))
  testthat::expect_false(identical(callback_span$parent, outer_callback$span_id))
})

# ---------------------------------------------------------------------------
# get_userinfo — HTTP child span captures response metadata
# ---------------------------------------------------------------------------

otel_e2e("userinfo HTTP response attributes stay on HTTP child span", {
  cli <- make_test_client()
  cli@provider@userinfo_url <- "https://example.com/userinfo"

  r <- otelsdk::with_otel_record({
    testthat::with_mocked_bindings(
      req_with_retry = function(req, ...) {
        httr2::response(
          url = "https://example.com/userinfo",
          status = 200,
          headers = list("content-type" = "application/json"),
          body = charToRaw('{"sub":"user123"}')
        )
      },
      .package = "shinyOAuth",
      {
        shinyOAuth::get_userinfo(cli, token = "at")
      }
    )
  })
  http_span <- r$traces[["shinyOAuth.userinfo.http"]]
  parent_span <- r$traces[["shinyOAuth.userinfo"]]

  testthat::expect_identical(
    as.integer(http_span$attributes[["http.response.status_code"]]),
    200L
  )
  testthat::expect_null(parent_span$attributes[["http.response.status_code"]])
  testthat::expect_identical(http_span$status, "ok")
})

# ---------------------------------------------------------------------------
# revoke_token — sync span hierarchy
# ---------------------------------------------------------------------------

otel_e2e("revoke_token sync emits revoke + HTTP child span", {
  cli <- make_test_client()
  cli@provider@revocation_url <- "https://example.com/revoke"
  tok <- OAuthToken(
    access_token = "at",
    refresh_token = NA_character_,
    expires_at = as.numeric(Sys.time()) + 60,
    id_token = NA_character_
  )

  r <- otelsdk::with_otel_record({
    testthat::with_mocked_bindings(
      req_with_retry = function(req, ...) {
        httr2::response(
          url = "https://example.com/revoke",
          status = 200,
          headers = list("content-type" = "application/json"),
          body = charToRaw("{}")
        )
      },
      .package = "shinyOAuth",
      {
        shinyOAuth::revoke_token(
          cli,
          tok,
          which = "access",
          async = FALSE
        )
      }
    )
  })
  testthat::expect_true("shinyOAuth.token.revoke" %in% names(r$traces))
  testthat::expect_true("shinyOAuth.token.revoke.http" %in% names(r$traces))
  testthat::expect_identical(
    r$traces[["shinyOAuth.token.revoke"]]$status,
    "ok"
  )
})

# ---------------------------------------------------------------------------
# introspect_token — error span on HTTP failure
# ---------------------------------------------------------------------------

otel_e2e("introspect_token HTTP span marked error on 500", {
  cli <- make_test_client()
  cli@provider@introspection_url <- "https://example.com/introspect"
  tok <- OAuthToken(
    access_token = "at",
    refresh_token = NA_character_,
    expires_at = as.numeric(Sys.time()) + 60,
    id_token = NA_character_
  )

  r <- otelsdk::with_otel_record({
    testthat::with_mocked_bindings(
      req_with_retry = function(req, ...) {
        httr2::response(
          url = "https://example.com/introspect",
          status = 500,
          headers = list("content-type" = "application/json"),
          body = charToRaw("{}")
        )
      },
      .package = "shinyOAuth",
      {
        shinyOAuth::introspect_token(
          cli,
          tok,
          which = "access",
          async = FALSE
        )
      }
    )
  })
  http_span <- r$traces[["shinyOAuth.token.introspect.http"]]
  testthat::expect_identical(
    as.integer(http_span$attributes[["http.response.status_code"]]),
    500L
  )
  testthat::expect_identical(http_span$status, "error")
})

# ---------------------------------------------------------------------------
# refresh_token — sync span with exchange child
# ---------------------------------------------------------------------------

otel_e2e("refresh_token sync emits span hierarchy", {
  cli <- make_test_client()
  tok <- OAuthToken(
    access_token = "at",
    refresh_token = "rt",
    expires_at = as.numeric(Sys.time()) - 60,
    id_token = NA_character_
  )

  r <- otelsdk::with_otel_record({
    testthat::with_mocked_bindings(
      swap_code_for_token_set = function(client, ...) {
        list(access_token = "new_at", expires_in = 3600)
      },
      req_with_retry = function(req, ...) {
        httr2::response(
          url = "https://example.com/token",
          status = 200,
          headers = list("content-type" = "application/json"),
          body = charToRaw(
            '{"access_token":"new_at","expires_in":3600}'
          )
        )
      },
      .package = "shinyOAuth",
      {
        shinyOAuth::refresh_token(cli, tok, async = FALSE)
      }
    )
  })
  span_names <- names(r$traces)
  testthat::expect_true("shinyOAuth.refresh" %in% span_names)
})

# ---------------------------------------------------------------------------
# Instrumentation scope
# ---------------------------------------------------------------------------

otel_e2e("instrumentation scope is r.package.shinyOAuth", {
  r <- otelsdk::with_otel_record({
    shinyOAuth:::with_otel_span("shinyOAuth.test.scope", 1)
  })
  s <- r$traces[["shinyOAuth.test.scope"]]
  testthat::expect_identical(
    s$instrumentation_scope$name,
    "io.github.lukakoning.shinyOAuth"
  )
})
