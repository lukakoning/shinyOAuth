resolve_test_promise <- function(p) {
  testthat::skip_if_not_installed("promises")
  testthat::skip_if_not_installed("later")

  resolved <- NULL
  rejected <- NULL

  promises::as.promise(p)$then(function(value) {
    resolved <<- value
  })$catch(function(err) {
    rejected <<- err
  })

  deadline <- Sys.time() + 5
  while (is.null(resolved) && is.null(rejected) && Sys.time() < deadline) {
    later::run_now(0.05)
    Sys.sleep(0.02)
  }

  if (!is.null(rejected)) {
    stop(rejected)
  }

  resolved
}

testthat::test_that("audit_event forwards the structured event without creating a span", {
  calls <- character()
  seen_event <- NULL

  testthat::with_mocked_bindings(
    with_otel_span = function(name, code, attributes = NULL, options = NULL) {
      calls <<- c(calls, name)
      eval.parent(substitute(code))
    },
    emit_trace_event = function(event) {
      seen_event <<- event
      invisible(NULL)
    },
    .package = "shinyOAuth",
    {
      shinyOAuth:::audit_event("token_refresh", context = list(status = "ok"))
    }
  )

  testthat::expect_length(calls, 0L)
  testthat::expect_identical(seen_event$type, "audit_token_refresh")
})

testthat::test_that("revoke_token creates otel spans for sync and async flows", {
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  cli@provider@revocation_url <- "https://example.com/revoke"
  tok <- OAuthToken(
    access_token = "at",
    refresh_token = "rt",
    expires_at = as.numeric(Sys.time()) + 60,
    id_token = NA_character_
  )

  sync_calls <- character()
  sync_result <- testthat::with_mocked_bindings(
    with_otel_span = function(name, code, attributes = NULL, options = NULL) {
      sync_calls <<- c(sync_calls, name)
      eval.parent(substitute(code))
    },
    emit_trace_event = function(event) invisible(NULL),
    req_with_retry = function(req, ...) {
      httr2::response(
        url = as.character(req$url),
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw("{}")
      )
    },
    .package = "shinyOAuth",
    {
      shinyOAuth::revoke_token(cli, tok, which = "access", async = FALSE)
    }
  )

  testthat::expect_identical(sync_result$status, "ok")
  testthat::expect_true(all(
    c(
      "shinyOAuth.token.revoke",
      "shinyOAuth.token.revoke.http"
    ) %in%
      sync_calls
  ))

  async_start <- NULL
  async_worker <- NULL
  async_raw <- testthat::with_mocked_bindings(
    otel_start_async_parent = function(name, attributes = NULL) {
      async_start <<- name
      list(
        span = NULL,
        headers = c(
          traceparent = "00-11111111111111111111111111111111-2222222222222222-01"
        )
      )
    },
    async_dispatch = function(
      expr,
      args,
      .timeout = NULL,
      otel_context = NULL
    ) {
      async_worker <<- otel_context$worker_span_name
      promises::promise_resolve(list(
        .shinyOAuth_async_wrapped = TRUE,
        value = list(supported = TRUE, revoked = TRUE, status = "ok"),
        warnings = list(),
        messages = list()
      ))
    },
    .package = "shinyOAuth",
    {
      shinyOAuth::revoke_token(cli, tok, which = "access", async = TRUE)
    }
  )
  async_result <- shinyOAuth:::replay_async_conditions(resolve_test_promise(
    async_raw
  ))

  testthat::expect_identical(async_start, "shinyOAuth.token.revoke")
  testthat::expect_identical(async_worker, "shinyOAuth.token.revoke.worker")
  testthat::expect_identical(async_result$status, "ok")
})

testthat::test_that("introspect_token creates otel spans for sync and async flows", {
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  cli@provider@introspection_url <- "https://example.com/introspect"
  tok <- OAuthToken(
    access_token = "at",
    refresh_token = "rt",
    expires_at = as.numeric(Sys.time()) + 60,
    id_token = NA_character_
  )

  sync_calls <- character()
  sync_result <- testthat::with_mocked_bindings(
    with_otel_span = function(name, code, attributes = NULL, options = NULL) {
      sync_calls <<- c(sync_calls, name)
      eval.parent(substitute(code))
    },
    emit_trace_event = function(event) invisible(NULL),
    req_with_retry = function(req, ...) {
      httr2::response(
        url = as.character(req$url),
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw('{"active":true}')
      )
    },
    .package = "shinyOAuth",
    {
      shinyOAuth::introspect_token(cli, tok, which = "access", async = FALSE)
    }
  )

  testthat::expect_true(isTRUE(sync_result$active))
  testthat::expect_true(all(
    c(
      "shinyOAuth.token.introspect",
      "shinyOAuth.token.introspect.http"
    ) %in%
      sync_calls
  ))

  async_start <- NULL
  async_worker <- NULL
  async_raw <- testthat::with_mocked_bindings(
    otel_start_async_parent = function(name, attributes = NULL) {
      async_start <<- name
      list(
        span = NULL,
        headers = c(
          traceparent = "00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-01"
        )
      )
    },
    async_dispatch = function(
      expr,
      args,
      .timeout = NULL,
      otel_context = NULL
    ) {
      async_worker <<- otel_context$worker_span_name
      promises::promise_resolve(list(
        .shinyOAuth_async_wrapped = TRUE,
        value = list(
          supported = TRUE,
          active = TRUE,
          raw = list(active = TRUE),
          status = "ok"
        ),
        warnings = list(),
        messages = list()
      ))
    },
    .package = "shinyOAuth",
    {
      shinyOAuth::introspect_token(cli, tok, which = "access", async = TRUE)
    }
  )
  async_result <- shinyOAuth:::replay_async_conditions(resolve_test_promise(
    async_raw
  ))

  testthat::expect_identical(async_start, "shinyOAuth.token.introspect")
  testthat::expect_identical(async_worker, "shinyOAuth.token.introspect.worker")
  testthat::expect_identical(async_result$status, "ok")
})
