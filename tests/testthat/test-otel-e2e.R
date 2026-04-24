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

otel_named_spans <- function(traces, name) {
  Filter(function(span) identical(span$name %||% NA_character_, name), traces)
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
    cli <- make_test_client(
      use_pkce = TRUE,
      use_nonce = TRUE,
      scopes = c("openid", "profile", "email"),
      claims = list(id_token = list(email = list(essential = TRUE)))
    )
    cli@provider@id_token_validation <- TRUE
    cli@required_acr_values <- c("loa2", "loa3")
    cli@provider@extra_auth_params <- list(max_age = 300, prompt = "login")
    shinyOAuth::prepare_call(cli, browser_token = valid_browser_token())
  })
  s <- r$traces[["shinyOAuth.login.request"]]
  testthat::expect_false(is.null(s))
  testthat::expect_identical(s$status, "ok")
  testthat::expect_identical(s$attributes[["oauth.provider.name"]], "example")
  testthat::expect_identical(s$attributes[["oauth.phase"]], "login.request")
  testthat::expect_identical(
    s$attributes[["oauth.scopes.requested"]],
    "openid profile email"
  )
  testthat::expect_identical(
    as.integer(s$attributes[["oauth.scopes.requested_count"]]),
    3L
  )
  testthat::expect_identical(s$attributes[["oauth.claims.requested"]], TRUE)
  testthat::expect_identical(
    s$attributes[["oauth.claims.targets"]],
    "id_token"
  )
  testthat::expect_identical(
    s$attributes[["oauth.required_acr_values"]],
    "loa2 loa3"
  )
  testthat::expect_identical(
    as.integer(s$attributes[["oauth.required_acr_values_count"]]),
    2L
  )
  testthat::expect_identical(
    as.numeric(s$attributes[["oauth.max_age.requested"]]),
    300
  )
  testthat::expect_identical(
    as.integer(s$attributes[["oauth.extra_auth_params_count"]]),
    2L
  )
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
  testthat::expect_false(identical(
    callback_span$parent,
    outer_callback$span_id
  ))
})

otel_e2e("handle_callback span captures callback flow attributes", {
  cli <- make_test_client(use_nonce = TRUE)
  cli@provider@introspection_url <- "https://example.com/introspect"
  cli@provider@userinfo_url <- "https://example.com/userinfo"
  cli@provider@userinfo_required <- TRUE
  cli@provider@id_token_validation <- TRUE
  cli@provider@userinfo_id_token_match <- TRUE
  cli@introspect <- TRUE
  cli@introspect_elements <- c("scope", "sub")

  r <- otelsdk::with_otel_record({
    testthat::with_mocked_bindings(
      handle_callback_internal = function(...) "ok",
      .package = "shinyOAuth",
      {
        shinyOAuth::handle_callback(
          cli,
          code = "test_code",
          payload = "test_payload",
          browser_token = valid_browser_token()
        )
      }
    )
  })

  s <- r$traces[["shinyOAuth.callback"]]
  testthat::expect_identical(s$attributes[["oauth.introspect"]], TRUE)
  testthat::expect_identical(
    s$attributes[["oauth.introspect_elements"]],
    "scope,sub"
  )
  testthat::expect_identical(
    as.integer(s$attributes[["oauth.introspect_elements_count"]]),
    2L
  )
  testthat::expect_identical(s$attributes[["oauth.userinfo.required"]], TRUE)
  testthat::expect_identical(
    s$attributes[["oauth.userinfo.id_token_match_required"]],
    TRUE
  )
  testthat::expect_identical(
    s$attributes[["oauth.id_token.validation_enabled"]],
    TRUE
  )
})

otel_e2e("module.init span captures module configuration attributes", {
  cli <- make_test_client()
  cli@provider@revocation_url <- "https://example.com/revoke"

  r <- otelsdk::with_otel_record({
    shiny::testServer(
      shinyOAuth::oauth_module_server,
      args = list(
        id = "auth",
        client = cli,
        auto_redirect = FALSE,
        async = FALSE,
        indefinite_session = TRUE,
        reauth_after_seconds = 1800,
        refresh_proactively = TRUE,
        refresh_lead_seconds = 90,
        revoke_on_session_end = TRUE,
        browser_cookie_path = "/app",
        browser_cookie_samesite = "Strict"
      ),
      {
        invisible(NULL)
      }
    )
  })

  s <- r$traces[["shinyOAuth.module.init"]]
  testthat::expect_identical(s$attributes[["oauth.auto_redirect"]], FALSE)
  testthat::expect_identical(
    s$attributes[["oauth.refresh_proactively"]],
    TRUE
  )
  testthat::expect_identical(
    s$attributes[["oauth.revoke_on_session_end"]],
    TRUE
  )
  testthat::expect_identical(
    s$attributes[["oauth.indefinite_session"]],
    TRUE
  )
  testthat::expect_identical(
    as.numeric(s$attributes[["oauth.reauth_after_seconds"]]),
    1800
  )
  testthat::expect_identical(
    as.numeric(s$attributes[["oauth.refresh_lead_seconds"]]),
    90
  )
  testthat::expect_identical(
    s$attributes[["oauth.browser_cookie_samesite"]],
    "Strict"
  )
  testthat::expect_identical(
    s$attributes[["oauth.browser_cookie_path_root"]],
    FALSE
  )
})

otel_e2e("module logout and session-end flows emit lifecycle spans around revoke spans", {
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  cli@provider@revocation_url <- "https://example.com/revoke"

  make_token <- function() {
    OAuthToken(
      access_token = "at",
      refresh_token = "rt",
      expires_at = as.numeric(Sys.time()) + 60,
      id_token = NA_character_
    )
  }

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
        shiny::testServer(
          shinyOAuth::oauth_module_server,
          args = list(
            id = "logout_mod",
            client = cli,
            auto_redirect = FALSE,
            async = FALSE,
            revoke_on_session_end = FALSE
          ),
          {
            values$token <- make_token()
            session$flushReact()
            values$logout()
            session$flushReact()
          }
        )

        shiny::testServer(
          shinyOAuth::oauth_module_server,
          args = list(
            id = "session_end_mod",
            client = cli,
            auto_redirect = FALSE,
            async = FALSE,
            revoke_on_session_end = TRUE
          ),
          {
            values$token <- make_token()
            session$flushReact()
            testthat::expect_true(values$authenticated)
          }
        )
      }
    )
  })

  logout_span <- otel_named_spans(r$traces, "shinyOAuth.logout")
  session_end_span <- otel_named_spans(r$traces, "shinyOAuth.session.end.revoke")
  revoke_spans <- otel_named_spans(r$traces, "shinyOAuth.token.revoke")
  revoke_http_spans <- otel_named_spans(r$traces, "shinyOAuth.token.revoke.http")

  testthat::expect_length(logout_span, 1L)
  testthat::expect_length(session_end_span, 1L)
  testthat::expect_length(revoke_spans, 4L)
  testthat::expect_length(revoke_http_spans, 4L)

  logout_span <- logout_span[[1L]]
  session_end_span <- session_end_span[[1L]]
  logout_app_trace_id <- logout_span$attributes[["shinyoauth.trace_id"]]
  session_end_app_trace_id <- session_end_span$attributes[[
    "shinyoauth.trace_id"
  ]]

  logout_revoke_spans <- Filter(
    function(span) {
      identical(
        span$attributes[["shinyoauth.trace_id"]],
        logout_app_trace_id
      )
    },
    revoke_spans
  )
  session_end_revoke_spans <- Filter(
    function(span) {
      identical(
        span$attributes[["shinyoauth.trace_id"]],
        session_end_app_trace_id
      )
    },
    revoke_spans
  )
  logout_revoke_ids <- vapply(logout_revoke_spans, `[[`, "", "span_id")
  session_end_revoke_ids <- vapply(
    session_end_revoke_spans,
    `[[`,
    "",
    "span_id"
  )
  logout_http_spans <- Filter(
    function(span) {
      identical(
        span$attributes[["shinyoauth.trace_id"]],
        logout_app_trace_id
      ) &&
        span$parent %in% logout_revoke_ids
    },
    revoke_http_spans
  )
  session_end_http_spans <- Filter(
    function(span) {
      identical(
        span$attributes[["shinyoauth.trace_id"]],
        session_end_app_trace_id
      ) &&
        span$parent %in% session_end_revoke_ids
    },
    revoke_http_spans
  )

  testthat::expect_identical(logout_span$status, "ok")
  testthat::expect_identical(
    logout_span$attributes[["oauth.phase"]],
    "logout"
  )
  testthat::expect_identical(
    logout_span$attributes[["shiny.module_id"]],
    "logout_mod"
  )
  testthat::expect_true(is_valid_string(logout_app_trace_id))
  testthat::expect_length(logout_revoke_spans, 2L)
  testthat::expect_length(logout_http_spans, 2L)
  testthat::expect_true(all(vapply(
    logout_revoke_spans,
    function(span) {
      identical(span$status, "ok") &&
        identical(span$parent, "0000000000000000")
    },
    logical(1)
  )))

  testthat::expect_identical(session_end_span$status, "ok")
  testthat::expect_identical(
    session_end_span$attributes[["oauth.phase"]],
    "session.end.revoke"
  )
  testthat::expect_identical(
    session_end_span$attributes[["shiny.module_id"]],
    "session_end_mod"
  )
  testthat::expect_identical(
    session_end_span$attributes[["shiny.session.is_async"]],
    FALSE
  )
  testthat::expect_identical(
    as.integer(session_end_span$attributes[["shiny.session.process_id"]]),
    Sys.getpid()
  )
  testthat::expect_true(is_valid_string(session_end_app_trace_id))
  testthat::expect_length(session_end_revoke_spans, 2L)
  testthat::expect_length(session_end_http_spans, 2L)
  testthat::expect_true(all(vapply(
    session_end_revoke_spans,
    function(span) {
      identical(span$status, "ok") &&
        identical(span$parent, "0000000000000000") &&
        identical(
          span$attributes[["shiny.session.is_async"]],
          FALSE
        ) &&
        identical(
          as.integer(span$attributes[["shiny.session.process_id"]]),
          Sys.getpid()
        )
    },
    logical(1)
  )))
})

otel_e2e("token.exchange span captures request and response attributes", {
  cli <- make_test_client(use_pkce = TRUE)
  cli@provider@extra_token_params <- list(resource = "https://api.example.com")
  cli@provider@extra_token_headers <- c(Accept = "application/json")
  shiny_session <- list(
    token = "async-session-token",
    http = NULL,
    is_async = TRUE,
    process_id = 4321L,
    main_process_id = 1234L
  )

  r <- otelsdk::with_otel_record({
    testthat::with_mocked_bindings(
      req_with_retry = function(req, ...) {
        httr2::response(
          url = "https://example.com/token",
          status = 200,
          headers = list("content-type" = "application/json"),
          body = charToRaw(paste0(
            '{"access_token":"at","refresh_token":"rt","id_token":"id",',
            '"expires_in":3600,"scope":"openid profile","token_type":"Bearer"}'
          ))
        )
      },
      .package = "shinyOAuth",
      {
        shinyOAuth:::swap_code_for_token_set(
          cli,
          code = "test_code",
          code_verifier = "test_verifier",
          shiny_session = shiny_session
        )
      }
    )
  })

  s <- r$traces[["shinyOAuth.token.exchange"]]
  testthat::expect_identical(s$attributes[["oauth.client_auth_style"]], "body")
  testthat::expect_identical(
    as.integer(s$attributes[["oauth.extra_token_params_count"]]),
    1L
  )
  testthat::expect_identical(
    as.integer(s$attributes[["oauth.extra_token_headers_count"]]),
    1L
  )
  testthat::expect_identical(s$attributes[["oauth.token_type"]], "Bearer")
  testthat::expect_identical(s$attributes[["oauth.received_id_token"]], TRUE)
  testthat::expect_identical(
    s$attributes[["oauth.received_refresh_token"]],
    TRUE
  )
  testthat::expect_identical(
    s$attributes[["oauth.scopes.granted"]],
    "openid profile"
  )
  testthat::expect_identical(s$attributes[["oauth.expires_in_present"]], TRUE)
  testthat::expect_identical(
    s$attributes[["oauth.expires_in_synthesized"]],
    FALSE
  )
  testthat::expect_identical(s$attributes[["oauth.scope.present"]], TRUE)
  testthat::expect_identical(s$attributes[["shiny.session.is_async"]], TRUE)
})

otel_e2e("token.verify span captures validation decision attributes", {
  cli <- make_test_client(
    use_nonce = TRUE,
    scopes = c("openid", "profile")
  )
  cli@provider@id_token_validation <- TRUE
  cli@required_acr_values <- "loa2"
  shiny_session <- list(
    token = "async-session-token",
    http = NULL,
    is_async = TRUE,
    process_id = 4321L,
    main_process_id = 1234L
  )

  r <- otelsdk::with_otel_record({
    testthat::with_mocked_bindings(
      validate_id_token = function(...) invisible(TRUE),
      parse_jwt_payload = function(...) list(sub = "user-1", acr = "loa2"),
      .package = "shinyOAuth",
      {
        shinyOAuth:::verify_token_set(
          cli,
          token_set = list(
            access_token = "at",
            refresh_token = "rt",
            id_token = "jwt",
            token_type = "Bearer",
            scope = "openid profile"
          ),
          nonce = "nonce-1",
          is_refresh = FALSE,
          shiny_session = shiny_session
        )
      }
    )
  })

  s <- r$traces[["shinyOAuth.token.verify"]]
  testthat::expect_identical(s$attributes[["oauth.id_token.required"]], TRUE)
  testthat::expect_identical(s$attributes[["oauth.id_token.present"]], TRUE)
  testthat::expect_identical(s$attributes[["oauth.id_token.validated"]], TRUE)
  testthat::expect_identical(s$attributes[["oauth.nonce.required"]], TRUE)
  testthat::expect_identical(
    s$attributes[["oauth.scope.validation_mode"]],
    "strict"
  )
  testthat::expect_identical(
    s$attributes[["oauth.scopes.requested"]],
    "openid profile"
  )
  testthat::expect_identical(
    as.integer(s$attributes[["oauth.scopes.requested_count"]]),
    2L
  )
  testthat::expect_identical(
    s$attributes[["oauth.scopes.granted"]],
    "openid profile"
  )
  testthat::expect_identical(
    as.integer(s$attributes[["oauth.scopes.granted_count"]]),
    2L
  )
  testthat::expect_identical(
    s$attributes[["oauth.required_acr_values"]],
    "loa2"
  )
  testthat::expect_identical(
    as.integer(s$attributes[["oauth.required_acr_values_count"]]),
    1L
  )
  testthat::expect_identical(s$attributes[["oauth.refresh_flow"]], FALSE)
  testthat::expect_identical(s$attributes[["shiny.session.is_async"]], TRUE)
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
  testthat::expect_identical(
    http_span$attributes[["http.response.content_type"]],
    "application/json"
  )
  testthat::expect_null(parent_span$attributes[["http.response.status_code"]])
  testthat::expect_identical(
    parent_span$attributes[["oauth.userinfo.jwt_required"]],
    FALSE
  )
  testthat::expect_identical(
    parent_span$attributes[["oauth.userinfo.jwt_response"]],
    FALSE
  )
  testthat::expect_identical(
    parent_span$attributes[["oauth.userinfo.subject_present"]],
    TRUE
  )
  testthat::expect_identical(http_span$status, "ok")
})

otel_e2e("userinfo span preserves explicit async shiny session attributes", {
  cli <- make_test_client()
  cli@provider@userinfo_url <- "https://example.com/userinfo"
  shiny_session <- list(
    token = "async-session-token",
    http = NULL,
    is_async = TRUE,
    process_id = 4321L,
    main_process_id = 1234L
  )

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
        shinyOAuth::get_userinfo(
          cli,
          token = "at",
          shiny_session = shiny_session
        )
      }
    )
  })

  parent_span <- r$traces[["shinyOAuth.userinfo"]]

  testthat::expect_identical(
    parent_span$attributes[["shiny.session.is_async"]],
    TRUE
  )
  testthat::expect_identical(
    as.integer(parent_span$attributes[["shiny.session.process_id"]]),
    4321L
  )
  testthat::expect_true(nzchar(parent_span$attributes[[
    "shiny.session_token_digest"
  ]]))
})

otel_e2e("userinfo span normalizes borrowed async shiny session context", {
  cli <- make_test_client()
  cli@provider@userinfo_url <- "https://example.com/userinfo"
  borrowed_shiny_session <- list(
    token = "async-session-token",
    http = NULL,
    is_async = TRUE,
    process_id = NULL,
    main_process_id = 1234L
  )

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
        shinyOAuth:::with_async_session_context(borrowed_shiny_session, {
          shinyOAuth::get_userinfo(
            cli,
            token = "at",
            shiny_session = borrowed_shiny_session
          )
        })
      }
    )
  })

  parent_span <- r$traces[["shinyOAuth.userinfo"]]

  testthat::expect_identical(
    parent_span$attributes[["shiny.session.is_async"]],
    TRUE
  )
  testthat::expect_identical(
    as.integer(parent_span$attributes[["shiny.session.process_id"]]),
    Sys.getpid()
  )
})

# ---------------------------------------------------------------------------
# revoke_token — sync span hierarchy
# ---------------------------------------------------------------------------

otel_e2e("revoke_token sync emits revoke + HTTP child span", {
  cli <- make_test_client()
  cli@provider@revocation_url <- "https://example.com/revoke"
  cli@provider@extra_token_headers <- c(Accept = "application/json")
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
  testthat::expect_identical(
    r$traces[["shinyOAuth.token.revoke"]]$attributes[[
      "oauth.client_auth_style"
    ]],
    "body"
  )
  testthat::expect_identical(
    as.integer(r$traces[["shinyOAuth.token.revoke"]]$attributes[[
      "oauth.extra_token_headers_count"
    ]]),
    1L
  )
  testthat::expect_identical(
    r$traces[["shinyOAuth.token.revoke"]]$attributes[["oauth.token.which"]],
    "access"
  )
})

# ---------------------------------------------------------------------------
# introspect_token — error span on HTTP failure
# ---------------------------------------------------------------------------

otel_e2e("introspect_token HTTP span marked error on 500", {
  cli <- make_test_client()
  cli@provider@introspection_url <- "https://example.com/introspect"
  cli@provider@extra_token_headers <- c(Accept = "application/json")
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
  testthat::expect_identical(
    r$traces[["shinyOAuth.token.introspect"]]$attributes[[
      "oauth.client_auth_style"
    ]],
    "body"
  )
  testthat::expect_identical(
    as.integer(r$traces[["shinyOAuth.token.introspect"]]$attributes[[
      "oauth.extra_token_headers_count"
    ]]),
    1L
  )
  testthat::expect_identical(
    r$traces[["shinyOAuth.token.introspect"]]$attributes[[
      "oauth.token.which"
    ]],
    "access"
  )
})

# ---------------------------------------------------------------------------
# refresh_token — sync span with exchange child
# ---------------------------------------------------------------------------

otel_e2e("refresh_token sync emits span hierarchy", {
  cli <- make_test_client()
  cli@provider@extra_token_params <- list(resource = "https://api.example.com")
  cli@provider@extra_token_headers <- c(Accept = "application/json")
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
            paste0(
              '{"access_token":"new_at","refresh_token":"new_rt",',
              '"expires_in":3600,"scope":"openid profile","token_type":"Bearer"}'
            )
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
  testthat::expect_identical(
    r$traces[["shinyOAuth.refresh"]]$attributes[[
      "oauth.client_auth_style"
    ]],
    "body"
  )
  testthat::expect_identical(
    as.integer(r$traces[["shinyOAuth.refresh"]]$attributes[[
      "oauth.extra_token_params_count"
    ]]),
    1L
  )
  testthat::expect_identical(
    as.integer(r$traces[["shinyOAuth.refresh"]]$attributes[[
      "oauth.extra_token_headers_count"
    ]]),
    1L
  )
  testthat::expect_identical(
    r$traces[["shinyOAuth.refresh"]]$attributes[[
      "oauth.received_refresh_token"
    ]],
    TRUE
  )
  testthat::expect_identical(
    r$traces[["shinyOAuth.refresh"]]$attributes[["oauth.scopes.granted"]],
    "openid profile"
  )
  testthat::expect_identical(
    r$traces[["shinyOAuth.refresh"]]$attributes[["oauth.expires_in_present"]],
    TRUE
  )
  testthat::expect_identical(
    r$traces[["shinyOAuth.refresh"]]$attributes[["oauth.scope.present"]],
    TRUE
  )
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
