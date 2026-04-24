# End-to-end OpenTelemetry tests for async span propagation.
# Covers both sync mirai (in-process) and real mirai daemons with a shared
# OTLP file exporter.

reset_test_otel_cache()
withr::defer(reset_test_otel_cache())

otel_async <- function(desc, code) {
  testthat::test_that(desc, {
    testthat::skip_if_not_installed("otelsdk")
    testthat::skip_if_not_installed("mirai")
    testthat::skip_if_not_installed("promises")
    testthat::skip_if_not_installed("later")
    withr::local_options(list(
      shinyOAuth.otel_tracing_enabled = TRUE,
      shinyOAuth.otel_logging_enabled = FALSE,
      shinyOAuth.skip_browser_token = TRUE
    ))
    force(code)
  })
}

otel_async_daemon <- function(desc, code) {
  testthat::test_that(desc, {
    testthat::skip_on_cran()
    testthat::skip_if_not_installed("otelsdk")
    testthat::skip_if_not_installed("mirai")
    testthat::skip_if_not_installed("promises")
    testthat::skip_if_not_installed("later")
    testthat::skip_if_not_installed("webfakes")
    withr::local_options(list(
      shinyOAuth.otel_tracing_enabled = TRUE,
      shinyOAuth.otel_logging_enabled = FALSE,
      shinyOAuth.skip_browser_token = TRUE
    ))
    force(code)
  })
}

otel_null_coalesce <- function(x, y) {
  if (is.null(x)) y else x
}

otel_export_attr_value <- function(attributes, key) {
  if (is.null(attributes) || !length(attributes)) {
    return(NULL)
  }

  for (attr in attributes) {
    if (!identical(attr$key, key)) {
      next
    }
    value <- otel_null_coalesce(attr$value, list())
    for (field in c("stringValue", "intValue", "boolValue", "doubleValue")) {
      if (!is.null(value[[field]])) {
        return(value[[field]])
      }
    }
  }

  NULL
}

otel_exported_spans <- function(path) {
  if (!file.exists(path)) {
    return(list())
  }

  docs <- lapply(
    readLines(path, warn = FALSE),
    jsonlite::fromJSON,
    simplifyVector = FALSE
  )

  spans <- list()
  for (doc in docs) {
    for (resource_span in otel_null_coalesce(doc$resourceSpans, list())) {
      process_id <- suppressWarnings(as.integer(
        otel_export_attr_value(
          otel_null_coalesce(resource_span$resource$attributes, list()),
          "process.pid"
        )
      ))
      for (scope_span in otel_null_coalesce(resource_span$scopeSpans, list())) {
        scope_name <- otel_null_coalesce(scope_span$scope$name, NA_character_)
        for (span in otel_null_coalesce(scope_span$spans, list())) {
          spans[[length(spans) + 1L]] <- list(
            name = otel_null_coalesce(span$name, NA_character_),
            trace_id = otel_null_coalesce(span$traceId, NA_character_),
            span_id = otel_null_coalesce(span$spanId, NA_character_),
            parent_span_id = otel_null_coalesce(
              span$parentSpanId,
              NA_character_
            ),
            scope_name = scope_name,
            process_id = process_id,
            attributes = otel_null_coalesce(span$attributes, list())
          )
        }
      }
    }
  }

  spans
}

otel_find_spans <- function(spans, name) {
  Filter(function(span) identical(span$name, name), spans)
}

otel_find_phase_spans <- function(spans, name, phase) {
  Filter(
    function(span) {
      identical(span$name, name) &&
        identical(otel_span_attribute(span, "oauth.phase"), phase)
    },
    spans
  )
}

otel_span_attribute <- function(span, key) {
  otel_export_attr_value(span$attributes, key)
}

otel_exported_logs <- function(path) {
  if (!file.exists(path)) {
    return(list())
  }

  docs <- lapply(
    readLines(path, warn = FALSE),
    jsonlite::fromJSON,
    simplifyVector = FALSE
  )

  logs <- list()
  for (doc in docs) {
    for (resource_log in otel_null_coalesce(doc$resourceLogs, list())) {
      for (scope_log in otel_null_coalesce(resource_log$scopeLogs, list())) {
        scope_name <- otel_null_coalesce(scope_log$scope$name, NA_character_)
        for (log_record in otel_null_coalesce(scope_log$logRecords, list())) {
          logs[[length(logs) + 1L]] <- list(
            body = otel_null_coalesce(
              otel_null_coalesce(log_record$body, list())$stringValue,
              NA_character_
            ),
            trace_id = otel_null_coalesce(log_record$traceId, NA_character_),
            span_id = otel_null_coalesce(log_record$spanId, NA_character_),
            scope_name = scope_name,
            attributes = otel_null_coalesce(log_record$attributes, list())
          )
        }
      }
    }
  }

  logs
}

otel_log_attribute <- function(log_record, key) {
  otel_export_attr_value(log_record$attributes, key)
}

otel_scope_spans <- function(path) {
  Filter(
    function(span) {
      identical(span$scope_name, "io.github.lukakoning.shinyOAuth")
    },
    otel_exported_spans(path)
  )
}

otel_scope_logs <- function(path) {
  Filter(
    function(log_record) {
      identical(log_record$scope_name, "io.github.lukakoning.shinyOAuth")
    },
    otel_exported_logs(path)
  )
}

expect_async_operation_spans <- function(
  spans,
  operation_name,
  worker_name,
  http_name,
  http_status = 200L
) {
  operation_spans <- otel_find_spans(spans, operation_name)
  worker_span <- otel_find_spans(spans, worker_name)
  http_span <- otel_find_spans(spans, http_name)

  testthat::expect_length(operation_spans, 2L)
  testthat::expect_length(worker_span, 1L)
  testthat::expect_length(http_span, 1L)

  if (
    length(operation_spans) != 2L ||
      length(worker_span) != 1L ||
      length(http_span) != 1L
  ) {
    return(NULL)
  }

  main_operation <- Filter(
    function(span) identical(span$process_id, Sys.getpid()),
    operation_spans
  )
  worker_operation <- Filter(
    function(span) identical(span$process_id, worker_span[[1L]]$process_id),
    operation_spans
  )

  testthat::expect_length(main_operation, 1L)
  testthat::expect_length(worker_operation, 1L)

  if (length(main_operation) != 1L || length(worker_operation) != 1L) {
    return(NULL)
  }

  trace_ids <- unique(vapply(
    c(operation_spans, worker_span, http_span),
    function(span) span$trace_id,
    character(1)
  ))
  testthat::expect_length(trace_ids, 1L)
  testthat::expect_identical(
    worker_span[[1L]]$parent_span_id,
    main_operation[[1L]]$span_id
  )
  testthat::expect_identical(
    worker_operation[[1L]]$parent_span_id,
    worker_span[[1L]]$span_id
  )
  testthat::expect_identical(
    http_span[[1L]]$parent_span_id,
    worker_operation[[1L]]$span_id
  )
  if (!is.null(http_status)) {
    testthat::expect_identical(
      as.integer(otel_span_attribute(
        http_span[[1L]],
        "http.response.status_code"
      )),
      as.integer(http_status)
    )
  }
  testthat::expect_false(
    identical(main_operation[[1L]]$process_id, worker_span[[1L]]$process_id)
  )

  list(
    main_operation = main_operation[[1L]],
    worker_span = worker_span[[1L]],
    worker_operation = worker_operation[[1L]],
    http_span = http_span[[1L]]
  )
}

otel_temp_jsonl_path <- function(prefix) {
  stamp <- gsub("[^0-9]", "", format(Sys.time(), "%Y%m%d%H%M%OS6"))
  file.path(
    tempdir(),
    paste0(prefix, "-", Sys.getpid(), "-", stamp, ".jsonl")
  )
}

make_async_otel_client <- function(token_url) {
  prov <- shinyOAuth::oauth_provider(
    name = "example",
    auth_url = "https://example.com/auth",
    token_url = token_url,
    userinfo_url = NA_character_,
    introspection_url = NA_character_,
    issuer = NA_character_,
    use_nonce = FALSE,
    use_pkce = TRUE,
    pkce_method = "S256",
    userinfo_required = FALSE,
    id_token_required = FALSE,
    id_token_validation = FALSE,
    userinfo_id_token_match = FALSE,
    extra_auth_params = list(),
    extra_token_params = list(),
    extra_token_headers = character(),
    token_auth_style = "body",
    jwks_cache = cachem::cache_mem(max_age = 60),
    jwks_pins = character(),
    jwks_pin_mode = "any",
    allowed_algs = c("RS256", "ES256"),
    allowed_token_types = character(),
    leeway = 60
  )

  shinyOAuth::oauth_client(
    provider = prov,
    client_id = "abc",
    client_secret = "",
    redirect_uri = "http://localhost:8100",
    scopes = character(0),
    state_store = cachem::cache_mem(max_age = 600),
    state_payload_max_age = 300,
    state_entropy = 64,
    state_key = paste0(
      "0123456789abcdefghijklmnopqrstuvwxyz",
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    )
  )
}

otel_async("async parent/worker span propagation via sync mirai", {
  mirai::daemons(1, sync = TRUE)
  withr::defer(mirai::daemons(0))

  r <- otelsdk::with_otel_record({
    parent <- shinyOAuth:::otel_start_async_parent(
      "shinyOAuth.test.async.parent",
      attributes = list(oauth.phase = "test")
    )

    resolved <- NULL
    promises::then(
      promises::as.promise(
        shinyOAuth:::async_dispatch(
          expr = quote({
            .ns <- asNamespace("shinyOAuth")
            .ns$with_otel_span("shinyOAuth.test.async.child", 1)
          }),
          args = list(),
          otel_context = list(
            headers = parent$headers,
            worker_span_name = "shinyOAuth.test.async.worker"
          )
        )
      ),
      function(x) {
        resolved <<- x
        invisible(NULL)
      }
    )

    deadline <- Sys.time() + 10
    while (is.null(resolved) && Sys.time() < deadline) {
      later::run_now(0.05)
      Sys.sleep(0.01)
    }

    testthat::expect_false(is.null(resolved))
    shinyOAuth:::replay_async_conditions(resolved)
    shinyOAuth:::otel_end_async_parent(parent, status = "ok")
  })

  span_names <- names(r$traces)
  testthat::expect_true("shinyOAuth.test.async.parent" %in% span_names)

  # sync mirai runs in-process, so worker and child spans may also be captured
  parent_span <- r$traces[["shinyOAuth.test.async.parent"]]
  testthat::expect_identical(parent_span$status, "ok")
})

otel_async("async parent span marked error on failure", {
  r <- otelsdk::with_otel_record({
    parent <- shinyOAuth:::otel_start_async_parent(
      "shinyOAuth.test.async.err"
    )
    shinyOAuth:::otel_end_async_parent(
      parent,
      status = "error",
      error = simpleError("async operation failed")
    )
  })

  s <- r$traces[["shinyOAuth.test.async.err"]]
  testthat::expect_identical(s$status, "error")
  testthat::expect_true(length(s$events) > 0)
})

otel_async("async context headers contain traceparent", {
  r <- otelsdk::with_otel_record({
    parent <- shinyOAuth:::otel_start_async_parent(
      "shinyOAuth.test.async.ctx"
    )
    hdrs <- parent$headers
    shinyOAuth:::otel_end_async_parent(parent, status = "ok")
    hdrs
  })

  testthat::expect_true("traceparent" %in% names(r$value))
  testthat::expect_true(nzchar(r$value[["traceparent"]]))
})

otel_async_daemon("async parent/worker span propagation via real mirai daemon", {
  ok <- tryCatch(
    {
      mirai::daemons(1, rs = "--vanilla")
      TRUE
    },
    error = function(...) FALSE
  )
  testthat::skip_if(!ok, "Could not start mirai daemons")
  withr::defer(mirai::daemons(0))
  assert_shinyoauth_available_in_daemon()

  otel_file <- otel_temp_jsonl_path("shinyoauth-otel-async")
  if (file.exists(otel_file)) {
    file.remove(otel_file)
  }

  withr::local_envvar(c(
    OTEL_R_TRACES_EXPORTER = "otlp/file",
    OTEL_TRACES_EXPORTER = "otlp/file",
    OTEL_R_LOGS_EXPORTER = "none",
    OTEL_LOGS_EXPORTER = "none",
    OTEL_R_METRICS_EXPORTER = "none",
    OTEL_METRICS_EXPORTER = "none",
    OTEL_EXPORTER_OTLP_TRACES_FILE = otel_file,
    OTEL_EXPORTER_OTLP_TRACES_FILE_FLUSH_COUNT = "1",
    OTEL_EXPORTER_OTLP_TRACES_FILE_FLUSH_INTERVAL = "1ms"
  ))
  get("otel_clean_cache", envir = asNamespace("otel"))()
  withr::defer(reset_test_otel_cache())

  parent <- shinyOAuth:::otel_start_async_parent(
    "shinyOAuth.test.async.parent",
    attributes = list(oauth.phase = "test")
  )
  testthat::expect_true(
    is.character(parent$headers[["traceparent"]]) &&
      nzchar(parent$headers[["traceparent"]])
  )

  resolved <- NULL
  promises::then(
    promises::as.promise(
      shinyOAuth:::async_dispatch(
        expr = quote({
          .ns <- asNamespace("shinyOAuth")
          .ns$with_otel_span("shinyOAuth.test.async.child", 1)
        }),
        args = list(),
        otel_context = list(
          headers = parent$headers,
          worker_span_name = "shinyOAuth.test.async.worker"
        )
      )
    ),
    function(x) {
      resolved <<- x
      invisible(NULL)
    }
  )

  poll_for_async(function() !is.null(resolved), timeout = 10)
  testthat::expect_false(is.null(resolved))
  shinyOAuth:::replay_async_conditions(resolved)
  shinyOAuth:::otel_end_async_parent(parent, status = "ok")

  poll_for_async(
    function() {
      spans <- Filter(
        function(span) {
          identical(span$scope_name, "io.github.lukakoning.shinyOAuth")
        },
        otel_exported_spans(otel_file)
      )
      length(spans) >= 3L
    },
    timeout = 10
  )

  spans <- Filter(
    function(span) {
      identical(span$scope_name, "io.github.lukakoning.shinyOAuth")
    },
    otel_exported_spans(otel_file)
  )
  parent_span <- otel_find_spans(spans, "shinyOAuth.test.async.parent")
  worker_span <- otel_find_spans(spans, "shinyOAuth.test.async.worker")
  child_span <- otel_find_spans(spans, "shinyOAuth.test.async.child")

  testthat::expect_length(parent_span, 1L)
  testthat::expect_length(worker_span, 1L)
  testthat::expect_length(child_span, 1L)
  testthat::expect_identical(
    parent_span[[1L]]$trace_id,
    worker_span[[1L]]$trace_id
  )
  testthat::expect_identical(
    worker_span[[1L]]$trace_id,
    child_span[[1L]]$trace_id
  )
  testthat::expect_identical(
    worker_span[[1L]]$parent_span_id,
    parent_span[[1L]]$span_id
  )
  testthat::expect_identical(
    child_span[[1L]]$parent_span_id,
    worker_span[[1L]]$span_id
  )
  testthat::expect_false(
    identical(parent_span[[1L]]$process_id, worker_span[[1L]]$process_id)
  )
})

otel_async_daemon("reused real mirai daemons clear stale file exporters after env restore", {
  ok <- tryCatch(
    {
      mirai::daemons(1, rs = "--vanilla")
      TRUE
    },
    error = function(...) FALSE
  )
  testthat::skip_if(!ok, "Could not start mirai daemons")
  withr::defer(mirai::daemons(0))
  assert_shinyoauth_available_in_daemon()

  old_otel_state <- capture_test_otel_state()
  withr::defer(restore_test_otel_state(old_otel_state))

  otel_file <- otel_temp_jsonl_path("shinyoauth-otel-reused-daemon")
  if (file.exists(otel_file)) {
    file.remove(otel_file)
  }

  dispatch_span <- function(span_name) {
    resolved <- NULL
    promises::then(
      promises::as.promise(
        shinyOAuth:::async_dispatch(
          expr = quote({
            .ns <- asNamespace("shinyOAuth")
            .ns$with_otel_span(span_name, {
              list(
                pid = Sys.getpid(),
                tracing_enabled = otel::is_tracing_enabled(),
                traces_exporter = Sys.getenv(
                  "OTEL_R_TRACES_EXPORTER",
                  unset = NA_character_
                ),
                traces_file = Sys.getenv(
                  "OTEL_EXPORTER_OTLP_TRACES_FILE",
                  unset = NA_character_
                )
              )
            })
          }),
          args = list(span_name = span_name)
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

  first_result <- withr::with_envvar(
    c(
      OTEL_R_TRACES_EXPORTER = "otlp/file",
      OTEL_TRACES_EXPORTER = "otlp/file",
      OTEL_R_LOGS_EXPORTER = "none",
      OTEL_LOGS_EXPORTER = "none",
      OTEL_R_METRICS_EXPORTER = "none",
      OTEL_METRICS_EXPORTER = "none",
      OTEL_EXPORTER_OTLP_TRACES_FILE = otel_file,
      OTEL_EXPORTER_OTLP_TRACES_FILE_FLUSH_COUNT = "1",
      OTEL_EXPORTER_OTLP_TRACES_FILE_FLUSH_INTERVAL = "1ms"
    ),
    dispatch_span("shinyOAuth.test.async.file.enabled")
  )

  poll_for_async(
    function() {
      length(otel_find_spans(
        otel_scope_spans(otel_file),
        "shinyOAuth.test.async.file.enabled"
      )) >=
        1L
    },
    timeout = 10
  )

  spans_after_first <- otel_scope_spans(otel_file)
  first_spans <- otel_find_spans(
    spans_after_first,
    "shinyOAuth.test.async.file.enabled"
  )

  second_result <- withr::with_envvar(
    c(
      OTEL_R_TRACES_EXPORTER = NA_character_,
      OTEL_TRACES_EXPORTER = NA_character_,
      OTEL_R_LOGS_EXPORTER = NA_character_,
      OTEL_LOGS_EXPORTER = NA_character_,
      OTEL_R_METRICS_EXPORTER = NA_character_,
      OTEL_METRICS_EXPORTER = NA_character_,
      OTEL_EXPORTER_OTLP_TRACES_FILE = NA_character_,
      OTEL_EXPORTER_OTLP_TRACES_FILE_FLUSH_COUNT = NA_character_,
      OTEL_EXPORTER_OTLP_TRACES_FILE_FLUSH_INTERVAL = NA_character_
    ),
    dispatch_span("shinyOAuth.test.async.file.unset")
  )

  deadline <- Sys.time() + 1
  while (Sys.time() < deadline) {
    later::run_now(0.05)
    Sys.sleep(0.01)
  }

  spans_after_second <- otel_scope_spans(otel_file)
  second_spans <- otel_find_spans(
    spans_after_second,
    "shinyOAuth.test.async.file.unset"
  )

  testthat::expect_true(isTRUE(first_result$tracing_enabled))
  testthat::expect_identical(first_result$traces_exporter, "otlp/file")
  testthat::expect_identical(first_result$traces_file, otel_file)
  testthat::expect_length(first_spans, 1L)

  testthat::expect_identical(second_result$pid, first_result$pid)
  testthat::expect_false(isTRUE(second_result$tracing_enabled))
  testthat::expect_true(is.na(second_result$traces_exporter))
  testthat::expect_true(is.na(second_result$traces_file))
  testthat::expect_length(second_spans, 0L)
  testthat::expect_length(spans_after_second, length(spans_after_first))
})

otel_async_daemon("async module callback/login success exports correct main and worker session metadata", {
  ok <- tryCatch(
    {
      mirai::daemons(1, rs = "--vanilla")
      TRUE
    },
    error = function(...) FALSE
  )
  testthat::skip_if(!ok, "Could not start mirai daemons")
  withr::defer(mirai::daemons(0))
  assert_shinyoauth_available_in_daemon()

  app <- webfakes::new_app()
  app$post("/token", function(req, res) {
    res$set_status(200L)
    res$set_type("application/json")
    res$send_json(list(access_token = "ok_at", expires_in = 3600))
  })
  srv <- webfakes::local_app_process(app)

  otel_file <- otel_temp_jsonl_path("shinyoauth-otel-callback-success")
  if (file.exists(otel_file)) {
    file.remove(otel_file)
  }

  withr::local_envvar(c(
    OTEL_R_TRACES_EXPORTER = "otlp/file",
    OTEL_TRACES_EXPORTER = "otlp/file",
    OTEL_R_LOGS_EXPORTER = "none",
    OTEL_LOGS_EXPORTER = "none",
    OTEL_R_METRICS_EXPORTER = "none",
    OTEL_METRICS_EXPORTER = "none",
    OTEL_EXPORTER_OTLP_TRACES_FILE = otel_file,
    OTEL_EXPORTER_OTLP_TRACES_FILE_FLUSH_COUNT = "1",
    OTEL_EXPORTER_OTLP_TRACES_FILE_FLUSH_INTERVAL = "1ms"
  ))
  get("otel_clean_cache", envir = asNamespace("otel"))()
  withr::defer(reset_test_otel_cache())

  cli <- make_async_otel_client(srv$url("/token"))

  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = list(
      id = "auth",
      client = cli,
      auto_redirect = FALSE,
      async = TRUE,
      indefinite_session = TRUE
    ),
    expr = {
      testthat::expect_true(values$has_browser_token())
      auth_url <- values$build_auth_url()
      enc <- parse_query_param(auth_url, "state")
      testthat::expect_true(is.character(enc) && nzchar(enc))

      values$.process_query(paste0("?code=ok&state=", enc))
      poll_for_async(function() !is.null(values$token), session, timeout = 15)
      poll_for_async(function() isTRUE(values$authenticated), session, timeout = 15)

      testthat::expect_true(isTRUE(values$authenticated))
      testthat::expect_null(values$error)
      testthat::expect_false(is.null(values$token))
    }
  )

  poll_for_async(
    function() {
      spans <- otel_scope_spans(otel_file)
      length(otel_find_spans(spans, "shinyOAuth.login.request")) >= 1L &&
        length(otel_find_spans(spans, "shinyOAuth.callback")) >= 1L &&
        length(otel_find_spans(spans, "shinyOAuth.callback.worker")) >= 1L &&
        length(otel_find_phase_spans(
          spans,
          "shinyOAuth.callback.validate",
          "callback.state_payload"
        )) >=
          1L &&
        length(otel_find_phase_spans(
          spans,
          "shinyOAuth.callback.validate",
          "callback.state_store_consume"
        )) >=
          1L &&
        length(otel_find_spans(spans, "shinyOAuth.token.exchange")) >= 1L
    },
    timeout = 15
  )

  spans <- otel_scope_spans(otel_file)
  login_span <- otel_find_spans(spans, "shinyOAuth.login.request")
  callback_span <- otel_find_spans(spans, "shinyOAuth.callback")
  worker_span <- otel_find_spans(spans, "shinyOAuth.callback.worker")
  state_payload_span <- otel_find_phase_spans(
    spans,
    "shinyOAuth.callback.validate",
    "callback.state_payload"
  )
  state_store_span <- otel_find_phase_spans(
    spans,
    "shinyOAuth.callback.validate",
    "callback.state_store_consume"
  )
  token_exchange_span <- otel_find_spans(spans, "shinyOAuth.token.exchange")
  token_http_span <- otel_find_spans(spans, "shinyOAuth.token.exchange.http")

  testthat::expect_length(login_span, 1L)
  testthat::expect_length(callback_span, 1L)
  testthat::expect_length(worker_span, 1L)
  testthat::expect_length(state_payload_span, 1L)
  testthat::expect_length(state_store_span, 1L)
  testthat::expect_length(token_exchange_span, 1L)
  testthat::expect_length(token_http_span, 1L)

  if (
    length(login_span) != 1L ||
      length(callback_span) != 1L ||
      length(worker_span) != 1L ||
      length(state_payload_span) != 1L ||
      length(state_store_span) != 1L ||
      length(token_exchange_span) != 1L ||
      length(token_http_span) != 1L
  ) {
    return(invisible(NULL))
  }

  login_span <- login_span[[1L]]
  callback_span <- callback_span[[1L]]
  worker_span <- worker_span[[1L]]
  state_payload_span <- state_payload_span[[1L]]
  state_store_span <- state_store_span[[1L]]
  token_exchange_span <- token_exchange_span[[1L]]
  token_http_span <- token_http_span[[1L]]

  testthat::expect_identical(callback_span$trace_id, login_span$trace_id)
  testthat::expect_identical(callback_span$parent_span_id, login_span$span_id)
  testthat::expect_identical(worker_span$trace_id, callback_span$trace_id)
  testthat::expect_identical(worker_span$parent_span_id, callback_span$span_id)
  testthat::expect_identical(
    token_exchange_span$parent_span_id,
    worker_span$span_id
  )
  testthat::expect_identical(
    token_http_span$parent_span_id,
    token_exchange_span$span_id
  )

  for (span in list(state_payload_span, state_store_span)) {
    testthat::expect_identical(span$trace_id, callback_span$trace_id)
    testthat::expect_identical(span$parent_span_id, callback_span$span_id)
    testthat::expect_identical(span$process_id, Sys.getpid())
    testthat::expect_identical(
      otel_span_attribute(span, "shiny.session.is_async"),
      FALSE
    )
    testthat::expect_identical(
      as.integer(otel_span_attribute(span, "shiny.session.process_id")),
      Sys.getpid()
    )
  }

  testthat::expect_false(identical(worker_span$process_id, Sys.getpid()))
  testthat::expect_identical(
    otel_span_attribute(worker_span, "shiny.session.is_async"),
    TRUE
  )
  testthat::expect_identical(
    as.integer(otel_span_attribute(worker_span, "shiny.session.process_id")),
    worker_span$process_id
  )
  testthat::expect_identical(
    token_exchange_span$process_id,
    worker_span$process_id
  )
  testthat::expect_identical(
    as.integer(otel_span_attribute(
      token_exchange_span,
      "shiny.session.process_id"
    )),
    worker_span$process_id
  )
})

otel_async_daemon("refresh_token async exports correlated spans from a real daemon", {
  ok <- tryCatch(
    {
      mirai::daemons(1, rs = "--vanilla")
      TRUE
    },
    error = function(...) FALSE
  )
  testthat::skip_if(!ok, "Could not start mirai daemons")
  withr::defer(mirai::daemons(0))
  assert_shinyoauth_available_in_daemon()

  app <- webfakes::new_app()
  app$post("/token", function(req, res) {
    res$set_status(200L)
    res$set_type("application/json")
    res$send_json(list(access_token = "new_at", expires_in = 3600))
  })
  srv <- webfakes::local_app_process(app)

  cli <- make_async_otel_client(srv$url("/token"))
  tok <- shinyOAuth::OAuthToken(
    access_token = "at",
    refresh_token = "rt",
    expires_at = as.numeric(Sys.time()) - 60,
    id_token = NA_character_
  )

  otel_file <- otel_temp_jsonl_path("shinyoauth-otel-refresh")
  if (file.exists(otel_file)) {
    file.remove(otel_file)
  }

  withr::local_envvar(c(
    OTEL_R_TRACES_EXPORTER = "otlp/file",
    OTEL_TRACES_EXPORTER = "otlp/file",
    OTEL_R_LOGS_EXPORTER = "none",
    OTEL_LOGS_EXPORTER = "none",
    OTEL_R_METRICS_EXPORTER = "none",
    OTEL_METRICS_EXPORTER = "none",
    OTEL_EXPORTER_OTLP_TRACES_FILE = otel_file,
    OTEL_EXPORTER_OTLP_TRACES_FILE_FLUSH_COUNT = "1",
    OTEL_EXPORTER_OTLP_TRACES_FILE_FLUSH_INTERVAL = "1ms"
  ))
  get("otel_clean_cache", envir = asNamespace("otel"))()
  withr::defer(reset_test_otel_cache())

  resolved <- NULL
  promises::then(
    promises::as.promise(
      shinyOAuth::refresh_token(
        cli,
        tok,
        async = TRUE,
        introspect = FALSE
      )
    ),
    function(x) {
      resolved <<- x
      invisible(NULL)
    }
  )

  poll_for_async(function() !is.null(resolved), timeout = 10)
  testthat::expect_false(is.null(resolved))
  refreshed <- shinyOAuth:::replay_async_conditions(resolved)
  testthat::expect_true(S7::S7_inherits(refreshed, shinyOAuth::OAuthToken))
  testthat::expect_identical(refreshed@access_token, "new_at")

  poll_for_async(
    function() {
      spans <- Filter(
        function(span) {
          identical(span$scope_name, "io.github.lukakoning.shinyOAuth")
        },
        otel_exported_spans(otel_file)
      )
      length(spans) >= 4L
    },
    timeout = 10
  )

  spans <- otel_scope_spans(otel_file)
  expect_async_operation_spans(
    spans,
    operation_name = "shinyOAuth.refresh",
    worker_name = "shinyOAuth.refresh.worker",
    http_name = "shinyOAuth.token.exchange.http"
  )
})

otel_async_daemon("refresh_token async exports logs correlated with spans from a real daemon", {
  ok <- tryCatch(
    {
      mirai::daemons(1, rs = "--vanilla")
      TRUE
    },
    error = function(...) FALSE
  )
  testthat::skip_if(!ok, "Could not start mirai daemons")
  withr::defer(mirai::daemons(0))
  assert_shinyoauth_available_in_daemon()
  withr::local_options(list(shinyOAuth.otel_logging_enabled = TRUE))

  app <- webfakes::new_app()
  app$post("/token", function(req, res) {
    res$set_status(200L)
    res$set_type("application/json")
    res$send_json(list(access_token = "new_at", expires_in = 3600))
  })
  srv <- webfakes::local_app_process(app)

  cli <- make_async_otel_client(srv$url("/token"))
  tok <- shinyOAuth::OAuthToken(
    access_token = "at",
    refresh_token = "rt",
    expires_at = as.numeric(Sys.time()) - 60,
    id_token = NA_character_
  )

  trace_file <- otel_temp_jsonl_path("shinyoauth-otel-refresh-traces")
  log_file <- otel_temp_jsonl_path("shinyoauth-otel-refresh-logs")
  if (file.exists(trace_file)) {
    file.remove(trace_file)
  }
  if (file.exists(log_file)) {
    file.remove(log_file)
  }

  withr::local_envvar(c(
    OTEL_R_TRACES_EXPORTER = "otlp/file",
    OTEL_TRACES_EXPORTER = "otlp/file",
    OTEL_R_LOGS_EXPORTER = "otlp/file",
    OTEL_LOGS_EXPORTER = "otlp/file",
    OTEL_R_METRICS_EXPORTER = "none",
    OTEL_METRICS_EXPORTER = "none",
    OTEL_EXPORTER_OTLP_TRACES_FILE = trace_file,
    OTEL_EXPORTER_OTLP_TRACES_FILE_FLUSH_INTERVAL = "1ms",
    OTEL_EXPORTER_OTLP_LOGS_FILE = log_file,
    OTEL_EXPORTER_OTLP_LOGS_FILE_FLUSH_INTERVAL = "1ms"
  ))
  get("otel_clean_cache", envir = asNamespace("otel"))()
  withr::defer(reset_test_otel_cache())

  resolved <- NULL
  promises::then(
    promises::as.promise(
      shinyOAuth::refresh_token(
        cli,
        tok,
        async = TRUE,
        introspect = FALSE
      )
    ),
    function(x) {
      resolved <<- x
      invisible(NULL)
    }
  )

  poll_for_async(function() !is.null(resolved), timeout = 10)
  testthat::expect_false(is.null(resolved))
  refreshed <- shinyOAuth:::replay_async_conditions(resolved)
  testthat::expect_true(S7::S7_inherits(refreshed, shinyOAuth::OAuthToken))
  testthat::expect_identical(refreshed@access_token, "new_at")

  poll_for_async(
    function() {
      length(otel_scope_spans(trace_file)) >= 4L &&
        length(otel_scope_logs(log_file)) >= 1L
    },
    timeout = 10
  )

  span_tree <- expect_async_operation_spans(
    otel_scope_spans(trace_file),
    operation_name = "shinyOAuth.refresh",
    worker_name = "shinyOAuth.refresh.worker",
    http_name = "shinyOAuth.token.exchange.http"
  )
  if (is.null(span_tree)) {
    return(invisible(NULL))
  }

  refresh_logs <- Filter(
    function(log_record) {
      identical(
        otel_log_attribute(log_record, "event.type"),
        "audit_token_refresh"
      )
    },
    otel_scope_logs(log_file)
  )

  testthat::expect_true(length(refresh_logs) >= 1L)
  testthat::expect_true(any(vapply(
    refresh_logs,
    function(log_record) {
      identical(log_record$trace_id, span_tree$worker_operation$trace_id) &&
        identical(log_record$span_id, span_tree$worker_operation$span_id)
    },
    logical(1)
  )))
  testthat::expect_true(any(vapply(
    refresh_logs,
    function(log_record) {
      value <- otel_log_attribute(log_record, "shinyoauth.trace_id")
      is.character(value) && length(value) == 1L && nzchar(value)
    },
    logical(1)
  )))
})

otel_async_daemon("revoke_token async exports correlated spans from a real daemon", {
  ok <- tryCatch(
    {
      mirai::daemons(1, rs = "--vanilla")
      TRUE
    },
    error = function(...) FALSE
  )
  testthat::skip_if(!ok, "Could not start mirai daemons")
  withr::defer(mirai::daemons(0))
  assert_shinyoauth_available_in_daemon()

  app <- webfakes::new_app()
  app$post("/revoke", function(req, res) {
    res$set_status(200L)
    res$set_type("application/json")
    res$send_json(list())
  })
  srv <- webfakes::local_app_process(app)

  cli <- make_async_otel_client("https://example.com/token")
  cli@provider@revocation_url <- srv$url("/revoke")
  tok <- shinyOAuth::OAuthToken(
    access_token = "at",
    refresh_token = "rt",
    expires_at = as.numeric(Sys.time()) + 60,
    id_token = NA_character_
  )

  otel_file <- otel_temp_jsonl_path("shinyoauth-otel-revoke")
  if (file.exists(otel_file)) {
    file.remove(otel_file)
  }

  withr::local_envvar(c(
    OTEL_R_TRACES_EXPORTER = "otlp/file",
    OTEL_TRACES_EXPORTER = "otlp/file",
    OTEL_R_LOGS_EXPORTER = "none",
    OTEL_LOGS_EXPORTER = "none",
    OTEL_R_METRICS_EXPORTER = "none",
    OTEL_METRICS_EXPORTER = "none",
    OTEL_EXPORTER_OTLP_TRACES_FILE = otel_file,
    OTEL_EXPORTER_OTLP_TRACES_FILE_FLUSH_INTERVAL = "1ms"
  ))
  get("otel_clean_cache", envir = asNamespace("otel"))()
  withr::defer(reset_test_otel_cache())

  resolved <- NULL
  promises::then(
    promises::as.promise(
      shinyOAuth::revoke_token(
        cli,
        tok,
        which = "access",
        async = TRUE
      )
    ),
    function(x) {
      resolved <<- x
      invisible(NULL)
    }
  )

  poll_for_async(function() !is.null(resolved), timeout = 10)
  testthat::expect_false(is.null(resolved))
  revoke_result <- shinyOAuth:::replay_async_conditions(resolved)
  testthat::expect_true(isTRUE(revoke_result$supported))
  testthat::expect_true(isTRUE(revoke_result$revoked))
  testthat::expect_identical(revoke_result$status, "ok")

  poll_for_async(
    function() {
      length(otel_scope_spans(otel_file)) >= 4L
    },
    timeout = 10
  )

  expect_async_operation_spans(
    otel_scope_spans(otel_file),
    operation_name = "shinyOAuth.token.revoke",
    worker_name = "shinyOAuth.token.revoke.worker",
    http_name = "shinyOAuth.token.revoke.http"
  )
})

otel_async_daemon("introspect_token async exports correlated spans from a real daemon", {
  ok <- tryCatch(
    {
      mirai::daemons(1, rs = "--vanilla")
      TRUE
    },
    error = function(...) FALSE
  )
  testthat::skip_if(!ok, "Could not start mirai daemons")
  withr::defer(mirai::daemons(0))
  assert_shinyoauth_available_in_daemon()

  app <- webfakes::new_app()
  app$post("/introspect", function(req, res) {
    res$set_status(200L)
    res$set_type("application/json")
    res$send_json(list(active = TRUE))
  })
  srv <- webfakes::local_app_process(app)

  cli <- make_async_otel_client("https://example.com/token")
  cli@provider@introspection_url <- srv$url("/introspect")
  tok <- shinyOAuth::OAuthToken(
    access_token = "at",
    refresh_token = "rt",
    expires_at = as.numeric(Sys.time()) + 60,
    id_token = NA_character_
  )

  otel_file <- otel_temp_jsonl_path("shinyoauth-otel-introspect")
  if (file.exists(otel_file)) {
    file.remove(otel_file)
  }

  withr::local_envvar(c(
    OTEL_R_TRACES_EXPORTER = "otlp/file",
    OTEL_TRACES_EXPORTER = "otlp/file",
    OTEL_R_LOGS_EXPORTER = "none",
    OTEL_LOGS_EXPORTER = "none",
    OTEL_R_METRICS_EXPORTER = "none",
    OTEL_METRICS_EXPORTER = "none",
    OTEL_EXPORTER_OTLP_TRACES_FILE = otel_file,
    OTEL_EXPORTER_OTLP_TRACES_FILE_FLUSH_INTERVAL = "1ms"
  ))
  get("otel_clean_cache", envir = asNamespace("otel"))()
  withr::defer(reset_test_otel_cache())

  resolved <- NULL
  promises::then(
    promises::as.promise(
      shinyOAuth::introspect_token(
        cli,
        tok,
        which = "access",
        async = TRUE
      )
    ),
    function(x) {
      resolved <<- x
      invisible(NULL)
    }
  )

  poll_for_async(function() !is.null(resolved), timeout = 10)
  testthat::expect_false(is.null(resolved))
  introspection <- shinyOAuth:::replay_async_conditions(resolved)
  testthat::expect_true(isTRUE(introspection$supported))
  testthat::expect_true(isTRUE(introspection$active))
  testthat::expect_identical(introspection$status, "ok")

  poll_for_async(
    function() {
      length(otel_scope_spans(otel_file)) >= 4L
    },
    timeout = 10
  )

  expect_async_operation_spans(
    otel_scope_spans(otel_file),
    operation_name = "shinyOAuth.token.introspect",
    worker_name = "shinyOAuth.token.introspect.worker",
    http_name = "shinyOAuth.token.introspect.http"
  )
})
