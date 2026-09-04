testthat::test_that("session_started audit event is emitted and enriched", {
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))

  # Capture audit events via option hook
  events <- list()
  old <- options(shinyOAuth.audit_hook = function(e) {
    events[[length(events) + 1]] <<- e
  })
  on.exit(options(old), add = TRUE)

  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)

  # Launch module; do not auto redirect so we avoid further events noise
  shiny::testServer(
    app = oauth_module_server,
    args = list(
      id = "auth",
      client = cli,
      auto_redirect = FALSE,
      indefinite_session = TRUE
    ),
    expr = {
      # no-op: starting the server is enough to emit session_started
      testthat::expect_true(TRUE)
    }
  )

  # Extract types and find session_started
  types <- vapply(
    events,
    function(e) as.character(e[["type"]]),
    character(1)
  )
  idx <- grep("^audit_session_started$", types)
  testthat::expect_true(length(idx) >= 1)

  ev <- events[[idx[[1]]]]
  # Basic shape checks (non-sensitive fields only)
  testthat::expect_equal(
    ev[["module_id"]] %||% NA_character_,
    "auth"
  )
  testthat::expect_true(!is.null(ev[["client_id_digest"]]))

  # Shiny enrichment is grouped under `shiny_session`
  testthat::expect_true("shiny_session" %in% names(ev))
  ss <- ev[["shiny_session"]]
  # Subfields may be NULL in test env; we only assert presence of names
  testthat::expect_true(all(c("http", "session_token_digest") %in% names(ss)))
  testthat::expect_false("token" %in% names(ss))

  # Ensure it is JSON-serializable
  j <- jsonlite::toJSON(ev, auto_unbox = TRUE, null = "null")
  testthat::expect_true(nchar(as.character(j)) > 0)
})

testthat::test_that("shinyOAuth.audit_include_http = FALSE excludes http from events", {
  withr::local_options(list(
    shinyOAuth.skip_browser_token = TRUE,
    shinyOAuth.audit_include_http = FALSE
  ))

  # Capture audit events via option hook
  events <- list()
  old <- options(shinyOAuth.audit_hook = function(e) {
    events[[length(events) + 1]] <<- e
  })
  on.exit(options(old), add = TRUE)

  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)

  shiny::testServer(
    app = oauth_module_server,
    args = list(
      id = "auth",
      client = cli,
      auto_redirect = FALSE,
      indefinite_session = TRUE
    ),
    expr = {
      testthat::expect_true(TRUE)
    }
  )

  # Find session_started event
  types <- vapply(
    events,
    function(e) as.character(e[["type"]]),
    character(1)
  )
  idx <- grep("^audit_session_started$", types)
  testthat::expect_true(length(idx) >= 1)

  ev <- events[[idx[[1]]]]
  ss <- ev[["shiny_session"]]

  # http should be NULL when audit_include_http = FALSE

  testthat::expect_null(ss[["http"]])
  # session digest should still be present
  testthat::expect_true("session_token_digest" %in% names(ss))
  testthat::expect_false("token" %in% names(ss))
})

testthat::test_that("audit_event omits query values and headers by default", {
  sentinels <- c(
    "TOPSECRET_UNKNOWN_QUERY",
    "alice.sentinel@example.test",
    "ey.SENTINEL.jwt",
    "203.0.113.9"
  )
  events <- list()
  req <- list(
    REQUEST_METHOD = "GET",
    PATH_INFO = "/callback",
    QUERY_STRING = paste0(
      "api_key=",
      sentinels[[1L]],
      "&email=",
      sentinels[[2L]]
    ),
    HTTP_HOST = "example.com",
    HTTP_CF_ACCESS_JWT_ASSERTION = sentinels[[3L]],
    HTTP_FORWARDED = paste0("for=", sentinels[[4L]]),
    HTTP_X_FORWARDED_FOR = sentinels[[4L]],
    REMOTE_ADDR = sentinels[[4L]]
  )

  withr::local_options(list(
    shinyOAuth.audit_hook = function(e) {
      events[[length(events) + 1L]] <<- e
    },
    shinyOAuth.audit_include_http = TRUE,
    shinyOAuth.audit_redact_http = NULL
  ))

  testthat::with_mocked_bindings(
    get_current_shiny_request = function() req,
    get_current_shiny_session_token = function() "session-token",
    .package = "shinyOAuth",
    {
      shinyOAuth:::audit_event("test_http_context")
    }
  )

  http_event <- Filter(
    function(e) e[["type"]] == "audit_test_http_context",
    events
  )
  testthat::expect_length(http_event, 1L)

  http <- http_event[[1L]][["shiny_session"]][[
    "http",
    exact = TRUE
  ]]
  testthat::expect_identical(
    http_event[[1L]][["shiny_session"]][["session_token_digest"]],
    shinyOAuth:::string_digest("session-token")
  )
  testthat::expect_null(
    http_event[[1L]][["shiny_session"]][["token"]]
  )
  testthat::expect_equal(http[["method"]], "GET")
  testthat::expect_null(http[["query_string"]])
  testthat::expect_null(http[["headers"]])
  testthat::expect_null(http[["remote_addr"]])

  serialized <- as.character(jsonlite::toJSON(
    http_event[[1L]],
    auto_unbox = TRUE,
    null = "null"
  ))
  for (sentinel in sentinels) {
    testthat::expect_no_match(serialized, sentinel, fixed = TRUE)
  }
})

testthat::test_that("audit_event omits malformed callback query strings", {
  events <- list()
  req <- list(
    REQUEST_METHOD = "GET",
    PATH_INFO = "/callback",
    QUERY_STRING = paste(
      "code=authcode123%ZZ",
      "state=mystate%ZZ",
      "request=signed.request.jwt%ZZ",
      "request_uri=urn:ietf:params:oauth:request_uri:abc123",
      "safe=keep_me",
      sep = "&"
    ),
    HTTP_HOST = "example.com",
    HTTP_USER_AGENT = "TestClient/1.0"
  )

  withr::local_options(list(
    shinyOAuth.audit_hook = function(e) {
      events[[length(events) + 1L]] <<- e
    },
    shinyOAuth.audit_include_http = TRUE,
    shinyOAuth.audit_redact_http = TRUE
  ))

  testthat::with_mocked_bindings(
    get_current_shiny_request = function() req,
    get_current_shiny_session_token = function() "session-token",
    .package = "shinyOAuth",
    {
      shinyOAuth:::audit_event("test_http_context_malformed")
    }
  )

  http_event <- Filter(
    function(e) e[["type"]] == "audit_test_http_context_malformed",
    events
  )
  testthat::expect_length(http_event, 1L)

  http <- http_event[[1L]][["shiny_session"]][[
    "http",
    exact = TRUE
  ]]
  testthat::expect_null(http[["query_string"]])
  testthat::expect_null(http[["headers"]])
})

testthat::test_that("raw query fallback redacts sensitive callback values", {
  testthat::expect_identical(
    shinyOAuth:::redact_query_string_fallback(
      paste(
        "code=authcode123%ZZ",
        "state=mystate%ZZ",
        "client_secret=super-secret%ZZ",
        "client_assertion=jwt-assertion%ZZ",
        "request=signed.request.jwt%ZZ",
        "request_uri=urn:ietf:params:oauth:request_uri:abc123",
        "safe=keep_me",
        sep = "&"
      ),
      sensitive_params = c(
        "code",
        "state",
        "access_token",
        "refresh_token",
        "id_token",
        "token",
        "session_state",
        "code_verifier",
        "nonce",
        "client_secret",
        "client_assertion",
        "assertion",
        "request",
        "request_uri",
        "claims",
        "login_hint",
        "error_description",
        "code_challenge",
        "username",
        "password"
      )
    ),
    paste(
      "code=[REDACTED]",
      "state=[REDACTED]",
      "client_secret=[REDACTED]",
      "client_assertion=[REDACTED]",
      "request=[REDACTED]",
      "request_uri=[REDACTED]",
      "safe=keep_me",
      sep = "&"
    )
  )
})

testthat::test_that("audit_event can include raw HTTP context when redaction is disabled", {
  events <- list()
  req <- list(
    REQUEST_METHOD = "GET",
    PATH_INFO = "/callback",
    QUERY_STRING = "code=authcode123&state=mystate",
    HTTP_HOST = "example.com",
    HTTP_COOKIE = "session=secret123",
    HTTP_AUTHORIZATION = "Bearer token123",
    HTTP_USER_AGENT = "TestClient/1.0",
    HTTP_X_FORWARDED_FOR = "192.168.1.1"
  )

  withr::local_options(list(
    shinyOAuth.audit_hook = function(e) {
      events[[length(events) + 1L]] <<- e
    },
    shinyOAuth.audit_include_http = TRUE,
    shinyOAuth.audit_redact_http = FALSE
  ))

  testthat::with_mocked_bindings(
    get_current_shiny_request = function() req,
    get_current_shiny_session_token = function() "session-token",
    .package = "shinyOAuth",
    {
      shinyOAuth:::audit_event("test_http_context_raw")
    }
  )

  http_event <- Filter(
    function(e) e[["type"]] == "audit_test_http_context_raw",
    events
  )
  testthat::expect_length(http_event, 1L)

  http <- http_event[[1L]][["shiny_session"]][[
    "http",
    exact = TRUE
  ]]
  headers <- http[["headers"]]
  testthat::expect_match(http[["query_string"]], "authcode123")
  testthat::expect_match(http[["query_string"]], "mystate")
  testthat::expect_equal(headers[["cookie"]], "session=secret123")
  testthat::expect_equal(
    headers[["authorization"]],
    "Bearer token123"
  )
  testthat::expect_equal(
    headers[["x_forwarded_for"]],
    "192.168.1.1"
  )
  testthat::expect_equal(http[["remote_addr"]], "192.168.1.1")
})

testthat::test_that("audit hooks can opt back into raw Shiny session tokens", {
  events <- list()

  withr::local_options(list(
    shinyOAuth.audit_hook = function(e) {
      events[[length(events) + 1L]] <<- e
    },
    shinyOAuth.audit_include_raw_session_token = TRUE
  ))

  testthat::with_mocked_bindings(
    get_current_shiny_request = function() NULL,
    get_current_shiny_session_token = function() "session-token",
    .package = "shinyOAuth",
    {
      shinyOAuth:::audit_event("test_raw_session_token")
    }
  )

  raw_event <- Filter(
    function(e) e[["type"]] == "audit_test_raw_session_token",
    events
  )
  testthat::expect_length(raw_event, 1L)
  testthat::expect_identical(
    raw_event[[1L]][["shiny_session"]][["token"]],
    "session-token"
  )
  testthat::expect_identical(
    raw_event[[1L]][["shiny_session"]][["session_token_digest"]],
    shinyOAuth:::string_digest("session-token")
  )
})
