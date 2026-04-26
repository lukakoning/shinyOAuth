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
  types <- vapply(events, function(e) as.character(e$type), character(1))
  idx <- grep("^audit_session_started$", types)
  testthat::expect_true(length(idx) >= 1)

  ev <- events[[idx[[1]]]]
  # Basic shape checks (non-sensitive fields only)
  testthat::expect_equal(ev$module_id %||% NA_character_, "auth")
  testthat::expect_true(!is.null(ev$client_id_digest))

  # Shiny enrichment is grouped under `shiny_session`
  testthat::expect_true("shiny_session" %in% names(ev))
  ss <- ev$shiny_session
  # Subfields may be NULL in test env; we only assert presence of names
  testthat::expect_true(all(c("http", "token") %in% names(ss)))

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
  types <- vapply(events, function(e) as.character(e$type), character(1))
  idx <- grep("^audit_session_started$", types)
  testthat::expect_true(length(idx) >= 1)

  ev <- events[[idx[[1]]]]
  ss <- ev$shiny_session

  # http should be NULL when audit_include_http = FALSE

  testthat::expect_null(ss$http)
  # token should still be present
  testthat::expect_true("token" %in% names(ss))
})

testthat::test_that("audit_event includes redacted HTTP context by default", {
  events <- list()
  req <- list(
    REQUEST_METHOD = "GET",
    PATH_INFO = "/callback",
    QUERY_STRING = "code=authcode123&state=mystate&safe=keep_me",
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
    shinyOAuth.audit_redact_http = TRUE
  ))

  testthat::with_mocked_bindings(
    get_current_shiny_request = function() req,
    get_current_shiny_session_token = function() "session-token",
    .package = "shinyOAuth",
    {
      shinyOAuth:::audit_event("http_context")
    }
  )

  http_event <- Filter(function(e) e$type == "audit_http_context", events)
  testthat::expect_length(http_event, 1L)

  http <- http_event[[1L]]$shiny_session$http
  testthat::expect_equal(http$method, "GET")
  testthat::expect_match(http$query_string, "safe=keep_me")
  testthat::expect_no_match(http$query_string, "authcode123")
  testthat::expect_no_match(http$query_string, "mystate")
  testthat::expect_null(http$headers$cookie)
  testthat::expect_null(http$headers$authorization)
  testthat::expect_equal(http$headers$user_agent, "TestClient/1.0")
  testthat::expect_equal(http$headers$x_forwarded_for, "[REDACTED]")
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
      shinyOAuth:::audit_event("http_context_raw")
    }
  )

  http_event <- Filter(function(e) e$type == "audit_http_context_raw", events)
  testthat::expect_length(http_event, 1L)

  http <- http_event[[1L]]$shiny_session$http
  testthat::expect_match(http$query_string, "authcode123")
  testthat::expect_match(http$query_string, "mystate")
  testthat::expect_equal(http$headers$cookie, "session=secret123")
  testthat::expect_equal(http$headers$authorization, "Bearer token123")
  testthat::expect_equal(http$headers$x_forwarded_for, "192.168.1.1")
})
