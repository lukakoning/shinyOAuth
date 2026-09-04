testthat::test_that("get_userinfo errors consistently on malformed/non-JSON responses and audits", {
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  cli@provider@userinfo_url <- "https://example.com/userinfo"

  events <- list()
  old_hook <- getOption("shinyOAuth.audit_hook")

  options(shinyOAuth.audit_hook = function(event) {
    events[[length(events) + 1]] <<- event
  })
  on.exit(options(shinyOAuth.audit_hook = old_hook), add = TRUE)

  testthat::local_mocked_bindings(
    req_with_retry = function(req, ...) {
      httr2::response(
        url = as.character(req[["url"]]),
        status = 200,
        headers = list("content-type" = "text/plain"),
        body = charToRaw("this is not json")
      )
    },
    .package = "shinyOAuth"
  )

  testthat::expect_error(
    get_userinfo(cli, token = "access-token"),
    class = "shinyOAuth_userinfo_error",
    regexp = "parse|JSON|json"
  )

  # Audit trail should include a userinfo event even though parsing failed
  types <- vapply(
    events,
    function(e) e[["type"]] %||% NA_character_,
    character(1)
  )
  testthat::expect_true(any(types == "audit_userinfo"))

  ui_events <- events[types == "audit_userinfo"]
  # Our failure path sets status = "parse_error"
  statuses <- vapply(
    ui_events,
    function(e) e$status %||% NA_character_,
    character(1)
  )
  testthat::expect_true(any(statuses == "parse_error"))
})

testthat::test_that("UserInfo parser diagnostics do not expose response data", {
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  cli@provider@userinfo_url <- "https://example.com/userinfo"
  sentinel_json <- "USERINFO_JSON_SECRET_8472"
  sentinel_jwt <- "USERINFO_JWT_SECRET_3901"
  response_body <- paste0('{"sub":"alice","secret":"', sentinel_json)
  response_type <- "application/json"
  events <- list()
  log_calls <- list()

  withr::local_options(list(
    shinyOAuth.audit_hook = function(event) {
      events[[length(events) + 1L]] <<- event
    },
    shinyOAuth.otel_logging_enabled = TRUE,
    shinyOAuth.expose_error_body = FALSE
  ))
  testthat::local_mocked_bindings(
    req_with_retry = function(req, ...) {
      httr2::response(
        url = as.character(req[["url"]]),
        status = 200,
        headers = list("content-type" = response_type),
        body = charToRaw(response_body)
      )
    },
    .package = "shinyOAuth"
  )

  errors <- testthat::with_mocked_bindings(
    log = function(msg, severity, attributes = NULL, ...) {
      log_calls[[length(log_calls) + 1L]] <<- list(
        msg = msg,
        severity = severity,
        attributes = attributes
      )
    },
    .package = "otel",
    {
      json_error <- tryCatch(
        get_userinfo(cli, token = "access-token"),
        error = identity
      )

      malformed_header <- paste0(
        '{"alg":"RS256","secret":"',
        sentinel_jwt
      )
      response_body <- paste(
        shinyOAuth:::base64url_encode(charToRaw(malformed_header)),
        shinyOAuth:::base64url_encode(charToRaw("{}")),
        "AA",
        sep = "."
      )
      response_type <- "application/jwt"
      jwt_error <- tryCatch(
        get_userinfo(cli, token = "access-token"),
        error = identity
      )

      list(json_error, jwt_error)
    }
  )

  rendered <- paste(
    c(
      vapply(errors, conditionMessage, character(1)),
      capture.output(str(events)),
      capture.output(str(log_calls))
    ),
    collapse = "\n"
  )
  testthat::expect_no_match(rendered, sentinel_json, fixed = TRUE)
  testthat::expect_no_match(rendered, sentinel_jwt, fixed = TRUE)
  testthat::expect_true(any(vapply(
    events,
    function(event) is_valid_string(event[["body_digest"]]),
    logical(1)
  )))
  testthat::expect_true(any(vapply(
    events,
    function(event) identical(event[["reason"]], "parse_error"),
    logical(1)
  )))
})

testthat::test_that("get_userinfo rejects duplicate sub members in JSON responses", {
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  cli@provider@userinfo_url <- "https://example.com/userinfo"

  testthat::local_mocked_bindings(
    req_with_retry = function(req, ...) {
      httr2::response(
        url = as.character(req[["url"]]),
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw('{"sub":"alice","sub":"bob"}')
      )
    },
    .package = "shinyOAuth"
  )

  testthat::expect_error(
    get_userinfo(cli, token = "access-token"),
    class = "shinyOAuth_userinfo_error",
    regexp = "Failed to parse userinfo response as JSON"
  )
})

testthat::test_that("get_userinfo rejects non-object JSON responses", {
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  cli@provider@userinfo_url <- "https://example.com/userinfo"

  testthat::local_mocked_bindings(
    req_with_retry = function(req, ...) {
      httr2::response(
        url = as.character(req[["url"]]),
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw('[{"sub":"alice"}]')
      )
    },
    .package = "shinyOAuth"
  )

  testthat::expect_error(
    get_userinfo(cli, token = "access-token"),
    class = "shinyOAuth_userinfo_error",
    regexp = "Failed to parse userinfo response as JSON"
  )
})
