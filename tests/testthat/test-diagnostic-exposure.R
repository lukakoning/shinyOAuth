test_that("audit and OTel free-form details require exposure permission", {
  detail <- "private detail\r\nhttps://user:password@example.test/path?code=secret#secret"
  event <- list(
    type = "error",
    message = detail,
    context = list(error_message = detail, transport_error = detail)
  )
  seen <- NULL
  local_options(
    shinyOAuth.expose_error_body = FALSE,
    shinyOAuth.audit_hook = function(event) {
      seen <<- event
    }
  )
  emit_trace_event(event)
  expect_null(seen[["message"]])
  expect_null(seen[["context"]][["error_message"]])
  expect_false(any(grepl(
    "private detail",
    unlist(otel_event_attributes(event))
  )))
  local_options(shinyOAuth.expose_error_body = TRUE)
  emit_trace_event(event)
  expect_match(seen[["message"]], "private detail", fixed = TRUE)
  expect_false(any(grepl("password|secret|[\r\n]", unlist(seen))))
  expect_lte(
    nchar(sanitize_diagnostic_text(strrep("é", 600)), type = "bytes"),
    512
  )
  expect_false(grepl("[[:cntrl:]]", sanitize_diagnostic_text("a\tb\033c")))
})

test_that("provider HTTP descriptions respect exposure and OAuth text syntax", {
  local_options(shinyOAuth.expose_error_body = FALSE)
  response <- httr2::response(
    status = 400,
    headers = list("content-type" = "application/json"),
    body = charToRaw(
      '{"error":"invalid_grant","error_description":"private detail"}'
    )
  )
  error <- tryCatch(
    err_http("Token request failed", response),
    error = identity
  )
  expect_null(error[["oauth_error_description"]])
  expect_false(grepl("private detail", conditionMessage(error)))
  expect_false(grepl("private detail", oauth_module_compose_error(error)))
  local_options(shinyOAuth.expose_error_body = TRUE)
  error <- tryCatch(
    err_http("Token request failed", response),
    error = identity
  )
  expect_match(conditionMessage(error), "private detail", fixed = TRUE)
  for (text in c("bad\r\ntext", "bad\ttext", 'bad"text', "bad\\text", "é")) {
    expect_false(is_oauth_error_text(text))
    expect_error(
      validate_untrusted_query_param("error_description", text, 4096),
      "printable ASCII"
    )
  }
  expect_true(is_oauth_error_text("The request was denied."))
})

test_that("sink failures withhold details by default and sanitize opt-in warnings", {
  local_options(
    shinyOAuth.expose_error_body = FALSE,
    shinyOAuth.audit_hook = function(event) {
      stop("{dsn}\r\nhttps://u:password@example.test/?secret")
    }
  )
  expect_warning(emit_trace_event(list(type = "error")), "details withheld")
  local_options(shinyOAuth.expose_error_body = TRUE)
  observed <- NULL
  withCallingHandlers(
    emit_trace_event(list(type = "error")),
    warning = function(w) {
      observed <<- conditionMessage(w)
      invokeRestart("muffleWarning")
    }
  )
  expect_false(grepl("password|secret", observed))
  expect_match(observed, "{dsn}", fixed = TRUE)
})

test_that("module callback descriptions are omitted unless explicitly exposed", {
  local_options(shinyOAuth.skip_browser_token = TRUE)
  for (expose in c(FALSE, TRUE)) {
    local_options(shinyOAuth.expose_error_body = expose)
    shiny::testServer(
      oauth_module_server,
      args = list(
        id = "auth",
        client = make_test_client(),
        auto_redirect = FALSE
      ),
      {
        url <- values[["build_auth_url"]]()
        state <- parse_query_param(url, "state")
        values[[".process_query"]](paste0(
          "?error=access_denied&error_description=Private%20detail&state=",
          state
        ))
        session$flushReact()
        expect_identical(values[["error"]], "access_denied")
        if (expose) {
          expect_identical(values[["error_description"]], "Private detail")
        } else {
          expect_null(values[["error_description"]])
        }
      }
    )
  }
})

test_that("direct OTel log bodies apply diagnostic exposure policy", {
  local_options(
    shinyOAuth.otel_logging_enabled = TRUE,
    shinyOAuth.expose_error_body = FALSE
  )
  seen <- NULL
  local_mocked_bindings(
    log = function(msg, ...) {
      seen <<- msg
    },
    .package = "otel"
  )
  event <- list(
    type = "error",
    message = "Detail\r\nhttps://u:password@example.test/?secret#private"
  )
  otel_emit_log(event)
  expect_identical(seen, "error")
  local_options(shinyOAuth.expose_error_body = TRUE)
  otel_emit_log(event)
  expect_match(seen, "Detail", fixed = TRUE)
  expect_false(grepl("[\r\n]|password|secret|private", seen))
})
