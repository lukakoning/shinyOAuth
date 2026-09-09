test_that("claim conditions redact values and bound explicitly exposed details", {
  local_options(shinyOAuth.telemetry_path_scrubber = NULL)
  expected <- "https://expected.example.test/private-expected?query-secret"
  received <- "https://received.example.test/private-received?query-secret"
  client_id <- "private-expected-client"
  received_audience <- paste0(
    "private-received-client-{literal}",
    strrep("é", 600)
  )
  for (expose in c(FALSE, TRUE)) {
    local_options(shinyOAuth.expose_error_body = expose)
    for (claim in c("iss", "aud")) {
      claims <- list(sub = "user-1", iss = expected, aud = client_id)
      claims[[claim]] <- if (claim == "iss") received else received_audience
      error <- tryCatch(
        validate_signed_userinfo_claims(claims, expected, client_id),
        error = identity
      )
      expect_s3_class(error, "shinyOAuth_userinfo_error")
      expect_identical(error$context$claim, claim)
      expect_match(error$context$expected_claim_digest, "^[a-f0-9]{64}$")
      expect_false(identical(
        error$context$expected_claim_digest,
        error$context$received_claim_digest
      ))
      message <- conditionMessage(error)
      expect_false(grepl(
        "private-expected\\?|private-received\\?|query-secret",
        message
      ))
      expect_lt(nchar(message, type = "bytes"), 1500)
      if (expose) {
        expect_match(
          message,
          if (claim == "iss") "received.example.test" else "{literal}",
          fixed = TRUE
        )
      } else {
        expect_false(grepl(
          "private-|expected.example|received.example",
          message
        ))
      }
    }
  }
})

test_that("required ACR conditions apply the diagnostic exposure policy", {
  client <- oauth_client(
    oauth_provider(
      name = "acr",
      auth_url = "https://example.test/auth",
      token_url = "https://example.test/token",
      issuer = "https://example.test",
      use_nonce = FALSE,
      userinfo_required = FALSE
    ),
    client_id = "client",
    client_secret = "secret",
    redirect_uri = "http://localhost:8100",
    scopes = "openid",
    scope_validation = "none",
    required_acr_values = c("private-expected-acr", "private-alternative-acr")
  )
  key <- openssl::rsa_keygen()
  jwk <- jsonlite::fromJSON(write_test_jwk(key$pubkey), simplifyVector = FALSE)
  local_mocked_bindings(fetch_jwks = function(...) list(keys = list(jwk)))
  for (expose in c(FALSE, TRUE)) {
    local_options(shinyOAuth.expose_error_body = expose)
    for (acr in list(NULL, "private-received-acr-{literal}")) {
      claims <- jose::jwt_claim(
        iss = "https://example.test",
        aud = "client",
        sub = "user-1",
        iat = as.numeric(Sys.time()) - 10,
        exp = as.numeric(Sys.time()) + 300
      )
      claims[["acr"]] <- acr
      jwt <- jose::jwt_encode_sig(claims, key = key)
      error <- tryCatch(
        verify_token_set(
          client,
          list(
            access_token = "test-access",
            token_type = "Bearer",
            expires_in = 300,
            id_token = jwt
          ),
          nonce = NULL
        ),
        error = identity
      )
      expect_s3_class(error, "shinyOAuth_id_token_error")
      expect_identical(error$context$claim, "acr")
      expect_match(error$context$expected_claim_digest, "^[a-f0-9]{64}$")
      if (expose) {
        expect_match(
          conditionMessage(error),
          "private-expected-acr",
          fixed = TRUE
        )
        if (!is.null(acr)) {
          expect_match(conditionMessage(error), acr, fixed = TRUE)
        }
      } else {
        expect_false(grepl("private-", conditionMessage(error)))
      }
    }
  }
})

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

test_that("JWKS metadata failure redacts the producer's event and condition", {
  issuer <- "https://example.test/private-tenant"
  detail <- "diagnostic-marker https://example.test/private-tenant?query-marker"
  seen <- list()
  local_options(
    shinyOAuth.expose_error_body = FALSE,
    shinyOAuth.telemetry_path_scrubber = NULL,
    shinyOAuth.audit_hook = function(event) {
      seen[[length(seen) + 1L]] <<- event
    }
  )
  local_mocked_bindings(
    req_with_retry = function(...) stop(simpleError(detail)),
    .package = "shinyOAuth"
  )
  error <- tryCatch(
    fetch_authorization_server_metadata(issuer),
    error = identity
  )
  expect_s3_class(error, "shinyOAuth_config_error")
  expect_length(error$context$attempted_metadata_urls, 3L)
  expect_true(all(
    error$context$attempted_metadata_urls == "https://example.test/"
  ))
  expect_null(error$context$metadata_error)
  expect_false(any(grepl(
    "private-tenant|query-marker|diagnostic-marker",
    c(
      conditionMessage(error),
      capture.output(print(error)),
      unlist(error$context),
      unlist(seen)
    )
  )))
  local_options(shinyOAuth.expose_error_body = TRUE)
  error <- tryCatch(
    fetch_authorization_server_metadata(issuer),
    error = identity
  )
  expect_match(conditionMessage(error), "diagnostic-marker", fixed = TRUE)
  expect_false(grepl("private-tenant|query-marker", conditionMessage(error)))
})

test_that("redirect conditions omit identifying Location content", {
  local_options(
    shinyOAuth.allow_redirect = FALSE,
    shinyOAuth.telemetry_path_scrubber = NULL
  )
  for (location in c(
    "https://example.test/private-tenant?query-marker#fragment-marker",
    "/private-tenant?query-marker",
    ""
  )) {
    resp <- httr2::response(
      status_code = 302L,
      headers = list(location = location)
    )
    error <- tryCatch(reject_redirect_response(resp), error = identity)
    expect_s3_class(error, "shinyOAuth_http_error")
    expect_false(grepl(
      "private-tenant|query-marker|fragment-marker",
      conditionMessage(error)
    ))
  }
})

test_that("transport conditions retain classification without raw parent data", {
  url <- "https://example.test/private-tenant?query-marker"
  detail <- paste("diagnostic-marker", url)
  req <- httr2::request(url)
  local_mocked_bindings(
    req_perform = function(...) {
      rlang::abort(
        detail,
        class = "test_connection_error",
        request = req,
        parent = simpleError(detail)
      )
    },
    .package = "httr2"
  )
  local_options(
    shinyOAuth.expose_error_body = FALSE,
    shinyOAuth.telemetry_path_scrubber = NULL
  )
  error <- tryCatch(req_with_retry(req, idempotent = FALSE), error = identity)
  expect_s3_class(error, "shinyOAuth_transport_error")
  expect_s3_class(error$parent, "test_connection_error")
  expect_null(error$parent$request)
  expect_null(error$parent$parent)
  expect_null(error$parent$call)
  expect_null(error$parent$trace)
  expect_identical(error$context$url, "https://example.test/")
  expect_false(any(grepl(
    "private-tenant|query-marker|diagnostic-marker",
    c(
      conditionMessage(error),
      capture.output(print(error)),
      unlist(error$context),
      unlist(error$parent)
    )
  )))
})
