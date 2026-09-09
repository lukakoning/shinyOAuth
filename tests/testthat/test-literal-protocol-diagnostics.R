test_that("condition boundaries preserve literal braces in messages and nested errors", {
  detail <- "Received {.strong literal-label} and {literal}"
  error <- tryCatch(err_parse(detail), error = identity)
  expect_s3_class(error, "shinyOAuth_parse_error")
  expect_match(conditionMessage(error), detail, fixed = TRUE)
  nested <- tryCatch(rethrow_with_context(error), error = identity)
  expect_match(conditionMessage(nested), detail, fixed = TRUE)
  warning <- rlang::catch_cnd(warn_pkg(detail, detail), classes = "warning")
  expect_match(conditionMessage(warning), detail, fixed = TRUE)
  message <- rlang::catch_cnd(inform_pkg(detail, detail), classes = "message")
  expect_match(conditionMessage(message), detail, fixed = TRUE)
})

test_that("received protocol diagnostics are literal and respect exposure", {
  marker <- "{.strong literal-label}"
  json <- paste0('{"', marker, '":1,"', marker, '":2}')
  form_name <- utils::URLencode(marker, reserved = TRUE)
  cases <- list(
    list(
      run = function() reject_duplicate_json_object_members(json, "JWT header"),
      class = "shinyOAuth_parse_error"
    ),
    list(
      run = function() {
        reject_duplicate_form_encoded_members(
          paste0(form_name, "=1&", form_name, "=2"),
          "Token response"
        )
      },
      class = "shinyOAuth_parse_error"
    ),
    list(
      run = function() {
        enforce_inbound_jwt_header_policy(list(typ = marker), err_id_token)
      },
      class = "shinyOAuth_id_token_error"
    ),
    list(
      run = function() {
        enforce_inbound_jwt_header_policy(
          list(crit = marker),
          err_invalid_state
        )
      },
      class = "shinyOAuth_state_error"
    ),
    list(
      run = function() {
        validate_encrypted_jarm_protected_header(
          list(alg = "RSA-OAEP", enc = "A256CBC-HS512", cty = marker),
          list()
        )
      },
      class = "shinyOAuth_state_error"
    ),
    list(
      run = function() {
        validate_encrypted_jarm_protected_header(
          list(
            alg = "RSA-OAEP",
            enc = "A256CBC-HS512",
            cty = "JWT",
            crit = list(marker)
          ),
          list()
        )
      },
      class = "shinyOAuth_state_error"
    )
  )
  for (expose in c(FALSE, TRUE)) {
    events <- list()
    local_options(
      shinyOAuth.expose_error_body = expose,
      shinyOAuth.audit_hook = function(event) {
        events[[length(events) + 1L]] <<- event
      }
    )
    for (case in cases) {
      error <- tryCatch(case$run(), error = identity)
      expect_s3_class(error, case$class)
      expect_identical(
        grepl(marker, conditionMessage(error), fixed = TRUE),
        expose
      )
      event <- events[[length(events)]]
      expect_identical(any(grepl(marker, unlist(event), fixed = TRUE)), expose)
      expect_identical(
        any(grepl(marker, unlist(otel_event_attributes(event)), fixed = TRUE)),
        expose
      )
    }
  }
})

test_that("confirmation diagnostics hide values and reject malformed SHA-256 encodings", {
  first <- base64url_encode(openssl::sha256(charToRaw("first")))
  second <- base64url_encode(openssl::sha256(charToRaw("second")))
  for (field in c("x5t#S256", "jkt")) {
    cnf <- stats::setNames(list(first), field)
    expect_identical(normalize_token_cnf(cnf), cnf)
    for (value in list(
      NULL,
      "{.strong literal-label}",
      "",
      list(first),
      1,
      paste0(first, "="),
      strrep("A", 42),
      paste0(strrep("A", 42), "B")
    )) {
      expect_error(
        normalize_token_cnf(stats::setNames(list(value), field)),
        class = "shinyOAuth_token_error"
      )
    }
    for (expose in c(FALSE, TRUE)) {
      seen <- NULL
      local_options(
        shinyOAuth.expose_error_body = expose,
        shinyOAuth.audit_hook = function(event) seen <<- event
      )
      error <- tryCatch(
        validate_token_cnf_consistency(
          cnf = cnf,
          introspection_result = list(
            cnf = stats::setNames(list(second), field)
          )
        ),
        error = identity
      )
      expect_s3_class(error, "shinyOAuth_input_error")
      expect_match(conditionMessage(error), field, fixed = TRUE)
      expect_match(conditionMessage(error), "token_response", fixed = TRUE)
      expect_match(conditionMessage(error), "introspection", fixed = TRUE)
      for (value in c(first, second)) {
        expect_identical(
          grepl(value, conditionMessage(error), fixed = TRUE),
          expose
        )
        expect_identical(any(grepl(value, unlist(seen), fixed = TRUE)), expose)
        expect_identical(
          any(grepl(value, unlist(otel_event_attributes(seen)), fixed = TRUE)),
          expose
        )
      }
    }
  }
})
