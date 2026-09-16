test_that("token telemetry exports only recognized canonical schemes", {
  for (value in list(
    "secret",
    "Bearer\n",
    strrep("x", 5000),
    1,
    list("Bearer"),
    NA
  )) {
    expect_identical(
      otel_token_response_attributes(list(token_type = value))[[
        "oauth.token_type"
      ]],
      "unknown"
    )
  }
  expect_identical(otel_token_type_attribute("bEaReR"), "Bearer")
  expect_identical(otel_token_type_attribute("dpop"), "DPoP")
  expect_null(otel_token_type_attribute(NULL))
})

test_that("rejected exchanges and refreshes never export raw token types", {
  skip_if_not_installed("otelsdk")
  reset_test_otel_cache()
  withr::defer(reset_test_otel_cache())
  events <- list()
  local_options(
    shinyOAuth.expose_error_body = FALSE,
    shinyOAuth.otel_tracing_enabled = TRUE,
    shinyOAuth.audit_hook = function(event) {
      events[[length(events) + 1L]] <<- event
    }
  )
  client <- make_test_client()
  client@provider@allowed_token_types <- "Bearer"
  untrusted <- paste0("secret-marker\n", strrep("x", 5000L))
  local_mocked_bindings(req_with_dpop_retry = function(req, ...) {
    httr2::response(
      url = req[["url"]],
      status_code = 200L,
      headers = list("content-type" = "application/json"),
      body = charToRaw(jsonlite::toJSON(
        list(
          access_token = "synthetic-access",
          token_type = untrusted,
          expires_in = 60
        ),
        auto_unbox = TRUE
      ))
    )
  })
  for (operation in c("exchange", "refresh")) {
    log_file <- local_test_otel_log_file()
    browser <- valid_browser_token()
    state <- parse_query_param(prepare_call(client, browser), "state")
    record <- otelsdk::with_otel_record({
      tryCatch(
        if (operation == "exchange") {
          handle_callback(client, "code", state, browser_token = browser)
        } else {
          refresh_token(
            client,
            OAuthToken(
              access_token = "old-access",
              refresh_token = "old-refresh"
            )
          )
        },
        error = identity
      )
    })
    expect_s3_class(record[["value"]], "shinyOAuth_token_error")
    types <- unlist(lapply(record[["traces"]], function(span) {
      as.list(span[["attributes"]])[["oauth.token_type"]]
    }))
    expect_gt(length(types), 0L)
    expect_true(all(types == "unknown"))
    expect_true(file.exists(log_file))
    logs <- readLines(log_file, warn = FALSE)
    expect_true(any(grepl("shinyOAuth_token_error", logs, fixed = TRUE)))
    surfaces <- list(
      record[["traces"]],
      logs,
      events,
      conditionMessage(record[["value"]]),
      record[["value"]][["context"]]
    )
    expect_false(any(grepl("secret-marker", unlist(surfaces), fixed = TRUE)))
  }
})
