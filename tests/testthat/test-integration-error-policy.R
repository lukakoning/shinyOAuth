test_that("integration defaults preserve redaction and structured HTTP diagnostics", {
  helper <- test_path(
    "..",
    "..",
    "integration",
    "keycloak",
    "helper-keycloak.R"
  )
  skip_if_not(
    file.exists(helper),
    "Integration helpers are not shipped in the package"
  )
  integration <- new.env(parent = environment())
  sys.source(helper, envir = integration)
  integration$local_test_options()
  expect_false(allow_expose_error_body())
  audit <- integration$local_keycloak_audit_events()
  response <- httr2::response(
    url = "https://example.test/par",
    status = 401L,
    headers = list("content-type" = "application/json"),
    body = charToRaw(
      '{"error":"invalid_client","error_description":"private-provider-diagnostic"}'
    )
  )
  error <- tryCatch(err_http("PAR failed", response), error = identity)
  expect_s3_class(error, "shinyOAuth_http_error")
  expect_identical(error$status, 401L)
  expect_identical(error$oauth_error, "invalid_client")
  expect_null(error$oauth_error_description)
  expect_match(oauth_module_compose_error(error), "^HTTP request failed")
  expect_no_match(
    oauth_module_compose_error(error),
    "private-provider-diagnostic"
  )
  event <- Filter(
    function(event) identical(event$type, "http_error"),
    audit$events
  )[[1L]]
  expect_identical(event$status, 401L)
  expect_identical(event$oauth_error, "invalid_client")
  expect_null(event$oauth_error_description)

  # Diagnostics tests may opt in locally; the shared harness never does so.
  withr::with_options(list(shinyOAuth.expose_error_body = TRUE), {
    error <- tryCatch(err_http("PAR failed", response), error = identity)
    expect_identical(
      error$oauth_error_description,
      "private-provider-diagnostic"
    )
  })
  expect_false(allow_expose_error_body())
})

test_that("module callback failures keep stable codes without internal descriptions", {
  withr::local_options(list(shinyOAuth.expose_error_body = FALSE))
  events <- list()
  withr::local_options(shinyOAuth.audit_hook = function(event) {
    events[[length(events) + 1L]] <<- event
  })
  for (class in c("shinyOAuth_state_error", "shinyOAuth_id_token_error")) {
    error <- tryCatch(
      err_abort("private-validation-detail", class = class),
      error = identity
    )
    expect_identical(
      oauth_module_callback_failure_error_code(error),
      if (class == "shinyOAuth_state_error") {
        "invalid_state"
      } else {
        "token_exchange_error"
      }
    )
    expect_no_match(
      oauth_module_compose_error(error),
      "private-validation-detail"
    )
    expect_match(
      oauth_module_compose_error(error),
      if (class == "shinyOAuth_state_error") {
        "^Invalid OAuth state"
      } else {
        "^ID token error"
      }
    )
    expect_identical(tail(events, 1L)[[1L]]$error_class, class)
  }
})
