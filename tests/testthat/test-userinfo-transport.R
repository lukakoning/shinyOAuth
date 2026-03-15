testthat::test_that("get_userinfo preserves transport errors", {
  source(testthat::test_path("helper-login.R"), local = TRUE)

  cli <- make_test_client()
  cli@provider@userinfo_url <- "https://example.com/userinfo"

  events <- list()
  old_opts <- options(
    shinyOAuth.audit_hook = function(event) {
      events[[length(events) + 1L]] <<- event
    },
    shinyOAuth.otel_logging_enabled = FALSE,
    shinyOAuth.otel_tracing_enabled = FALSE,
    shinyOAuth.retry_max_tries = 1L
  )
  on.exit(options(old_opts), add = TRUE)

  err <- testthat::with_mocked_bindings(
    req_perform = function(request) {
      stop("network down")
    },
    .package = "httr2",
    {
      tryCatch(shinyOAuth::get_userinfo(cli, token = "at"), error = identity)
    }
  )

  testthat::expect_true(inherits(err, "shinyOAuth_transport_error"))
  testthat::expect_false(inherits(err, "shinyOAuth_userinfo_error"))

  types <- vapply(events, function(event) event$type %||% "", character(1))
  testthat::expect_true("transport_error" %in% types)
  testthat::expect_false("audit_userinfo" %in% types)
})
