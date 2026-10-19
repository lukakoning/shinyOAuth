test_that("real HTTP requests keep private URLs out of every telemetry scope", {
  skip_if_not_installed("callr")
  skip_if_not_installed("otelsdk")
  skip_if_not_installed("webfakes")
  skip_on_cran()

  app <- webfakes::new_app()
  app[["get"]]("/Patient/synthetic-private-patient", function(req, res) {
    res[["set_type"]]("application/json")[["send"]](jsonlite::toJSON(list(
      authorization = req[["get_header"]]("authorization"),
      identifier = req[["query"]][["identifier"]],
      traceparent = req[["get_header"]]("traceparent")
    ), auto_unbox = TRUE, null = "null"))
  })
  app[["get"]]("/ordinary", function(req, res) res[["send"]]("ok"))
  app[["get"]]("/Patient/synthetic-private-large", function(req, res) {
    res[["send"]](paste(rep("x", 2048L), collapse = ""))
  })
  srv <- webfakes::local_app_process(app)
  package_path <- getNamespaceInfo(asNamespace("shinyOAuth"), "path")
  installed <- file.exists(file.path(package_path, "Meta", "package.rds"))

  result <- callr::r(
    function(base, package_path, installed) {
      # The SDK must be active BEFORE httr2 is imported: it caches its tracer.
      stopifnot(!isNamespaceLoaded("httr2"))
      Sys.unsetenv(c("OTEL_R_EMIT_SCOPES", "OTEL_R_SUPPRESS_SCOPES"))
      record <- otelsdk::with_otel_record({
        stopifnot(!isNamespaceLoaded("httr2"))
        if (installed) {
          loadNamespace("shinyOAuth", lib.loc = dirname(package_path))
        } else {
          pkgload::load_all(package_path, quiet = TRUE, helpers = FALSE)
        }
        options(
          shinyOAuth.otel_logging_enabled = FALSE,
          shinyOAuth.expose_error_body = FALSE,
          shinyOAuth.retry_max_tries = 1L,
          shinyOAuth.telemetry_path_scrubber = NULL
        )
        perform <- httr2::req_perform
        ordinary <- httr2::req_timeout(
          httr2::request(paste0(base, "/ordinary")), 5
        )
        httr2::req_perform(ordinary)
        private_url <- paste0(base, "/Patient/synthetic-private-patient")
        responses <- list()
        for (enabled in c(FALSE, TRUE)) {
          options(shinyOAuth.otel_tracing_enabled = enabled)
          responses[[as.character(enabled)]] <- shinyOAuth:::with_otel_span(
            "private.request",
            shinyOAuth::perform_resource_req(
              "synthetic-access-token", private_url,
              query = list(identifier = "synthetic-private-identifier"),
              resource_hosts = "127.0.0.1"
            ),
            attributes = shinyOAuth:::otel_http_attributes(
              method = "GET", url = private_url
            )
          )
        }
        options(shinyOAuth.telemetry_path_scrubber = function(path) {
          "/Patient/:id"
        })
        shinyOAuth:::with_otel_span(
          "approved.route",
          shinyOAuth::perform_resource_req(
            "synthetic-access-token", private_url,
            query = list(identifier = "synthetic-private-identifier"),
            resource_hosts = "127.0.0.1"
          ),
          attributes = shinyOAuth:::otel_http_attributes(
            method = "GET", url = private_url
          )
        )
        options(shinyOAuth.max_body_bytes = 1024L)
        failure <- tryCatch(
          shinyOAuth::perform_resource_req(
            "synthetic-access-token",
            paste0(base, "/Patient/synthetic-private-large"),
            resource_hosts = "127.0.0.1"
          ),
          error = identity
        )
        # Ordinary app requests still use httr2's own instrumentation after
        # both successful requests and a transport/body-limit failure.
        httr2::req_perform(ordinary)
        list(
          wire = lapply(responses, httr2::resp_body_json),
          failure = class(failure),
          perform_unchanged = identical(perform, httr2::req_perform)
        )
      })
      record
    },
    args = list(sub("/$", "", srv[["url"]]()), package_path, installed),
    libpath = if (installed) c(dirname(package_path), .libPaths()) else .libPaths(),
    timeout = 60,
    spinner = FALSE
  )

  traces <- result[["traces"]]
  exported <- paste(capture.output(str(traces, max.level = 20)), collapse = "\n")
  expect_false(grepl("synthetic-private-", exported, fixed = TRUE))
  expect_false(grepl("synthetic-access-token", exported, fixed = TRUE))
  expect_true(result[["value"]][["perform_unchanged"]])
  expect_contains(result[["value"]][["failure"]], "shinyOAuth_parse_error")
  for (wire in result[["value"]][["wire"]]) {
    expect_identical(wire[["authorization"]], "Bearer synthetic-access-token")
    expect_identical(wire[["identifier"]], "synthetic-private-identifier")
  }
  expect_null(result[["value"]][["wire"]][["FALSE"]][["traceparent"]])
  expect_length(Filter(function(span) {
    identical(span[["name"]], "private.request")
  }, traces), 1L)
  expect_identical(
    traces[["private.request"]][["attributes"]][["url.full"]],
    paste0(sub("/$", "", srv[["url"]]()), "/")
  )
  expect_identical(
    traces[["approved.route"]][["attributes"]][["url.full"]],
    paste0(sub("/$", "", srv[["url"]]()), "/Patient/:id")
  )
  if (utils::packageVersion("httr2") >= "1.2.2") {
    expect_identical(
      result[["value"]][["wire"]][["TRUE"]][["traceparent"]],
      paste0(
        "00-", traces[["private.request"]][["trace_id"]], "-",
        traces[["private.request"]][["span_id"]], "-01"
      )
    )
    dependency_spans <- Filter(function(span) {
      identical(span[["instrumentation_scope"]][["name"]], "org.r-lib.httr2")
    }, traces)
    expect_length(dependency_spans, 2L)
    expect_true(all(vapply(dependency_spans, function(span) {
      endsWith(span[["attributes"]][["url.full"]], "/ordinary")
    }, logical(1))))
  }
})

test_that("unknown httr2 instrumentation layouts fail before sending HTTP", {
  skip_if(utils::packageVersion("httr2") < "1.2.2")
  testthat::local_mocked_bindings(
    req_perform1 = function(...) stop("HTTP must not be performed"),
    .package = "httr2"
  )
  expect_error(
    shinyOAuth:::req_perform_without_auto_trace(httr2::request("https://example.test")),
    "cannot protect URL privacy",
    class = "shinyOAuth_config_error"
  )
})
