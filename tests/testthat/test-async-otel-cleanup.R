test_that("async worker outcomes are recorded before restoring telemetry settings", {
  skip_if_not_installed("promises")
  skip_if_not_installed("future")
  local_options(shinyOAuth.otel_tracing_enabled = TRUE)
  withr::local_envvar(OTEL_SERVICE_NAME = "parent-service")

  for (prior_gate in c(TRUE, FALSE)) {
    for (outcome in c("success", "error", "http_failure")) {
      recorded <- new.env(parent = emptyenv())
      recorded[["attributes"]] <- list()
      recorded[["events"]] <- list()
      recorded[["ended"]] <- 0L
      span <- list(
        set_status = function(status, ...) {
          recorded[["status"]] <- status
        },
        set_attribute = function(key, value) {
          recorded[["attributes"]][[key]] <- value
        },
        add_event = function(name, ...) {
          recorded[["events"]][[name]] <- TRUE
        },
        end = function(...) {
          recorded[["ended"]] <- recorded[["ended"]] + 1L
          recorded[["gate_at_end"]] <- getOption("shinyOAuth.otel_tracing_enabled")
          recorded[["service_at_end"]] <- Sys.getenv("OTEL_SERVICE_NAME")
        }
      )
      # Evaluate the actual dispatched expression in a worker-like function so
      # its on.exit handlers run, while keeping the transport deterministic.
      run_worker <- function(expr, envir, ...) {
        local_options(shinyOAuth.otel_tracing_enabled = prior_gate)
        withr::local_envvar(OTEL_SERVICE_NAME = "worker-service")
        evaluate <- as.function(c(alist(), list(expr)), envir = envir)
        answer <- tryCatch(evaluate(), error = identity)
        recorded[["restored_gate"]] <- getOption("shinyOAuth.otel_tracing_enabled")
        recorded[["restored_service"]] <- Sys.getenv("OTEL_SERVICE_NAME")
        answer
      }
      expression <- switch(
        outcome,
        success = quote(42),
        error = quote(stop("controlled worker failure")),
        http_failure = quote(list(status = "http_403", supported = TRUE))
      )
      result <- with_mocked_bindings(
        mirai_daemons_active = function() FALSE,
        reset_async_otel_cache = function(...) TRUE,
        otel_restore_parent_in_worker = function(...) span,
        otel_with_active_span = function(span, code) force(code),
        .package = "shinyOAuth",
        with_mocked_bindings(
          nbrOfWorkers = function() 1L,
          .package = "future",
          with_mocked_bindings(
            future_promise = run_worker,
            .package = "promises",
            async_dispatch(
              expression,
              list(),
              otel_context = list(
                headers = list(),
                token_operation_result = outcome == "http_failure"
              )
            )
          )
        )
      )
      expect_identical(recorded[["status"]], if (outcome == "success") "ok" else "error")
      expect_identical(recorded[["ended"]], 1L)
      expect_true(recorded[["gate_at_end"]])
      expect_identical(recorded[["service_at_end"]], "parent-service")
      expect_identical(recorded[["restored_gate"]], prior_gate)
      expect_identical(recorded[["restored_service"]], "worker-service")
      if (outcome == "error") {
        expect_s3_class(result, "error")
        expect_identical(recorded[["attributes"]][["error.type"]], "simpleError")
        expect_true(recorded[["events"]][["exception"]])
      } else {
        expect_true(result[[".shinyOAuth_async_wrapped"]])
        if (outcome == "http_failure") {
          expect_identical(recorded[["attributes"]][["oauth.status"]], "http_403")
          expect_identical(recorded[["attributes"]][["error.type"]], "http_403")
        } else {
          expect_identical(result[["value"]], 42)
        }
      }
    }
  }
})
