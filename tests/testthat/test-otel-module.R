testthat::test_that("oauth_module_server activates the session span before prepare_call", {
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))

  active_span <- NULL
  session_span <- list(
    add_event = function(...) invisible(NULL),
    end = function(...) invisible(NULL)
  )

  testthat::with_mocked_bindings(
    is_otel_tracing = function() TRUE,
    otel_active_sessions = function(...) invisible(NULL),
    .package = "shinyOAuth",
    {
      testthat::local_mocked_bindings(
        start_span = function(name, ...) {
          testthat::expect_equal(name, "shiny_session")
          session_span
        },
        local_active_span = function(span, ...) {
          active_span <<- span
          invisible(span)
        },
        as_attributes = function(x) x,
        .package = "otel"
      )

      shiny::testServer(
        app = shinyOAuth::oauth_module_server,
        args = list(
          id = "auth",
          client = make_test_client(use_pkce = TRUE, use_nonce = FALSE),
          auto_redirect = FALSE,
          async = FALSE
        ),
        expr = {
          url <- testthat::with_mocked_bindings(
            prepare_call = function(...) {
              testthat::expect_identical(active_span, session_span)
              "https://example.com/auth?state=test"
            },
            .package = "shinyOAuth",
            {
              values$build_auth_url()
            }
          )

          testthat::expect_equal(url, "https://example.com/auth?state=test")
        }
      )
    }
  )
})

testthat::test_that("async callback fallback ends the manual callback span on success", {
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))

  callback_status <- NULL
  session_span <- list(
    add_event = function(...) invisible(NULL),
    end = function(...) invisible(NULL)
  )
  callback_span <- list(
    add_event = function(...) invisible(NULL),
    record_exception = function(...) invisible(NULL),
    end = function(status_code = NULL) {
      callback_status <<- status_code
      invisible(NULL)
    }
  )

  testthat::with_mocked_bindings(
    is_otel_tracing = function() TRUE,
    otel_active_sessions = function(...) invisible(NULL),
    otel_count_login = function(...) invisible(NULL),
    capture_async_options = function() list(),
    capture_shiny_session_context = function() NULL,
    state_payload_decrypt_validate = function(...) list(state = "worker-state"),
    state_store_get_remove = function(...) list(
      browser_token = "__SKIPPED__",
      pkce_code_verifier = NULL,
      nonce = NULL
    ),
    prepare_client_for_worker = function(...) NULL,
    handle_callback_internal = function(...) structure(
      list(access_token = "tok"),
      class = "mock_token"
    ),
    .package = "shinyOAuth",
    {
      testthat::local_mocked_bindings(
        start_span = function(name, ...) {
          if (identical(name, "shiny_session")) {
            return(session_span)
          }
          if (identical(name, "handle_callback")) {
            return(callback_span)
          }
          testthat::fail(paste("unexpected span", name))
        },
        local_active_span = function(span, ...) invisible(span),
        as_attributes = function(x) x,
        .package = "otel"
      )

      shiny::testServer(
        app = shinyOAuth::oauth_module_server,
        args = list(
          id = "auth",
          client = make_test_client(use_pkce = TRUE, use_nonce = FALSE),
          auto_redirect = FALSE,
          async = TRUE
        ),
        expr = {
          testthat::expect_warning(
            values$.process_query("?code=ok&state=test"),
            class = "shinyOAuth_async_serialization_fallback"
          )
          session$flushReact()

          testthat::expect_identical(callback_status, "ok")
          testthat::expect_false(is.null(values$token))
        }
      )
    }
  )
})

testthat::test_that("async callback pre-dispatch errors end the manual callback span with error", {
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))

  callback_status <- NULL
  recorded_exception <- NULL
  session_span <- list(
    add_event = function(...) invisible(NULL),
    end = function(...) invisible(NULL)
  )
  callback_span <- list(
    add_event = function(...) invisible(NULL),
    record_exception = function(error, ...) {
      recorded_exception <<- error
      invisible(NULL)
    },
    end = function(status_code = NULL) {
      callback_status <<- status_code
      invisible(NULL)
    }
  )

  testthat::with_mocked_bindings(
    is_otel_tracing = function() TRUE,
    otel_active_sessions = function(...) invisible(NULL),
    otel_count_login = function(...) invisible(NULL),
    capture_async_options = function() list(),
    capture_shiny_session_context = function() NULL,
    state_payload_decrypt_validate = function(...) stop("boom"),
    .package = "shinyOAuth",
    {
      testthat::local_mocked_bindings(
        start_span = function(name, ...) {
          if (identical(name, "shiny_session")) {
            return(session_span)
          }
          if (identical(name, "handle_callback")) {
            return(callback_span)
          }
          testthat::fail(paste("unexpected span", name))
        },
        local_active_span = function(span, ...) invisible(span),
        as_attributes = function(x) x,
        .package = "otel"
      )

      shiny::testServer(
        app = shinyOAuth::oauth_module_server,
        args = list(
          id = "auth",
          client = make_test_client(use_pkce = TRUE, use_nonce = FALSE),
          auto_redirect = FALSE,
          async = TRUE
        ),
        expr = {
          values$.process_query("?code=ok&state=test")
          session$flushReact()

          testthat::expect_identical(callback_status, "error")
          testthat::expect_s3_class(recorded_exception, "condition")
          testthat::expect_identical(values$error, "token_exchange_error")
        }
      )
    }
  )
})
