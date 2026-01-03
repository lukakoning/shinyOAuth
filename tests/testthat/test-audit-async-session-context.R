testthat::test_that("audit events from async worker include shiny session token", {
  testthat::skip_on_cran()
  testthat::skip_if_not_installed("promises")
  testthat::skip_if_not_installed("future")
  testthat::skip_if_not_installed("later")

  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))

  # Use in-process futures so mocks apply within future_promise
  old_plan <- NULL
  old_plan <- tryCatch(future::plan(), error = function(...) NULL)
  try(future::plan(future::sequential), silent = TRUE)
  withr::defer({
    if (!is.null(old_plan)) try(future::plan(old_plan), silent = TRUE)
  })

  # Capture audit events via the audit hook
  audit_events <- list()
  withr::local_options(list(
    shinyOAuth.audit_hook = function(event) {
      audit_events <<- c(audit_events, list(event))
    }
  ))

  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)

  shiny::testServer(
    app = oauth_module_server,
    args = list(
      id = "auth",
      client = cli,
      auto_redirect = FALSE,
      async = TRUE,
      indefinite_session = TRUE
    ),
    expr = {
      testthat::expect_true(values$has_browser_token())

      expected_session_token <- .scalar_chr(session$token)
      testthat::expect_true(
        is.character(expected_session_token) && nzchar(expected_session_token)
      )

      # Build the authorization URL and capture encoded state
      url <- values$build_auth_url()
      enc <- parse_query_param(url, "state")
      testthat::expect_true(is.character(enc) && nzchar(enc))

      # Mock token exchange to avoid HTTP
      testthat::with_mocked_bindings(
        swap_code_for_token_set = function(
          client,
          code,
          code_verifier,
          shiny_session = NULL
        ) {
          list(access_token = "t-async-audit", expires_in = 3600)
        },
        .package = "shinyOAuth",
        {
          values$.process_query(paste0("?code=ok&state=", enc))

          # Allow promise handlers to run
          deadline <- Sys.time() + 3
          while (is.null(values$token) && Sys.time() < deadline) {
            later::run_now(0.05)
            session$flushReact()
            Sys.sleep(0.01)
          }
        }
      )

      # Wait a bit for audit hook events to arrive
      deadline <- Sys.time() + 3
      while (length(audit_events) == 0 && Sys.time() < deadline) {
        later::run_now(0.05)
        session$flushReact()
        Sys.sleep(0.01)
      }

      testthat::expect_true(length(audit_events) > 0)

      # At least one audit event should include the originating shiny session token.
      seen_tokens <- vapply(
        audit_events,
        function(e) {
          (e$shiny_session %||% list())$token %||% NA_character_
        },
        character(1)
      )

      testthat::expect_true(any(
        !is.na(seen_tokens) & seen_tokens == expected_session_token
      ))
    }
  )
})
