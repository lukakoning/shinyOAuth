if (!exists("make_provider", mode = "function")) {
  source(file.path(dirname(sys.frame(1)$ofile %||% "."), "helper-keycloak.R"))
}

testthat::test_that("future multisession resolves OAuth success and failure from a worker", {
  skip_common()
  testthat::skip_on_cran()
  testthat::skip_if_not_installed("future")
  testthat::skip_if_not_installed("promises")
  testthat::skip_if_not_installed("later")

  local_test_options()

  if (rlang::is_installed("mirai")) {
    tryCatch(mirai::daemons(0), error = function(...) NULL)
  }

  old_plan <- future::plan()
  future::plan(future::multisession, workers = 2)
  withr::defer(future::plan(old_plan))

  audit_log_file <- tempfile(fileext = ".jsonl")
  withr::defer(unlink(audit_log_file), envir = parent.frame())
  audit_hook <- function(event) {
    session_context <- event[["shiny_session"]]
    if (is.list(session_context) && isTRUE(session_context[["is_async"]])) {
      cat(
        jsonlite::toJSON(
          list(
            type = event$type,
            hook_pid = Sys.getpid(),
            session = session_context,
            package_version = as.character(
              utils::packageVersion("shinyOAuth")
            )
          ),
          auto_unbox = TRUE,
          null = "null"
        ),
        "\n",
        file = audit_log_file,
        append = TRUE
      )
    }
  }
  withr::local_options(list(shinyOAuth.audit_hook = audit_hook))

  main_pid <- Sys.getpid()
  success_client <- make_public_client(make_provider())

  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(success_client, async = TRUE),
    expr = {
      url <- values$build_auth_url()
      login <- perform_login_form(
        url,
        redirect_uri = success_client@redirect_uri
      )

      values$.process_query(callback_query(login))
      deadline <- Sys.time() + 20
      while (
        (!isTRUE(values$authenticated) || is.null(values$token)) &&
          is.null(values$error) &&
          Sys.time() < deadline
      ) {
        later::run_now(0.05)
        session$flushReact()
        Sys.sleep(0.02)
      }

      testthat::expect_true(isTRUE(values$authenticated))
      testthat::expect_null(values$error)
      testthat::expect_false(is.null(values$token))
      testthat::expect_true(isTRUE(values$last_login_async_used))
    }
  )

  testthat::expect_true(file.exists(audit_log_file))
  worker_events <- lapply(
    readLines(audit_log_file, warn = FALSE),
    jsonlite::fromJSON,
    simplifyVector = FALSE
  )
  testthat::expect_gt(length(worker_events), 0L)
  worker_pids <- vapply(
    worker_events,
    function(event) as.integer(event$hook_pid),
    integer(1)
  )
  testthat::expect_true(all(worker_pids != as.integer(main_pid)))
  testthat::expect_true(all(vapply(
    worker_events,
    function(event) {
      identical(
        event$package_version,
        as.character(utils::packageVersion("shinyOAuth"))
      )
    },
    logical(1)
  )))

  failure_client <- make_public_client(make_provider())
  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(failure_client, async = TRUE),
    expr = {
      url <- values$build_auth_url()
      state <- parse_query_param(url, "state")

      values$.process_query(paste0(
        "?code=not-a-valid-code&state=",
        state,
        "&iss=",
        utils::URLencode(get_issuer(), reserved = TRUE)
      ))
      deadline <- Sys.time() + 20
      while (is.null(values$error) && Sys.time() < deadline) {
        later::run_now(0.05)
        session$flushReact()
        Sys.sleep(0.02)
      }

      testthat::expect_identical(values$error, "token_exchange_error")
      testthat::expect_false(isTRUE(values$authenticated))
      testthat::expect_null(values$token)
      testthat::expect_true(isTRUE(values$last_login_async_used))
    }
  )
})
