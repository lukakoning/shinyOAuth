test_that("single-module connections export credentials and survive refresh only", {
  local_options(shinyOAuth.skip_browser_token = TRUE)
  local_mocked_bindings(revoke_token = function(...) invisible(NULL))
  client <- make_test_client(use_nonce = FALSE)
  client@scopes <- c("read", "write")
  calls <- 0L
  local_mocked_bindings(refresh_token = function(client, token, ...) {
    calls <<- calls + 1L
    token@access_token <- paste0("fresh-", calls)
    token@expires_at <- as.numeric(Sys.time()) + 3600
    token
  })
  shiny::testServer(
    oauth_module_server,
    args = list(id = "auth", client = client, auto_redirect = FALSE),
    {
      expect_null(values[["connection"]]())
      operation <- .begin_auth_operation("login", NULL, new_epoch = TRUE)
      .accept_login_token(manager_test_token(), NULL)
      .finish_auth_operation(operation, "login")
      connection <- values[["connection"]]()
      expect_identical(connection, values[["connection"]]())
      expect_identical(connection[["access_token"]](), "synthetic-access")
      expect_identical(connection[["has_scopes"]]("write"), TRUE)
      expect_identical(connection[["has_scopes"]]("undeclared"), FALSE)
      expect_identical(
        connection[["access_token"]](force_refresh = TRUE),
        "fresh-1"
      )
      expect_identical(calls, 1L)
      expect_identical(connection, values[["connection"]]())
      values[["logout"]]()
      expect_null(values[["connection"]]())
      error <- tryCatch(connection[["access_token"]](), error = identity)
      expect_s3_class(error, "shinyOAuth_access_error")
      expect_identical(
        error[["context"]][["reason"]],
        "authorization_unavailable"
      )
      operation <- .begin_auth_operation("login", NULL, new_epoch = TRUE)
      .accept_login_token(manager_test_token(access = "second-login"), NULL)
      .finish_auth_operation(operation, "login")
      replacement <- values[["connection"]]()
      expect_identical(replacement[["access_token"]](), "second-login")
      expect_identical(
        identical(connection[["id"]], replacement[["id"]]),
        FALSE
      )
      expect_identical(connection[["has_scopes"]]("read"), FALSE)
    }
  )
})

test_that("scope checks do not require fresh tokens and acquisition is bounded", {
  local_options(shinyOAuth.skip_browser_token = TRUE)
  client <- make_test_client(use_nonce = FALSE)
  client@scopes <- c("read", "write")
  calls <- 0L
  local_mocked_bindings(refresh_token = function(client, token, ...) {
    calls <<- calls + 1L
    token@expires_at <- as.numeric(Sys.time()) + 5
    token
  })
  shiny::testServer(
    oauth_module_server,
    args = list(
      id = "auth",
      client = client,
      auto_redirect = FALSE,
      indefinite_session = TRUE
    ),
    {
      token <- manager_test_token()
      values[["token"]] <- token
      connection <- values[["connection"]]()
      token@expires_at <- as.numeric(Sys.time()) - 1
      values[["token"]] <- token
      expect_identical(connection[["has_scopes"]]("read"), TRUE)
      expect_identical(connection[["is_usable"]](), FALSE)
      error <- tryCatch(
        connection[["access_token"]](min_valid_for = 60),
        error = identity
      )
      expect_identical(error[["context"]][["reason"]], "lifetime_unavailable")
      expect_identical(calls, 1L)
      expect_identical(
        connection[["access_token"]](min_valid_for = 0),
        "synthetic-access"
      )
      token <- values[["token"]]
      token@granted_scopes <- "read"
      values[["token"]] <- token
      error <- tryCatch(
        connection[["access_token"]](required_scopes = "write"),
        error = identity
      )
      expect_identical(error[["context"]][["reason"]], "insufficient_scope")
      expect_identical(calls, 1L)
    }
  )
})

test_that("integration consumers ignore rotations but invalidate on logout", {
  local_options(shinyOAuth.skip_browser_token = TRUE)
  local_mocked_bindings(revoke_token = function(...) invisible(NULL))
  client <- make_test_client(use_nonce = FALSE)
  client@scopes <- c("read", "write")
  local_mocked_bindings(refresh_token = function(...) {
    manager_test_token(access = "first-refresh")
  })
  shiny::testServer(
    oauth_module_server,
    args = list(id = "auth", client = client, auto_redirect = FALSE),
    {
      token <- manager_test_token()
      token@expires_at <- as.numeric(Sys.time()) + 10
      values[["token"]] <- token
      reads <- 0L
      output[["records"]] <- shiny::renderText({
        connection <- shiny::req(values[["connection"]]())
        reads <<- reads + 1L
        connection[["access_token"]]()
        "records"
      })
      session[["flushReact"]]()
      expect_identical(output[["records"]], "records")
      expect_identical(reads, 1L)
      expect_identical(values[["token"]]@access_token, "first-refresh")
      baseline <- reads
      values[["token"]] <- manager_test_token(access = "rotated")
      session[["flushReact"]]()
      expect_identical(reads, baseline)
      values[["logout"]]()
      session[["flushReact"]]()
      result <- tryCatch(output[["records"]], error = identity)
      expect_s3_class(result, "shiny.silent.error")
    }
  )
})

test_that("async callers share the committed refresh and sync callers never wait", {
  skip_if_not_installed("promises")
  local_options(shinyOAuth.skip_browser_token = TRUE)
  client <- make_test_client(use_nonce = FALSE)
  client@scopes <- c("read", "write")
  resolve <- NULL
  calls <- 0L
  local_mocked_bindings(refresh_token = function(...) {
    calls <<- calls + 1L
    promises::promise(function(resolve_, reject_) resolve <<- resolve_)
  })
  shiny::testServer(
    oauth_module_server,
    args = list(id = "auth", client = client, auto_redirect = FALSE),
    {
      values[["token"]] <- manager_test_token()
      connection <- values[["connection"]]()
      first <- connection[["access_token"]](force_refresh = TRUE, async = TRUE)
      second <- connection[["access_token"]](async = TRUE)
      error <- tryCatch(connection[["access_token"]](), error = identity)
      expect_identical(error[["context"]][["reason"]], "refresh_pending")
      expect_identical(calls, 1L)
      answers <- list()
      promises::then(first, function(value) answers[["first"]] <<- value)
      promises::then(second, function(value) answers[["second"]] <<- value)
      resolve(manager_test_token(access = "committed"))
      for (i in seq_len(10)) {
        later::run_now(0)
      }
      expect_identical(answers, list(first = "committed", second = "committed"))
      expect_s3_class(connection[["access_token"]](async = TRUE), "promise")
    }
  )
})

test_that("sender-bound credentials cannot be exported as bearer strings", {
  local_options(shinyOAuth.skip_browser_token = TRUE)
  client <- make_test_client(use_nonce = FALSE)
  client@scopes <- c("read", "write")
  shiny::testServer(
    oauth_module_server,
    args = list(id = "auth", client = client, auto_redirect = FALSE),
    {
      token <- manager_test_token()
      token@cnf <- list("x5t#S256" = "synthetic-certificate")
      values[["token"]] <- token
      error <- tryCatch(
        values[["connection"]]()[["access_token"]](),
        error = identity
      )
      expect_identical(
        error[["context"]][["reason"]],
        "unsupported_token_binding"
      )
    }
  )
})

test_that("managed connections expose the same accessor and join refresh", {
  skip_if_not_installed("promises")
  f <- manager_test_fixture()
  cookie <- manager_test_cookie(f)
  resolve <- NULL
  calls <- 0L
  local_mocked_bindings(refresh_token = function(...) {
    calls <<- calls + 1L
    promises::promise(function(resolve_, reject_) resolve <<- resolve_)
  })
  shiny::testServer(
    oauth_connections_server,
    args = list(id = "health", manager = f[["manager"]]),
    session = manager_test_session(cookie),
    {
      id <- manager_test_accept(controller)
      auth <- session[["getReturned"]]()
      connection <- auth[["connection"]](id)
      expect_identical(connection, auth[["connection"]](id))
      expect_identical(
        connection[["access_token"]](required_scopes = "write"),
        "synthetic-access"
      )
      first <- connection[["access_token"]](force_refresh = TRUE, async = TRUE)
      second <- connection[["access_token"]](async = TRUE)
      expect_identical(calls, 1L)
      answers <- list()
      promises::then(first, function(x) answers[["a"]] <<- x)
      promises::then(second, function(x) answers[["b"]] <<- x)
      resolve(manager_test_token(access = "managed-fresh"))
      for (i in seq_len(10)) {
        later::run_now(0)
      }
      expect_identical(answers, list(a = "managed-fresh", b = "managed-fresh"))
      auth[["disconnect"]](id, revoke = FALSE)
      error <- tryCatch(connection[["access_token"]](), error = identity)
      expect_identical(
        error[["context"]][["reason"]],
        "authorization_unavailable"
      )
    }
  )
})

test_that("token export never escapes its original session or late logout", {
  skip_if_not_installed("promises")
  local_options(shinyOAuth.skip_browser_token = TRUE)
  local_mocked_bindings(revoke_token = function(...) invisible(NULL))
  client <- make_test_client(use_nonce = FALSE)
  client@scopes <- c("read", "write")
  resolve <- NULL
  local_mocked_bindings(refresh_token = function(...) {
    promises::promise(function(resolve_, reject_) resolve <<- resolve_)
  })
  foreign <- shiny::MockShinySession[["new"]]()
  withr::defer(foreign[["close"]]())
  held <- NULL
  shiny::testServer(
    oauth_module_server,
    args = list(id = "auth", client = client, auto_redirect = FALSE),
    {
      values[["token"]] <- manager_test_token()
      connection <- values[["connection"]]()
      held <<- connection
      error <- shiny::withReactiveDomain(
        foreign,
        tryCatch(connection[["access_token"]](), error = identity)
      )
      expect_identical(
        error[["context"]][["reason"]],
        "authorization_unavailable"
      )
      result <- NULL
      pending <- connection[["access_token"]](
        force_refresh = TRUE,
        async = TRUE
      )
      promises::then(
        pending,
        function(value) result <<- value,
        function(error) result <<- error
      )
      values[["logout"]]()
      resolve(manager_test_token(access = "must-not-escape"))
      for (i in seq_len(10)) {
        later::run_now(0)
      }
      expect_s3_class(result, "shinyOAuth_access_error")
      expect_identical(
        result[["context"]][["reason"]],
        "authorization_unavailable"
      )
      expect_null(values[["token"]])
      immediate <- NULL
      promises::catch(connection[["access_token"]](async = TRUE), function(e) {
        immediate <<- e
      })
      for (i in seq_len(10)) {
        later::run_now(0)
      }
      expect_s3_class(immediate, "shinyOAuth_access_error")
    }
  )
  error <- shiny::withReactiveDomain(
    foreign,
    shiny::isolate(tryCatch(held[["access_token"]](), error = identity))
  )
  expect_identical(error[["context"]][["reason"]], "authorization_unavailable")
})

test_that("credential-only clients work with external HTTP libraries", {
  skip_if_not_installed("webfakes")
  local_options(shinyOAuth.skip_browser_token = TRUE)
  app <- webfakes::new_app()
  app[["get"]]("/records", function(req, res) {
    if (
      !identical(
        req[["get_header"]]("Authorization"),
        "Bearer synthetic-access"
      )
    ) {
      return(res[["set_status"]](401)[["send"]]("missing authorization"))
    }
    res[["send_json"]](list(records = 3L), auto_unbox = TRUE)
  })
  process <- webfakes::local_app_process(app)
  client <- make_test_client(use_nonce = FALSE)
  client@scopes <- c("read", "write")
  shiny::testServer(
    oauth_module_server,
    args = list(id = "auth", client = client, auto_redirect = FALSE),
    {
      values[["token"]] <- manager_test_token()
      connection <- values[["connection"]]()
      response <- httr2::request(paste0(process[["url"]](), "records")) |>
        httr2::req_auth_bearer_token(connection[["access_token"]](
          required_scopes = "read"
        )) |>
        httr2::req_perform()
      expect_identical(httr2::resp_body_json(response)[["records"]], 3L)
      expect_identical(connection[["summary"]]()[["resource_ids"]], character())
      error <- tryCatch(connection[["request"]]("undeclared"), error = identity)
      expect_s3_class(error, "shinyOAuth_input_error")
    }
  )
})

test_that("single-module narrowing persists through subsequent refresh", {
  local_options(shinyOAuth.skip_browser_token = TRUE)
  client <- make_test_client(use_nonce = FALSE)
  client@scopes <- c("read", "write")
  requests <- list()
  local_mocked_bindings(refresh_token_dispatch = function(
    client,
    token,
    scope_request,
    ...
  ) {
    requests[[length(requests) + 1L]] <<- scope_request[["scopes"]]
    token@granted_scopes <- scope_request[["scopes"]]
    token@expires_at <- as.numeric(Sys.time()) + 3600
    token
  })
  shiny::testServer(
    oauth_module_server,
    args = list(id = "auth", client = client, auto_redirect = FALSE),
    {
      values[["token"]] <- manager_test_token()
      connection <- values[["connection"]]()
      checks <- logical()
      shiny::observe({
        checks <<- c(checks, connection[["has_scopes"]]("write"))
      })
      session[["flushReact"]]()
      expect_identical(connection[["refresh"]](scopes = "read"), TRUE)
      session[["flushReact"]]()
      expect_identical(checks, c(TRUE, FALSE))
      values[["refresh_next_attempt_at"]] <- 0
      expect_identical(.refresh_current_token(automatic = TRUE), TRUE)
      expect_identical(requests, list("read", "read"))
      expect_identical(connection, values[["connection"]]())
      error <- tryCatch(
        connection[["refresh"]](scopes = "write"),
        error = identity
      )
      expect_s3_class(error, "shinyOAuth_token_error")
      expect_length(requests, 2L)
    }
  )
})

test_that("accessor refresh obeys the module's retry pacing", {
  local_options(shinyOAuth.skip_browser_token = TRUE)
  client <- make_test_client(use_nonce = FALSE)
  client@scopes <- c("read", "write")
  calls <- 0L
  local_mocked_bindings(refresh_token = function(...) {
    calls <<- calls + 1L
    stop(refresh_outcome_error(simpleError("retry later"), "not_consumed"))
  })
  shiny::testServer(
    oauth_module_server,
    args = list(
      id = "auth",
      client = client,
      auto_redirect = FALSE,
      indefinite_session = TRUE
    ),
    {
      values[["token"]] <- manager_test_token()
      connection <- values[["connection"]]()
      first <- tryCatch(
        connection[["access_token"]](force_refresh = TRUE),
        error = identity
      )
      second <- tryCatch(
        connection[["access_token"]](force_refresh = TRUE),
        error = identity
      )
      expect_identical(first[["context"]][["reason"]], "refresh_unavailable")
      expect_identical(second[["context"]][["reason"]], "refresh_unavailable")
      expect_identical(calls, 1L)
    }
  )
})

test_that("legacy wrappers require the module factory for token acquisition", {
  client <- make_test_client(use_nonce = FALSE)
  client@resource_bases <- c(api = "https://api.example.test/v1")
  shiny::testServer(
    function(input, output, session) {
      connection <- oauth_connection(
        client,
        shiny::reactive(manager_test_token())
      )
    },
    {
      error <- tryCatch(connection[["access_token"]](), error = identity)
      expect_s3_class(error, "shinyOAuth_config_error")
      expect_identical(connection[["summary"]]()[["resource_ids"]], "api")
    }
  )
})
