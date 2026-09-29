rejected_target_response_fixture <- function(
  rejection = "scope",
  rotated = TRUE
) {
  provider <- oauth_provider(
    "cleanup",
    "https://issuer.example/auth",
    "https://issuer.example/token",
    revocation_url = "https://issuer.example/revoke",
    introspection_url = "https://issuer.example/introspect",
    token_auth_style = "public",
    use_nonce = FALSE,
    token_target_mode = "rfc8707"
  )
  client <- oauth_client(
    provider,
    "app",
    client_secret = "",
    redirect_uri = "https://app.example/callback",
    scopes = c("primary.read", "secondary.read"),
    scope_validation = "none",
    introspect = rejection == "introspection",
    introspection_checks = if (rejection == "introspection") {
      "scope"
    } else {
      character()
    },
    token_targets = list(
      primary = list(resource = "urn:primary", scopes = "primary.read"),
      secondary = list(resource = "urn:secondary", scopes = "secondary.read")
    ),
    default_token_target = "primary"
  )
  state <- new.env(parent = emptyenv())
  state[["revoked"]] <- character()
  state[["revocation_timeouts"]] <- numeric()
  state[["events"]] <- list()
  state[["token_calls"]] <- 0L
  state[["introspection_calls"]] <- 0L
  http <- function(req, ...) {
    if (endsWith(req[["url"]], "/revoke")) {
      state[["revocation_timeouts"]] <- c(
        state[["revocation_timeouts"]],
        req[["options"]][["timeout_ms"]]
      )
      state[["revoked"]] <- c(
        state[["revoked"]],
        as.character(req[["body"]][["data"]][["token"]])
      )
      return(httr2::response(req[["url"]], status = 200L))
    }
    body <- if (endsWith(req[["url"]], "/introspect")) {
      state[["introspection_calls"]] <- state[["introspection_calls"]] + 1L
      list(active = TRUE, scope = "foreign.read")
    } else {
      state[["token_calls"]] <- state[["token_calls"]] + 1L
      list(
        access_token = "cleanup-new-access",
        refresh_token = if (rotated) "cleanup-new-refresh" else NULL,
        token_type = "Bearer",
        expires_in = 3600,
        scope = if (rejection == "scope") "foreign.read" else "secondary.read"
      )
    }
    httr2::response(
      req[["url"]],
      status = 200L,
      headers = list("content-type" = "application/json"),
      body = charToRaw(jsonlite::toJSON(compact_list(body), auto_unbox = TRUE))
    )
  }
  list(
    client = client,
    token = OAuthToken(
      access_token = "cleanup-old-access",
      refresh_token = "cleanup-old-refresh",
      token_type = "Bearer",
      expires_at = as.numeric(Sys.time()) + 3600,
      granted_scopes = "primary.read",
      granted_scopes_verified = TRUE
    ),
    state = state,
    http = http
  )
}

test_that("HTTP validation rejection reaches both owners without exposing credentials", {
  local_options(shinyOAuth.skip_browser_token = TRUE)
  for (managed in c(FALSE, TRUE)) {
    for (async in c(FALSE, TRUE)) {
      for (rotated in c(FALSE, TRUE)) {
        for (rejection in c("scope", "introspection")) {
          f <- rejected_target_response_fixture(rejection, rotated)
          client <- f[["client"]]
          state <- f[["state"]]
          local_options(shinyOAuth.audit_hook = function(event) {
            state[["events"]][[length(state[["events"]]) + 1L]] <- event
          })
          local_mocked_bindings(
            req_with_retry = f[["http"]],
            async_dispatch = function(expr, args, ...) {
              promises::promise_resolve(eval(
                expr,
                list2env(args, parent = globalenv())
              ))
            }
          )
          manager <- ordinary_manager_fixture(client)
          shiny::testServer(
            if (managed) oauth_connections_server else oauth_module_server,
            args = if (managed) {
              list(id = "health", manager = manager[["manager"]], async = async)
            } else {
              list(
                id = "auth",
                client = client,
                auto_redirect = FALSE,
                async = async
              )
            },
            session = manager_test_session(
              if (managed) manager_test_cookie(manager) else NULL
            ),
            {
              current <- if (managed) {
                connection(manager_test_accept(
                  controller,
                  token = f[["token"]]
                ))
              } else {
                .accept_login_token(f[["token"]], NULL)
                values[["connection"]]()
              }
              result <- tryCatch(
                current[["access_token"]](target = "secondary", async = async),
                error = identity
              )
              if (inherits(result, "promise")) {
                settled <- NULL
                promises::then(
                  result,
                  function(value) settled <<- value,
                  function(error) settled <<- error
                )
                poll_for_async(function() !is.null(settled), session)
                result <- settled
              }
              expect_s3_class(result, "shinyOAuth_access_error")
              if (rotated) {
                poll_for_async(
                  function() length(state[["revoked"]]) == 2L,
                  session
                )
                expect_identical(
                  state[["revoked"]],
                  c("cleanup-new-refresh", "cleanup-new-access")
                )
                expect_true(all(state[["revocation_timeouts"]] <= 2000))
                expect_false(current[["has_scopes"]]("primary.read"))
                if (managed) {
                  expect_identical(
                    controller[["read"]](current[["id"]])[["status"]],
                    "uncertain"
                  )
                  controller[["logout"]]()
                } else {
                  expect_null(values[["token"]])
                  values[["logout"]]()
                }
                expect_length(state[["revoked"]], 2L)
              } else {
                expect_length(state[["revoked"]], 0L)
                expect_identical(
                  current[["access_token"]](),
                  "cleanup-old-access"
                )
              }
              expect_identical(state[["token_calls"]], 1L)
              expect_identical(
                state[["introspection_calls"]],
                if (rejection == "introspection") 1L else 0L
              )
              diagnostic <- paste(
                capture.output(str(list(
                  error = result,
                  events = state[["events"]]
                ))),
                collapse = "\n"
              )
              expect_false(grepl(
                "cleanup-(new|old)-(access|refresh)",
                diagnostic
              ))
            }
          )
        }
      }
    }
  }
})

test_that("indefinite target sessions retain their shared grant after HTTP rejection", {
  local_options(shinyOAuth.skip_browser_token = TRUE)
  for (async in c(FALSE, TRUE)) {
    f <- rejected_target_response_fixture()
    client <- f[["client"]]
    state <- f[["state"]]
    local_mocked_bindings(
      req_with_retry = f[["http"]],
      async_dispatch = function(expr, args, ...) {
        promises::promise_resolve(eval(
          expr,
          list2env(args, parent = globalenv())
        ))
      }
    )
    shiny::testServer(
      oauth_module_server,
      args = list(
        id = "auth",
        client = client,
        auto_redirect = FALSE,
        indefinite_session = TRUE,
        async = async
      ),
      {
        .accept_login_token(f[["token"]], NULL)
        current <- values[["connection"]]()
        result <- tryCatch(
          current[["access_token"]](target = "secondary", async = async),
          error = identity
        )
        if (inherits(result, "promise")) {
          settled <- NULL
          promises::catch(result, function(error) settled <<- error)
          poll_for_async(function() !is.null(settled), session)
          result <- settled
        }
        expect_s3_class(result, "shinyOAuth_access_error")
        expect_length(state[["revoked"]], 0L)
        expect_identical(current[["access_token"]](), "cleanup-old-access")
        expect_false(is_valid_string(values[["token"]]@refresh_token))
      }
    )
  }
})

test_that("public refresh errors do not contain privately retained response credentials", {
  f <- rejected_target_response_fixture()
  local_mocked_bindings(req_with_retry = f[["http"]])
  error <- tryCatch(
    refresh_token(f[["client"]], f[["token"]]),
    error = identity
  )
  expect_s3_class(error, "shinyOAuth_token_error")
  expect_identical(error[["refresh_credential_outcome"]], "consumed")
  expect_false(grepl(
    "cleanup-(new|old)-(access|refresh)",
    paste(capture.output(str(error)), collapse = "\n")
  ))
  expect_length(f[["state"]][["revoked"]], 0L)
})

test_that("warning replay failures cannot lose rejected response credentials", {
  local_options(shinyOAuth.skip_browser_token = TRUE, warn = 2)
  f <- rejected_target_response_fixture()
  state <- f[["state"]]
  local_mocked_bindings(
    req_with_retry = f[["http"]],
    async_dispatch = function(expr, args, ...) {
      value <- eval(expr, list2env(args, parent = globalenv()))
      promises::promise_resolve(list(
        .shinyOAuth_async_wrapped = TRUE,
        value = value,
        warnings = if (
          identical(args[["function_name"]], "refresh_token_impl")
        ) {
          list(simpleWarning("synthetic worker diagnostic"))
        } else {
          list()
        },
        messages = list()
      ))
    }
  )
  shiny::testServer(
    oauth_module_server,
    args = list(
      id = "auth",
      client = f[["client"]],
      auto_redirect = FALSE,
      async = TRUE
    ),
    {
      .accept_login_token(f[["token"]], NULL)
      result <- NULL
      promises::catch(
        values[["connection"]]()[["access_token"]](
          target = "secondary",
          async = TRUE
        ),
        function(error) result <<- error
      )
      poll_for_async(function() !is.null(result), session)
      expect_s3_class(result, "shinyOAuth_access_error")
      poll_for_async(function() length(state[["revoked"]]) == 2L, session)
      expect_identical(
        state[["revoked"]],
        c("cleanup-new-refresh", "cleanup-new-access")
      )
      expect_null(values[["token"]])
    }
  )
})

test_that("late HTTP rejection respects logout and replacement cleanup intent", {
  local_options(shinyOAuth.skip_browser_token = TRUE)
  for (managed in c(FALSE, TRUE)) {
    for (revoke in c(FALSE, TRUE)) {
      f <- rejected_target_response_fixture()
      client <- f[["client"]]
      state <- f[["state"]]
      complete <- NULL
      local_mocked_bindings(
        req_with_retry = f[["http"]],
        async_dispatch = function(expr, args, ...) {
          evaluate <- function() {
            eval(expr, list2env(args, parent = globalenv()))
          }
          if (identical(args[["function_name"]], "refresh_token_impl")) {
            promises::promise(function(resolve, reject) {
              complete <<- function() resolve(evaluate())
            })
          } else {
            promises::promise_resolve(evaluate())
          }
        }
      )
      manager <- ordinary_manager_fixture(client)
      shiny::testServer(
        if (managed) oauth_connections_server else oauth_module_server,
        args = if (managed) {
          list(id = "health", manager = manager[["manager"]], async = TRUE)
        } else {
          list(
            id = "auth",
            client = client,
            auto_redirect = FALSE,
            async = TRUE,
            indefinite_session = TRUE
          )
        },
        session = manager_test_session(
          if (managed) manager_test_cookie(manager) else NULL
        ),
        {
          current <- if (managed) {
            connection(manager_test_accept(controller, token = f[["token"]]))
          } else {
            .accept_login_token(f[["token"]], NULL)
            values[["connection"]]()
          }
          result <- NULL
          promises::catch(
            current[["access_token"]](target = "secondary", async = TRUE),
            function(error) result <<- error
          )
          if (managed) {
            if (revoke) {
              controller[["logout"]]()
            } else {
              controller[["reauthorize"]](current[["id"]])
            }
          } else {
            if (revoke) values[["logout"]]() else values[["reauthorize"]]()
          }
          if (revoke) {
            poll_for_async(function() length(state[["revoked"]]) == 2L, session)
          }
          state[["revoked"]] <- character()
          complete()
          poll_for_async(function() !is.null(result), session)
          expect_s3_class(result, "shinyOAuth_access_error")
          if (revoke) {
            poll_for_async(function() length(state[["revoked"]]) == 2L, session)
            expect_identical(
              state[["revoked"]],
              c("cleanup-new-refresh", "cleanup-new-access")
            )
          } else {
            expect_length(state[["revoked"]], 0L)
          }
          expect_false(current[["has_scopes"]]("primary.read"))
        }
      )
    }
  }
})

test_that("a real worker delivers rejected credentials privately for bounded cleanup", {
  skip_if_not_installed("webfakes")
  skip_if_not_installed("mirai")
  local_options(
    shinyOAuth.skip_browser_token = TRUE,
    shinyOAuth.retry_max_tries = 100L,
    shinyOAuth.timeout = 30
  )
  mirai::daemons(1)
  withr::defer(mirai::daemons(0))
  assert_shinyoauth_available_in_daemon()
  app <- webfakes::new_app()
  app[["use"]](webfakes::mw_urlencoded())
  app[["locals"]][["revoked"]] <- character()
  app[["post"]]("/token", function(req, res) {
    res[["send_json"]](
      list(
        access_token = "worker-rejected-access",
        refresh_token = "worker-rejected-refresh",
        token_type = "Bearer",
        expires_in = 3600,
        scope = "foreign.read"
      ),
      auto_unbox = TRUE
    )
  })
  app[["post"]]("/revoke", function(req, res) {
    req[["app"]][["locals"]][["revoked"]] <- c(
      req[["app"]][["locals"]][["revoked"]],
      req[["form"]][["token"]]
    )
    res[["set_status"]](503L)
    res[["set_header"]]("Retry-After", "60")
    res[["send"]]("")
  })
  app[["get"]]("/revoked", function(req, res) {
    res[["send_json"]](list(tokens = req[["app"]][["locals"]][["revoked"]]))
  })
  server <- webfakes::local_app_process(app)
  f <- rejected_target_response_fixture()
  client <- f[["client"]]
  S7::props(client@provider) <- list(
    token_url = server[["url"]]("/token"),
    revocation_url = server[["url"]]("/revoke")
  )
  for (managed in c(FALSE, TRUE)) {
    manager <- ordinary_manager_fixture(client)
    shiny::testServer(
      if (managed) oauth_connections_server else oauth_module_server,
      args = if (managed) {
        list(id = "health", manager = manager[["manager"]], async = TRUE)
      } else {
        list(id = "auth", client = client, auto_redirect = FALSE, async = TRUE)
      },
      session = manager_test_session(
        if (managed) manager_test_cookie(manager) else NULL
      ),
      {
        current <- if (managed) {
          connection(manager_test_accept(controller, token = f[["token"]]))
        } else {
          .accept_login_token(f[["token"]], NULL)
          values[["connection"]]()
        }
        result <- NULL
        promises::catch(
          current[["access_token"]](target = "secondary", async = TRUE),
          function(error) result <<- error
        )
        poll_for_async(function() !is.null(result), session, timeout = 30)
        expect_s3_class(result, "shinyOAuth_access_error")
        read_revoked <- function() {
          unlist(
            httr2::resp_body_json(httr2::req_perform(
              httr2::request(server[["url"]]("/revoked"))
            ))[["tokens"]],
            use.names = FALSE
          )
        }
        poll_for_async(
          function() length(read_revoked()) >= if (managed) 4L else 2L,
          session,
          timeout = 30
        )
        expect_identical(
          tail(read_revoked(), 2L),
          c("worker-rejected-refresh", "worker-rejected-access")
        )
        expect_false(grepl(
          "worker-rejected",
          paste(capture.output(str(result)), collapse = "\n")
        ))
      }
    )
  }
})
