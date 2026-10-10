test_that("ordinary and narrowed refreshes retain rejected credentials for their owners", {
  local_options(shinyOAuth.skip_browser_token = TRUE, warn = 2)
  for (managed in c(FALSE, TRUE)) {
    for (async in c(FALSE, TRUE)) {
      for (narrowed in c(FALSE, TRUE)) {
        for (failure in c("scope", "lifetime", "replay")) {
          provider <- oauth_provider(
            "cleanup",
            "https://issuer.example/auth",
            "https://issuer.example/token",
            revocation_url = "https://issuer.example/revoke",
            token_auth_style = "public",
            use_nonce = FALSE
          )
          client <- oauth_client(
            provider,
            "app",
            client_secret = "",
            redirect_uri = "https://app.example/callback",
            scopes = c("read", "write"),
            scope_validation = "strict"
          )
          revoked <- character()
          local_mocked_bindings(
            req_with_retry = function(req, ...) {
              if (endsWith(req[["url"]], "/revoke")) {
                revoked <<- c(
                  revoked,
                  as.character(req[["body"]][["data"]][["token"]])
                )
                return(httr2::response(req[["url"]], status = 200L))
              }
              httr2::response(
                req[["url"]],
                status = 200L,
                headers = list("content-type" = "application/json"),
                body = charToRaw(jsonlite::toJSON(
                  list(
                    access_token = "rejected-new-access",
                    refresh_token = "rejected-new-refresh",
                    token_type = "Bearer",
                    expires_in = if (failure == "lifetime") -1 else 3600,
                    scope = if (failure == "scope") {
                      "foreign"
                    } else if (narrowed) {
                      "read"
                    } else {
                      "read write"
                    }
                  ),
                  auto_unbox = TRUE
                ))
              )
            },
            async_dispatch = function(expr, args, ...) {
              value <- eval(expr, list2env(args, parent = globalenv()))
              promises::promise_resolve(list(
                .shinyOAuth_async_wrapped = TRUE,
                value = value,
                messages = list(),
                warnings = if (
                  failure == "replay" &&
                    identical(args[["function_name"]], "refresh_token_impl")
                ) {
                  list(simpleWarning("worker warning promoted in parent"))
                } else {
                  list()
                }
              ))
            }
          )
          if (failure == "replay" && !async) {
            next
          }
          f <- ordinary_manager_fixture(client)
          shiny::testServer(
            if (managed) oauth_connections_server else oauth_module_server,
            args = if (managed) {
              list(id = "health", manager = f[["manager"]], async = async)
            } else {
              list(
                id = "auth",
                client = client,
                auto_redirect = FALSE,
                async = async
              )
            },
            session = manager_test_session(
              if (managed) manager_test_cookie(f) else NULL
            ),
            {
              current <- if (managed) {
                connection(manager_test_accept(controller))
              } else {
                .accept_login_token(manager_test_token(), NULL)
                values[["connection"]]()
              }
              result <- tryCatch(
                current[["refresh"]](scopes = if (narrowed) "read" else NULL),
                error = identity
              )
              if (inherits(result, "promise")) {
                settled <- NULL
                promises::then(
                  result,
                  function(value) {
                    settled <<- value
                  },
                  function(error) {
                    settled <<- error
                  }
                )
                poll_for_async(function() !is.null(settled), session)
                result <- settled
              }
              expect_s3_class(
                result,
                if (managed) {
                  "shinyOAuth_token_error"
                } else {
                  "shinyOAuth_access_error"
                }
              )
              poll_for_async(function() length(revoked) == 2L, session)
              expect_identical(
                revoked,
                c("rejected-new-refresh", "rejected-new-access")
              )
              expect_false(grepl(
                "rejected-new-",
                paste(capture.output(str(result)), collapse = "\n")
              ))
              if (managed) {
                expect_null(controller[["read"]](current[["id"]])[["token"]])
              } else {
                expect_null(values[["token"]])
              }
            }
          )
        }
      }
    }
  }
})

test_that("public refresh rejects early validation errors without returning cleanup credentials", {
  client <- make_test_client()
  local_mocked_bindings(req_with_retry = function(req, ...) {
    httr2::response(
      req[["url"]],
      status = 200L,
      headers = list("content-type" = "application/json"),
      body = charToRaw(
        '{"access_token":"private-new-access","refresh_token":"private-new-refresh","expires_in":-1,"token_type":"Bearer"}'
      )
    )
  })
  error <- tryCatch(
    refresh_token(client, manager_test_token()),
    error = identity
  )
  expect_s3_class(error, "shinyOAuth_token_error")
  expect_identical(error[["refresh_credential_outcome"]], "consumed")
  expect_false(grepl(
    "private-new-",
    paste(capture.output(str(error)), collapse = "\n")
  ))
})

test_that("real worker warning replay retires successful rotated refresh credentials", {
  skip_if_not_installed("webfakes")
  skip_if_not_installed("mirai")
  assert_shinyoauth_available_in_daemon()
  local_options(shinyOAuth.skip_browser_token = TRUE)
  app <- webfakes::new_app()
  app[["locals"]][["revoked"]] <- 0L
  app[["post"]]("/token", function(req, res) {
    res[["set_type"]]("application/json")[["send"]](
      '{"access_token":"worker-new-access","refresh_token":"worker-new-refresh","token_type":"Bearer","expires_in":3600,"scope":"read"}'
    )
  })
  app[["post"]]("/revoke", function(req, res) {
    req[["app"]][["locals"]][["revoked"]] <- req[["app"]][["locals"]][[
      "revoked"
    ]] +
      1L
    res[["set_status"]](200L)[["send"]]("")
  })
  app[["get"]]("/counts", function(req, res) {
    res[["set_type"]]("application/json")[["send"]](jsonlite::toJSON(
      list(revoked = req[["app"]][["locals"]][["revoked"]]),
      auto_unbox = TRUE
    ))
  })
  server <- webfakes::new_app_process(app)
  withr::defer(server[["stop"]]())
  base <- sub("/$", "", server[["url"]]())
  provider <- oauth_provider(
    "worker",
    "https://issuer.example/auth",
    paste0(base, "/token"),
    revocation_url = paste0(base, "/revoke"),
    token_auth_style = "public",
    use_nonce = FALSE
  )
  client <- oauth_client(
    provider,
    "app",
    client_secret = "",
    redirect_uri = "https://app.example/callback",
    scopes = c("read", "write"),
    scope_validation = "warn"
  )
  mirai::daemons(1L)
  withr::defer(mirai::daemons(0L))
  shiny::testServer(
    oauth_module_server,
    args = list(
      id = "auth",
      client = client,
      auto_redirect = FALSE,
      async = TRUE
    ),
    {
      .accept_login_token(manager_test_token(), NULL)
      local_options(warn = 2)
      result <- NULL
      promises::catch(.refresh_current_token(async = TRUE), function(error) {
        result <<- error
      })
      poll_for_async(function() !is.null(result), session, timeout = 30)
      expect_s3_class(result, "error")
      expect_null(values[["token"]])
      counts <- function() {
        httr2::request(paste0(base, "/counts")) |>
          httr2::req_perform() |>
          httr2::resp_body_json()
      }
      poll_for_async(
        function() counts()[["revoked"]] == 2L,
        session,
        timeout = 30
      )
      expect_equal(counts()[["revoked"]], 2)
    }
  )
})
