test_that("HTTP errors retain only bounded Retry-After metadata", {
  local_options(shinyOAuth.expose_error_body = FALSE)
  now <- as.POSIXct("2026-01-01 00:00:00", tz = "UTC")
  local_mocked_bindings(Sys.time = function() now, .package = "base")
  cases <- list(
    list("60", 60),
    list("0", 0),
    list("999999999999", 3600),
    list("Thu, 01 Jan 2026 00:01:00 GMT", 60),
    list("Wed, 31 Dec 2025 23:59:00 GMT", 0),
    list("-1", NA_real_),
    list("Inf", NA_real_),
    list("private-header-value", NA_real_),
    list(c("60", "120"), NA_real_),
    list(NULL, NA_real_)
  )
  for (case in cases) {
    response <- httr2::response(
      "https://example.com/token?secret=private-query-value",
      status = 503L,
      headers = compact_list(list(
        "content-type" = "application/json",
        "set-cookie" = "private-cookie-value",
        "retry-after" = case[[1L]]
      )),
      body = charToRaw(paste0(
        '{"error":"temporarily_unavailable",',
        '"access_token":"private-token-value"}'
      ))
    )
    error <- tryCatch(err_http("Refresh failed", response), error = identity)
    expect_s3_class(error, "shinyOAuth_http_error")
    expect_identical(refresh_condition_retry_after(error), case[[2L]])
    expect_null(error[["response"]])
    expect_null(error[["headers"]])
    expect_false(grepl(
      "private-(header|query|cookie|token)-value",
      paste(capture.output(str(error)), collapse = " ")
    ))
    restored <- unserialize(serialize(error, NULL))
    expect_identical(refresh_condition_retry_after(restored), case[[2L]])
  }
  for (invalid in list(
    "60",
    TRUE,
    -1,
    Inf,
    NA_real_,
    numeric(),
    c(1, 2),
    list(60)
  )) {
    expect_identical(
      refresh_condition_retry_after(list(retry_after = invalid)),
      NA_real_
    )
  }
})

retry_after_test_client <- function(
  targeted = TRUE,
  base = "https://example.com"
) {
  provider <- oauth_provider(
    "retry-after",
    paste0(base, "/auth"),
    paste0(base, "/token"),
    use_nonce = FALSE,
    token_auth_style = "public",
    token_target_mode = if (targeted) "rfc8707" else "none"
  )
  oauth_client(
    provider,
    "retry-app",
    redirect_uri = "https://app.example/callback",
    scopes = c("read", "write", "contacts"),
    token_targets = if (targeted) {
      list(
        primary = list(resource = "urn:primary", scopes = c("read", "write")),
        secondary = list(resource = "urn:secondary", scopes = "contacts")
      )
    } else {
      list()
    },
    default_token_target = if (targeted) "primary" else character()
  )
}

test_that("real refresh errors pace sibling targets and queued acquisitions", {
  local_options(shinyOAuth.skip_browser_token = TRUE)
  now <- Sys.time()
  local_mocked_bindings(Sys.time = function() now, .package = "base")
  calls <- 0L
  local_mocked_bindings(
    revoke_token = function(...) invisible(NULL),
    async_dispatch = function(expr, args, ...) {
      tryCatch(
        promises::promise_resolve(eval(
          expr,
          list2env(args, parent = globalenv())
        )),
        error = promises::promise_reject
      )
    },
    req_with_retry = function(req, ...) {
      calls <<- calls + 1L
      httr2::response(
        req[["url"]],
        status = if (calls == 1L) 503L else 200L,
        headers = list(
          "content-type" = "application/json",
          "retry-after" = "60"
        ),
        body = charToRaw(jsonlite::toJSON(
          if (calls == 1L) {
            list(error = "temporarily_unavailable")
          } else {
            list(
              access_token = paste0("fresh-", calls),
              refresh_token = "rotated-refresh",
              token_type = "Bearer",
              expires_in = 3600,
              scope = utils::URLdecode(as.character(req[["body"]][["data"]][[
                "scope"
              ]]))
            )
          },
          auto_unbox = TRUE
        ))
      )
    }
  )
  for (targeted in c(FALSE, TRUE)) {
    for (managed in c(FALSE, TRUE)) {
      for (async in c(FALSE, TRUE)) {
        calls <- 0L
        client <- retry_after_test_client(targeted)
        manager <- oauth_connections(list(a = client), "https://app.example")
        oauth_connections_ui(shiny::fluidPage(), "auth", manager)
        shiny::testServer(
          if (managed) oauth_connections_server else oauth_module_server,
          args = if (managed) {
            list(id = "auth", manager = manager, async = async)
          } else {
            list(
              id = "auth",
              client = client,
              auto_redirect = FALSE,
              indefinite_session = TRUE,
              async = async
            )
          },
          session = manager_test_session(),
          {
            current <- if (managed) {
              connection(manager_test_accept(controller))
            } else {
              .accept_login_token(manager_test_token(), NULL)
              values[["connection"]]()
            }
            alias <- if (managed) {
              connection(manager_test_accept(controller))
            } else {
              NULL
            }
            failed_target <- if (targeted) "secondary" else NULL
            sibling <- if (targeted) "primary" else NULL
            settle <- function(result) {
              if (!inherits(result, "promise")) {
                return(result)
              }
              value <- NULL
              promises::then(
                result,
                function(x) value <<- x,
                function(e) value <<- e
              )
              poll_for_async(function() !is.null(value), session)
              value
            }
            acquire <- function(target) {
              tryCatch(
                current[["access_token"]](
                  target = target,
                  force_refresh = TRUE,
                  async = async
                ),
                error = identity
              )
            }
            first <- acquire(failed_target)
            # In async mode this sibling is queued before the first error has
            # been delivered. Resuming must recheck the shared retry deadline.
            queued <- if (async) acquire(sibling) else NULL
            if (async) {
              # Observe rejection immediately while awaiting the first caller.
              # The assertion below still checks the queued caller's error.
              promises::catch(queued, function(...) NULL)
            }
            expect_s3_class(settle(first), "shinyOAuth_access_error")
            if (async) {
              expect_s3_class(settle(queued), "shinyOAuth_access_error")
            }
            expect_identical(calls, 1L)
            expect_identical(
              current[["access_token"]](target = sibling),
              "synthetic-access"
            )
            now <<- now + 31
            if (!is.null(alias)) {
              expect_error(
                alias[["access_token"]](force_refresh = TRUE),
                class = "shinyOAuth_access_error"
              )
            }
            expect_s3_class(
              settle(acquire(failed_target)),
              "shinyOAuth_access_error"
            )
            expect_s3_class(settle(acquire(sibling)), "shinyOAuth_access_error")
            manual <- tryCatch(
              current[["refresh"]](target = sibling),
              error = identity
            )
            expect_s3_class(settle(manual), "shinyOAuth_access_error")
            expect_identical(calls, 1L)
            now <<- now + 45
            expect_identical(settle(acquire(failed_target)), "fresh-2")
            expect_identical(calls, 2L)
          }
        )
      }
    }
  }
})

test_that("Retry-After survives a real refresh worker without retaining its response", {
  skip_if_not_installed("webfakes")
  skip_if_not_installed("mirai")
  mirai::daemons(1)
  withr::defer(mirai::daemons(0))
  assert_shinyoauth_available_in_daemon()
  app <- webfakes::new_app()
  app[["post"]]("/token", function(req, res) {
    res[["set_status"]](503L)
    res[["set_header"]]("Retry-After", "60")
    res[["set_header"]]("Set-Cookie", "private-cookie-value")
    res[["send_json"]](
      list(error = "temporarily_unavailable"),
      auto_unbox = TRUE
    )
  })
  server <- webfakes::local_app_process(app)
  client <- retry_after_test_client(base = sub("/$", "", server[["url"]]()))
  result <- NULL
  promises::then(
    refresh_token_dispatch(
      client,
      manager_test_token(),
      async = TRUE,
      target_request = token_target_request(client, "secondary")
    ),
    function(value) result <<- value,
    function(error) result <<- error
  )
  poll_for_async(function() !is.null(result), timeout = 30)
  expect_s3_class(result, "shinyOAuth_http_error")
  expect_identical(result[["refresh_credential_outcome"]], "not_consumed")
  expect_identical(refresh_condition_retry_after(result), 60)
  expect_null(result[["response"]])
  expect_false(grepl(
    "private-cookie-value",
    paste(capture.output(str(result)), collapse = " ")
  ))
})
