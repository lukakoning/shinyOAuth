test_that("same-session replacements do not restrict later ordinary login", {
  local_options(shinyOAuth.skip_browser_token = FALSE)
  for (targeted in c(FALSE, TRUE)) {
    for (async in c(FALSE, TRUE)) {
      client <- make_test_client(use_nonce = FALSE, scopes = c("read", "write"))
      if (targeted) {
        provider <- client@provider
        provider@token_target_mode <- "rfc8707"
        S7::props(client) <- list(
          provider = provider,
          token_targets = list(
            api = list(resource = "urn:api", scopes = c("read", "write"))
          ),
          default_token_target = "api"
        )
      }
      response_scope <- "read write"
      local_mocked_bindings(
        revoke_token = function(...) invisible(NULL),
        async_dispatch = function(expr, args, ...) {
          promises::promise_resolve(eval(
            expr,
            list2env(args, parent = globalenv())
          ))
        },
        swap_code_for_token_set = function(...) {
          list(
            access_token = "replacement",
            refresh_token = "replacement-refresh",
            token_type = "Bearer",
            expires_in = 3600,
            scope = response_scope
          )
        }
      )
      shiny::testServer(
        oauth_module_server,
        args = list(
          id = "auth",
          client = client,
          auto_redirect = FALSE,
          reauth_after_seconds = 60,
          async = async
        ),
        {
          session[["flushReact"]]()
          token <- manager_test_token()
          token@granted_scopes <- "read"
          .accept_login_token(token, NULL)
          previous <- values[["connection"]]()
          values[["reauthorize"]]()
          callback <- function() {
            values[["browser_token"]] <- valid_browser_token()
            url <- .build_auth_url()
            expect_identical(
              parse_query_param(url, "scope", decode = TRUE),
              "read"
            )
            values[[".process_query"]](paste0(
              "?code=replacement&state=",
              parse_query_param(url, "state")
            ))
            poll_for_async(
              function() is.null(auth_operations[["active_login_id"]]),
              session
            )
          }
          # A rejected response must not discard the restriction on retry.
          callback()
          expect_null(values[["token"]])
          expect_false(previous[["is_usable"]]())
          response_scope <<- "read"
          callback()
          expect_null(values[["error"]])
          expect_identical(values[["token"]]@access_token, "replacement")
          expect_false(values[["connection"]]()[["has_scopes"]]("write"))
          # Another explicit replacement still uses the retained grant, even
          # after the preceding request override has been consumed.
          values[["reauthorize"]]()
          callback()
          expect_null(values[["error"]])
          expect_false(values[["connection"]]()[["has_scopes"]]("write"))
          values[["auth_started_at"]] <- as.numeric(Sys.time()) - 120
          session[["flushReact"]]()
          expect_null(values[["token"]])
          values[["request_login"]]()
          values[["browser_token"]] <- valid_browser_token()
          url <- .build_auth_url()
          expect_setequal(
            normalize_scope_tokens(parse_query_param(
              url,
              "scope",
              decode = TRUE
            )),
            c("read", "write")
          )
        }
      )
    }
  }
})

test_that("fresh ordinary callbacks retain restrictions through later refreshes", {
  local_options(shinyOAuth.skip_browser_token = FALSE)
  for (async in c(FALSE, TRUE)) {
    for (evidence in c("token", "introspection")) {
      client <- make_test_client(use_nonce = FALSE, scopes = c("read", "write"))
      client@scope_validation <- "strict"
      if (evidence == "introspection") {
        client@provider@introspection_url <- "https://example.com/introspect"
        client@introspect <- TRUE
        client@introspection_checks <- "scope"
      }
      broaden <- FALSE
      requests <- character()
      local_mocked_bindings(
        revoke_token = function(...) invisible(NULL),
        async_dispatch = function(expr, args, ...) {
          promises::promise_resolve(eval(
            expr,
            list2env(args, parent = globalenv())
          ))
        },
        swap_code_for_token_set = function(...) {
          list(
            access_token = "replacement",
            refresh_token = "replacement-refresh",
            token_type = "Bearer",
            expires_in = 3600,
            scope = "read"
          )
        },
        req_with_retry = function(req, ...) {
          requests <<- c(
            requests,
            as.character(req[["body"]][["data"]][["scope"]])
          )
          httr2::response(
            req[["url"]],
            status = 200L,
            headers = list("content-type" = "application/json"),
            body = charToRaw(jsonlite::toJSON(
              list(
                access_token = "refreshed",
                refresh_token = "rotated",
                token_type = "Bearer",
                expires_in = 3600,
                scope = if (broaden && evidence == "token") {
                  "read write"
                } else {
                  "read"
                }
              ),
              auto_unbox = TRUE
            ))
          )
        },
        introspect_token = function(...) {
          list(
            supported = TRUE,
            active = TRUE,
            status = "ok",
            raw = list(
              active = TRUE,
              scope = if (broaden) "read write" else "read"
            )
          )
        }
      )
      browser <- valid_browser_token()
      url <- NULL
      shiny::testServer(
        oauth_module_server,
        args = list(id = "auth", client = client, auto_redirect = FALSE),
        {
          session[["flushReact"]]()
          token <- manager_test_token()
          token@granted_scopes <- "read"
          .accept_login_token(token, NULL)
          values[["reauthorize"]]()
          values[["browser_token"]] <- browser
          url <<- .build_auth_url()
          expect_identical(
            parse_query_param(url, "scope", decode = TRUE),
            "read"
          )
        }
      )
      shiny::testServer(
        oauth_module_server,
        args = list(
          id = "auth",
          client = client,
          auto_redirect = FALSE,
          async = async
        ),
        {
          session[["flushReact"]]()
          values[["browser_token"]] <- browser
          values[[".process_query"]](paste0(
            "?code=replacement&state=",
            parse_query_param(url, "state")
          ))
          poll_for_async(
            function() {
              !is.null(values[["token"]]) || !is.null(values[["error"]])
            },
            session
          )
          expect_null(values[["error"]])
          current <- values[["connection"]]()
          await_refresh <- function() {
            result <- tryCatch(current[["refresh"]](), error = identity)
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
            result
          }
          expect_true(await_refresh())
          expect_false(current[["has_scopes"]]("write"))
          broaden <<- TRUE
          expect_s3_class(await_refresh(), "shinyOAuth_access_error")
          expect_false(current[["has_scopes"]]("write"))
          expect_null(values[["token"]])
          expect_identical(requests, c("read", "read"))
        }
      )
    }
  }
})
