test_that("fresh callback failures retain verified replacement policy on retry", {
  local_options(shinyOAuth.skip_browser_token = FALSE)
  for (targeted in c(FALSE, TRUE)) {
    for (async in c(FALSE, TRUE)) {
      for (failure in c("grant", "transport", "denied", "foreign", "replay")) {
        client <- make_test_client(
          use_nonce = FALSE,
          scopes = c("read", "write")
        )
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
        redirects <- list()
        exchanges <- 0L
        local_mocked_bindings(
          send_oauth_module_redirect = function(session, url) {
            redirects[[length(redirects) + 1L]] <<- url
          },
          revoke_token = function(...) invisible(NULL),
          async_dispatch = function(expr, args, ...) {
            promises::promise_resolve(eval(
              expr,
              list2env(args, parent = globalenv())
            ))
          },
          swap_code_for_token_set = function(...) {
            exchanges <<- exchanges + 1L
            if (failure == "transport") {
              stop("synthetic transport failure")
            }
            list(
              access_token = "too-broad",
              refresh_token = "replacement-refresh",
              token_type = "Bearer",
              expires_in = 3600,
              scope = "read write"
            )
          }
        )
        browser <- valid_browser_token()
        original_url <- NULL
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
            original_url <<- .build_auth_url()
          }
        )
        state <- parse_query_param(original_url, "state")
        if (failure == "replay") {
          payload <- state_payload_decrypt_validate(client, state)
          state_store_get_remove(client, payload[["state"]])
        }
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
            values[["browser_token"]] <- if (failure == "foreign") {
              strrep("cd", 64L)
            } else {
              browser
            }
            values[[".process_query"]](paste0(
              if (failure == "denied") {
                "?error=access_denied&state="
              } else {
                "?code=replacement&state="
              },
              state
            ))
            poll_for_async(function() !is.null(values[["error"]]), session)
            expect_null(values[["token"]])
            verified <- failure %in% c("grant", "transport", "denied")
            expect_identical(
              exchanges,
              as.integer(failure %in% c("grant", "transport"))
            )
            expect_identical(
              auth_operations[["reauth_scopes"]],
              if (verified) "read" else NULL
            )
            redirects <<- list()
            values[["reauthorize"]]()
            session[["setInputs"]](
              shinyOAuth_sid = browser_ack[["token"]],
              shinyOAuth_cookie_ack = list(requestId = browser_ack[["id"]])
            )
            poll_for_async(function() length(redirects) > 0L, session)
            retry_url <- redirects[[length(redirects)]]
            if (is.list(retry_url)) {
              retry_url <- retry_url[["url"]]
            }
            expect_setequal(
              normalize_scope_tokens(parse_query_param(
                retry_url,
                "scope",
                decode = TRUE
              )),
              if (verified) "read" else c("read", "write")
            )
            expect_null(values[["token"]])
          }
        )
      }
    }
  }
})
