test_that("fresh callback sessions retain secondary target restrictions", {
  local_options(shinyOAuth.skip_browser_token = FALSE)
  client <- make_test_client(
    use_nonce = FALSE,
    scopes = c("a.read", "b.read", "b.write")
  )
  provider <- client@provider
  provider@token_target_mode <- "rfc8707"
  S7::props(client) <- list(
    provider = provider,
    token_targets = list(
      a = list(resource = "urn:a", scopes = "a.read"),
      b = list(resource = "urn:b", scopes = c("b.read", "b.write"))
    ),
    default_token_target = "a"
  )
  requests <- list()
  broaden <- FALSE
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
        access_token = "replacement-a",
        refresh_token = "replacement-refresh",
        token_type = "Bearer",
        expires_in = 3600,
        scope = "a.read"
      )
    },
    req_with_retry = function(req, ...) {
      body <- lapply(req[["body"]][["data"]], function(value) {
        utils::URLdecode(as.character(value))
      })
      requests[[length(requests) + 1L]] <<- body
      httr2::response(
        req[["url"]],
        status = 200L,
        headers = list("content-type" = "application/json"),
        body = charToRaw(jsonlite::toJSON(
          list(
            access_token = "replacement-b",
            refresh_token = "rotated-refresh",
            token_type = "Bearer",
            expires_in = 3600,
            scope = if (broaden) "b.read b.write" else body[["scope"]]
          ),
          auto_unbox = TRUE
        ))
      )
    }
  )
  for (async in c(FALSE, TRUE)) {
    browser <- valid_browser_token()
    url <- NULL
    broaden <- FALSE
    shiny::testServer(
      oauth_module_server,
      args = list(id = "auth", client = client, auto_redirect = FALSE),
      {
        session[["flushReact"]]()
        token <- manager_test_token()
        token@granted_scopes <- "a.read"
        .accept_login_token(token, NULL)
        values[["connection"]]()[["refresh"]](target = "b", scopes = "b.read")
        values[["reauthorize"]]()
        values[["browser_token"]] <- browser
        url <<- .build_auth_url()
        payload <- state_payload_decrypt_validate(
          client,
          parse_query_param(url, "state")
        )
        expect_identical(
          connection_data_decode(payload[["target_limits"]])[["b"]],
          "b.read"
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
          function() !is.null(values[["token"]]) || !is.null(values[["error"]]),
          session
        )
        expect_null(values[["error"]])
        expect_identical(auth_operations[["target_limits"]][["b"]], "b.read")
        current <- values[["connection"]]()
        before <- length(requests)
        error <- tryCatch(
          current[["access_token"]]("b.write", target = "b"),
          error = identity
        )
        expect_identical(error[["context"]][["reason"]], "insufficient_scope")
        expect_length(requests, before)
        expect_identical(
          current[["access_token"]]("b.read", target = "b"),
          "replacement-b"
        )
        expect_identical(tail(requests, 1L)[[1L]][["scope"]], "b.read")
        expect_false(current[["has_scopes"]]("b.write", target = "b"))
        # A provider cannot restore removed permissions in its response either.
        broaden <<- TRUE
        auth_operations[["target_next_attempt"]][["b"]] <- 0
        error <- tryCatch(
          current[["access_token"]](target = "b", force_refresh = TRUE),
          error = identity
        )
        expect_s3_class(error, "shinyOAuth_access_error")
        expect_false(current[["has_scopes"]]("b.write", target = "b"))
      }
    )
  }
})
