test_that("scope-free managed reauthorization replaces and refreshes an authorization", {
  local_options(shinyOAuth.skip_browser_token = FALSE)
  for (uncertain in c(FALSE, TRUE)) {
    client <- make_test_client(use_nonce = FALSE, scopes = character())
    client@redirect_uri <- "https://app.example/callback"
    fixture <- ordinary_manager_fixture(client)
    token <- manager_test_token()
    token@granted_scopes <- character()
    requests <- list()
    fail <- FALSE
    local_mocked_bindings(
      revoke_token = function(...) invisible(NULL),
      req_with_retry = function(req, ...) {
        if (fail) {
          stop("synthetic refresh interruption")
        }
        requests[[length(requests) + 1L]] <<- req[["body"]][["data"]]
        httr2::response(
          req[["url"]],
          status = 200L,
          headers = list("content-type" = "application/json"),
          body = charToRaw(jsonlite::toJSON(
            list(
              access_token = paste0("replacement-", length(requests)),
              refresh_token = paste0("refresh-", length(requests)),
              token_type = "Bearer",
              expires_in = 3600
            ),
            auto_unbox = TRUE
          ))
        )
      }
    )
    shiny::testServer(
      oauth_connections_server,
      args = list(id = "health", manager = fixture[["manager"]]),
      session = manager_test_session(manager_test_cookie(fixture)),
      {
        id <- manager_test_accept(controller, token = token)
        previous <- connection(id)
        if (uncertain) {
          fail <<- TRUE
          expect_error(previous[["refresh"]]())
          fail <<- FALSE
          expect_identical(previous[["summary"]]()[["status"]], "uncertain")
        }
        expect_identical(controller[["reauthorize"]](id), "a")
        hooks <- controller[["hooks"]]("a")
        context <- hooks[["prepare"]]()
        expect_null(context[["requested_scopes"]])
        expect_null(hooks[["parameters"]](context)[["requested_scopes"]])
        browser <- valid_browser_token()
        url <- prepare_call_internal(
          client,
          browser,
          .transaction_context = context,
          .requested_scopes = context[["requested_scopes"]]
        )
        expect_false("scope" %in% names(httr2::url_parse(url)[["query"]]))
        restored <- oauth_module_managed_context(
          hooks,
          client,
          parse_query_param(url, "state"),
          browser
        )
        expect_null(restored[["data"]][["requested_scopes"]])
        fresh <- handle_callback_internal(
          client,
          "code",
          parse_query_param(url, "state"),
          browser,
          .transaction_context = restored[["json"]]
        )
        hooks[["accept"]](fresh, restored[["data"]], as.numeric(Sys.time()))
        replacement <- Filter(
          function(row) identical(row[["replaces_connection_id"]], id),
          controller[["records"]]()
        )[[1L]]
        expect_false(replacement[["refresh_scope_narrowed"]])
        current <- connection(replacement[["stored"]][["id"]])
        expect_false(previous[["is_usable"]]())
        expect_true(current[["is_usable"]]())
        expect_true(current[["refresh"]]())
        expect_identical(current[["access_token"]](), "replacement-2")
        expect_length(requests, 2L)
        expect_true(all(vapply(
          requests,
          function(req) is.null(req[["scope"]]),
          logical(1)
        )))
      }
    )
  }
})

test_that("empty retained scopes do not reset a scoped client's authorization", {
  local_options(shinyOAuth.skip_browser_token = TRUE)
  client <- make_test_client(use_nonce = FALSE, scopes = "read")
  client@redirect_uri <- "https://app.example/callback"
  fixture <- ordinary_manager_fixture(client)
  token <- manager_test_token()
  token@granted_scopes <- character()
  shiny::testServer(
    oauth_connections_server,
    args = list(id = "health", manager = fixture[["manager"]]),
    session = manager_test_session(manager_test_cookie(fixture)),
    {
      id <- manager_test_accept(controller, token = token)
      expect_error(
        controller[["reauthorize"]](id),
        class = "shinyOAuth_access_error"
      )
      expect_identical(connection(id)[["summary"]]()[["status"]], "limited")
    }
  )
})
