test_that("plain form_post rejects direct success and error queries but accepts the bridge", {
  local_options(shinyOAuth.skip_browser_token = FALSE)
  for (kind in c("code", "error")) {
    client <- make_test_client(response_mode = "form_post")
    browser <- valid_browser_token()
    state <- parse_query_param(
      prepare_call(client, browser),
      "state",
      decode = TRUE
    )
    payload <- state_payload_decrypt_validate(client, state)
    fields <- c(
      if (kind == "code") {
        list(code = "valid-code")
      } else {
        list(error = "access_denied")
      },
      list(state = state)
    )
    body <- httr2::url_query_build(fields)
    exchanges <- 0L
    local_mocked_bindings(swap_code_for_token_set = function(...) {
      exchanges <<- exchanges + 1L
      list(
        access_token = "synthetic-access",
        token_type = "Bearer",
        expires_in = 3600
      )
    })
    shiny::testServer(
      oauth_module_server,
      args = list(id = "auth", client = client, auto_redirect = FALSE),
      {
        session[["setInputs"]](shinyOAuth_sid = browser)
        session[["flushReact"]]()
        values[[".process_query"]](
          paste0("?", body),
          current_uri = client@redirect_uri
        )
        session[["flushReact"]]()
        expect_false(values[["authenticated"]])
        expect_identical(values[["error"]], "invalid_callback_query")
        expect_identical(exchanges, 0L)
        expect_true(is.list(state_store_get(client, payload[["state"]])))

        req <- list(
          REQUEST_METHOD = "POST",
          "rook.url_scheme" = "http",
          HTTP_HOST = "localhost:8100",
          PATH_INFO = "/",
          QUERY_STRING = "",
          CONTENT_TYPE = "application/x-www-form-urlencoded",
          CONTENT_LENGTH = as.character(nchar(body, type = "bytes")),
          "rook.input" = list(read = function(n) charToRaw(body))
        )
        response <- oauth_form_post_handle_request(req, "auth", client)
        expect_identical(response[["status"]], 303L)
        values[[".process_query"]](
          response[["headers"]][["Location"]],
          current_uri = client@redirect_uri
        )
        session[["flushReact"]]()
        if (kind == "code") {
          expect_true(values[["authenticated"]])
          expect_identical(exchanges, 1L)
        } else {
          expect_false(values[["authenticated"]])
          expect_identical(values[["error"]], "access_denied")
          expect_identical(exchanges, 0L)
        }
      }
    )
  }
})

test_that("single-client and registry wrappers admit only configured transports", {
  for (mode in c("query", "form_post")) {
    for (registry in c(FALSE, TRUE)) {
      client <- make_test_client(response_mode = mode)
      browser <- valid_browser_token()
      state <- parse_query_param(
        prepare_call(client, browser),
        "state",
        decode = TRUE
      )
      state_payload <- state_payload_decrypt_validate(client, state)
      body <- httr2::url_query_build(list(code = "code", state = state))
      ui <- if (registry) {
        oauth_form_post_ui(shiny::fluidPage(), clients = list(auth = client))
      } else {
        oauth_form_post_ui(shiny::fluidPage(), "auth", client)
      }
      exchanges <- 0L
      local_mocked_bindings(swap_code_for_token_set = function(...) {
        exchanges <<- exchanges + 1L
        list(
          access_token = "synthetic-access",
          token_type = "Bearer",
          expires_in = 3600
        )
      })
      responses <- list()
      for (transport in c("query", "form_post")) {
        req <- list(
          REQUEST_METHOD = if (transport == "query") "GET" else "POST",
          "rook.url_scheme" = "http",
          HTTP_HOST = "localhost:8100",
          PATH_INFO = "/",
          QUERY_STRING = if (transport == "query") body else "",
          CONTENT_TYPE = "application/x-www-form-urlencoded",
          CONTENT_LENGTH = as.character(nchar(body, type = "bytes")),
          "rook.input" = list(read = function(n) charToRaw(body))
        )
        responses[[transport]] <- ui(req)
        expect_identical(
          responses[[transport]][["status"]],
          if (transport == mode) 303L else 400L
        )
        expect_true(is.list(state_store_get(client, state_payload[["state"]])))
      }
      shiny::testServer(
        oauth_module_server,
        args = list(id = "auth", client = client, auto_redirect = FALSE),
        {
          session[["setInputs"]](shinyOAuth_sid = browser)
          session[["flushReact"]]()
          values[[".process_query"]](
            responses[[mode]][["headers"]][["Location"]],
            current_uri = client@redirect_uri
          )
          session[["flushReact"]]()
          expect_true(values[["authenticated"]])
          expect_identical(exchanges, 1L)
        }
      )
    }
  }
})

test_that("sealed callbacks with the wrong transport cannot be consumed", {
  for (mode in c("query", "form_post")) {
    client <- make_test_client(response_mode = mode)
    browser <- valid_browser_token()
    state <- parse_query_param(
      prepare_call(client, browser),
      "state",
      decode = TRUE
    )
    state_payload <- state_payload_decrypt_validate(client, state)
    handle <- oauth_form_post_store_set(
      client,
      "auth",
      list(
        code = "code",
        state = state,
        transport = if (mode == "query") "form_post" else "query"
      )
    )
    local_mocked_bindings(swap_code_for_token_set = function(...) {
      stop("Must reject before token exchange")
    })
    shiny::testServer(
      oauth_module_server,
      args = list(id = "auth", client = client, auto_redirect = FALSE),
      {
        session[["setInputs"]](shinyOAuth_sid = browser)
        session[["flushReact"]]()
        values[[".process_query"]](
          paste0(
            "?shinyOAuth_form_post=",
            handle,
            "&shinyOAuth_form_post_id=auth"
          ),
          current_uri = client@redirect_uri
        )
        session[["flushReact"]]()
        expect_false(values[["authenticated"]])
        expect_identical(values[["error"]], "invalid_callback_query")
        expect_true(is.list(state_store_get(client, state_payload[["state"]])))
      }
    )
  }
})
