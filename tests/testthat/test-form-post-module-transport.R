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
