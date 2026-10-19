test_that("browser acknowledgment follows cookie expiry, deletion and blocking", {
  skip_if(Sys.which("node") == "")
  output <- system2(
    Sys.which("node"),
    c(
      shQuote(test_path("..", "browser-cookie-ack.cjs")),
      shQuote(system.file("www", "shinyOAuth.js", package = "shinyOAuth"))
    ),
    stdout = TRUE,
    stderr = TRUE
  )
  expect_null(
    attr(output, "status", exact = TRUE),
    info = paste(output, collapse = "\n")
  )
})

test_that("browser token input is validated before coercion or truncation", {
  withr::local_options(shinyOAuth.skip_browser_token = FALSE)
  repairs <- 0L
  events <- new.env(parent = emptyenv())
  events[["invalid"]] <- list()
  local_mocked_bindings(
    send_oauth_module_set_browser_token = function(...) {
      repairs <<- repairs + 1L
    },
    audit_event = function(type, context = list(), ...) {
      if (identical(type, "invalid_browser_token")) {
        events[["invalid"]][[length(events[["invalid"]]) + 1L]] <- list(
          reason = context[["reason"]],
          length = context[["length"]]
        )
      }
    },
    .package = "shinyOAuth"
  )
  client <- make_test_client(use_nonce = FALSE)
  shiny::testServer(
    oauth_module_server,
    args = list(id = "auth", client = client, auto_redirect = FALSE),
    {
      session[["flushReact"]]()
      token <- valid_browser_token()
      for (invalid in list(
        c(token, "extra"),
        list(token),
        list(token, "extra"),
        rep(token, 1024L),
        42L
      )) {
        session[["setInputs"]](shinyOAuth_sid = token)
        expect_identical(values[["browser_token"]], token)
        before <- repairs
        events[["invalid"]] <- list()
        session[["setInputs"]](shinyOAuth_sid = invalid)
        expect_null(values[["browser_token"]])
        expect_identical(repairs, before + 1L)
        expect_identical(
          events[["invalid"]],
          list(list(
            reason = "validation_failed",
            length = NA_integer_
          ))
        )
      }
      session[["setInputs"]](shinyOAuth_sid = token)
      expect_identical(values[["browser_token"]], token)
      expect_length(client@state_store[["keys"]](), 0L)
    }
  )
})

test_that("new login state waits for the current browser cookie acknowledgment", {
  withr::local_options(shinyOAuth.skip_browser_token = FALSE)
  client <- make_test_client(use_nonce = FALSE)
  shiny::testServer(
    oauth_module_server,
    args = list(id = "auth", client = client, auto_redirect = FALSE),
    {
      session[["flushReact"]]()
      old <- valid_browser_token()
      session[["setInputs"]](shinyOAuth_sid = old)
      before <- client@state_store[["keys"]]()
      result <- NULL
      promises::then(values[["build_auth_url"]](), function(url) {
        result <<- url
      })
      fresh <- browser_ack[["token"]]
      expect_false(identical(fresh, old))
      expect_null(result)
      expect_identical(client@state_store[["keys"]](), before)
      session[["setInputs"]](
        shinyOAuth_cookie_ack = list(requestId = "stale", token = old)
      )
      later::run_now()
      session[["flushReact"]]()
      expect_null(result)
      session[["setInputs"]](
        shinyOAuth_cookie_ack = list(
          requestId = browser_ack[["id"]],
          token = old
        )
      )
      later::run_now()
      session[["flushReact"]]()
      expect_null(result)
      expect_identical(client@state_store[["keys"]](), before)
      session[["setInputs"]](
        shinyOAuth_sid = fresh,
        shinyOAuth_cookie_ack = list(requestId = browser_ack[["id"]])
      )
      for (i in seq_len(8)) {
        later::run_now()
        session[["flushReact"]]()
      }
      expect_true(is.character(result) && nzchar(result))
      expect_identical(values[["browser_token"]], fresh)
      payload <- state_payload_decrypt_validate(
        client,
        parse_query_param(result, "state")
      )
      expect_error(
        handle_callback(
          client,
          code = "x",
          state = parse_query_param(result, "state"),
          browser_token = old
        ),
        "Browser token mismatch"
      )
      # Blocked cookies stop a subsequent login before creating any state.
      before <- client@state_store[["keys"]]()
      values[["request_login"]]()
      session[["setInputs"]](shinyOAuth_cookie_error = "cookie_unavailable")
      for (i in seq_len(8)) {
        later::run_now()
        session[["flushReact"]]()
      }
      expect_identical(client@state_store[["keys"]](), before)
      expect_false(values[["pending_login"]])
      expect_identical(values[["error"]], "browser_cookie_error")
    }
  )
})
