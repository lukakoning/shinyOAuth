test_that("browser rejection redirects erase callback queries and inherited fragments", {
  skip_if_not_installed("chromote")
  skip_if_not_installed("webfakes")
  skip_if(Sys.getenv("SHINYOAUTH_BROWSER_TESTS") != "true")
  for (post in c(FALSE, TRUE)) {
    client <- make_test_client(
      response_mode = if (post) "form_post" else "query"
    )
    client@redirect_uri <- "http://localhost:8100/callback"
    rendered <- 0L
    ui <- (if (post) oauth_form_post_ui else oauth_ui)(
      function(req) {
        rendered <<- rendered + 1L
        shiny::fluidPage("Application content")
      },
      "auth",
      client
    )
    encoded <- "code=SECRET-CODE&error=access_denied&state=SECRET-STATE"
    request <- if (post) {
      callback_rejection_request("code=SECRET-URL", encoded)
    } else {
      callback_rejection_request(encoded)
    }
    rejected <- ui(request)
    final <- callback_rejection_terminal(ui, request, rejected)
    expect_identical(rejected[["status"]], 303L)
    expect_identical(final[["status"]], 400L)
    expect_identical(rendered, 0L)
    # Serve responses produced by the real HTTP wrapper, as in the GET bridge
    # browser test. This controls browser navigation/fragment behavior; provider
    # exchange and the wrapper's one-use storage are tested separately.
    app <- webfakes::new_app()
    app[["locals"]][["rejected"]] <- rejected
    app[["locals"]][["final"]] <- final
    app[["get"]]("/callback", function(req, res) {
      response <- if (!is.null(req[["query"]][["shinyOAuth_callback_error"]])) {
        app[["locals"]][["final"]]
      } else {
        app[["locals"]][["rejected"]]
      }
      for (header in names(response[["headers"]])) {
        res[["set_header"]](header, response[["headers"]][[header]])
      }
      res[["set_status"]](response[["status"]])[["set_type"]](response[[
        "content_type"
      ]])[["send"]](response[["content"]])
    })
    app[["post"]]("/callback", function(req, res) {
      response <- app[["locals"]][["rejected"]]
      for (header in names(response[["headers"]])) {
        res[["set_header"]](header, response[["headers"]][[header]])
      }
      res[["set_status"]](response[["status"]])[["set_type"]](response[[
        "content_type"
      ]])[["send"]](response[["content"]])
    })
    app[["get"]]("/start", function(req, res) {
      res[["set_type"]]("html")[["send"]](paste0(
        '<!doctype html><form method="post" action="/callback?code=SECRET-URL#SECRET-FRAGMENT">',
        '<input name="code" value="SECRET-CODE"><input name="error" value="access_denied">',
        '<input name="state" value="SECRET-STATE"></form><script>document.forms[0].submit()</script>'
      ))
    })
    server <- webfakes::local_app_process(app)
    withr::defer(server[["stop"]](), envir = environment())
    browser <- chromote::ChromoteSession[["new"]]()
    withr::defer(browser[["close"]](), envir = environment())
    target <- server[["url"]](
      if (post) "/start" else paste0("/callback?", encoded, "#SECRET-FRAGMENT")
    )
    browser[["Page"]][["navigate"]](target)
    deadline <- Sys.time() + 15
    repeat {
      value <- browser[["Runtime"]][["evaluate"]](paste0(
        "JSON.stringify({href:location.href,hash:location.hash,",
        "body:document.body&&document.body.textContent})"
      ))[["result"]][["value"]]
      observed <- if (is.character(value)) jsonlite::fromJSON(value) else NULL
      if (
        !is.null(observed) &&
          grepl(
            "shinyOAuth_callback_error=",
            observed[["href"]],
            fixed = TRUE
          ) &&
          grepl(
            "must not contain both code and error",
            observed[["body"]],
            fixed = TRUE
          )
      ) {
        break
      }
      if (Sys.time() >= deadline) {
        stop("Browser did not reach the clean rejection page")
      }
      Sys.sleep(0.05)
    }
    expect_match(
      observed[["href"]],
      "/callback\\?shinyOAuth_callback_error=ce1_[A-Za-z0-9_-]{43}#?$"
    )
    expect_identical(observed[["hash"]], "")
    expect_false(grepl(
      "SECRET|Application content",
      paste(unlist(observed), collapse = " ")
    ))
    browser[["close"]]()
    server[["stop"]]()
  }
})
# shinyOAuth-browser-suite
