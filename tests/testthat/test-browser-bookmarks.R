# shinyOAuth-browser-suite

bookmark_binding_app <- function(store, bookmark_dir, scrub_only = FALSE) {
  client <- make_test_client(use_nonce = FALSE)
  ui <- function(request) shiny::fluidPage(
    shinyOAuth::use_shinyOAuth(),
    shiny::textInput("keep", "Keep", "public value"),
    shiny::textInput("dont_save", "Private", "app private value"),
    shiny::actionButton("bookmark", "Bookmark"),
    shiny::actionButton("prepare", "Prepare login"),
    shiny::verbatimTextOutput("bookmark_url"),
    shiny::verbatimTextOutput("prepared_url"),
    shiny::verbatimTextOutput("binding"),
    shiny::verbatimTextOutput("state_count"),
    shiny::verbatimTextOutput("auth_error"),
    shiny::verbatimTextOutput("authenticated")
  )
  server <- function(input, output, session) {
    shiny::shinyOptions(bookmarkStore = store, save.interface = function(id, callback) {
      path <- file.path(bookmark_dir, id)
      dir.create(path, recursive = TRUE)
      callback(path)
    })
    shiny::setBookmarkExclude(c("dont_save", "bookmark", "prepare"))
    if (scrub_only) {
      # Simulate another bookmark hook discarding the normal exclusions.
      shiny::onBookmark(function(state) state$exclude <- "dont_save")
    }
    client@redirect_uri <- shiny::isolate(paste0(
      session$clientData$url_protocol, "//", session$clientData$url_hostname,
      ":", session$clientData$url_port, session$clientData$url_pathname
    ))
    auth <- shinyOAuth::oauth_module_server("auth", client, auto_redirect = FALSE)
    shiny::moduleServer("outer", function(input, output, session) {
      shinyOAuth::oauth_module_server("auth", client, auto_redirect = FALSE)
    })
    saved <- shiny::reactiveVal("")
    prepared <- shiny::reactiveVal("")
    shiny::onBookmarked(saved)
    shiny::observeEvent(input$bookmark, session$doBookmark())
    shiny::observeEvent(input$prepare, {
      promises::then(auth$build_auth_url(), prepared)
      invisible(NULL)
    })
    output$bookmark_url <- shiny::renderText(saved())
    output$prepared_url <- shiny::renderText(prepared())
    output$binding <- shiny::renderText(auth$browser_token)
    output$state_count <- shiny::renderText({
      prepared()
      length(client@state_store$keys())
    })
    output$auth_error <- shiny::renderText(auth$error)
    output$authenticated <- shiny::renderText(auth$authenticated)
  }
  shiny::shinyApp(ui, server, enableBookmarking = store)
}

set_binding_test_inputs <- function(app, inputs) {
  app$run_js(paste0(
    "Object.entries(", jsonlite::toJSON(inputs, auto_unbox = TRUE),
    ").forEach(([name, value]) => Shiny.setInputValue(name, value, {priority: 'event'}));"
  ))
  app$wait_for_idle()
}

for (store in c("url", "server")) {
  for (scrub_only in c(FALSE, TRUE)) {
    test_that(paste(store, "bookmarks omit private module inputs; hook", scrub_only), {
      skip_if_not(tolower(Sys.getenv("SHINYOAUTH_BROWSER_TESTS")) == "true")
      bookmark_dir <- withr::local_tempdir()
      app <- shinytest2::AppDriver$new(
        bookmark_binding_app(store, bookmark_dir, scrub_only),
        load_timeout = 15000
      )
      on.exit(stop_test_app_driver(app), add = TRUE)
      app$wait_for_js("document.getElementById('binding').innerText.length === 128")
      token <- app$get_value(output = "binding")
      # Include legacy acknowledgment shapes and nested module inputs. The hook
      # must cover these even though current JS no longer duplicates the token.
      for (prefix in c("auth-", "outer-auth-")) {
        inputs <- list(token, list(requestId = "bookmark", token = token), token)
        names(inputs) <- paste0(prefix, c(
          "shinyOAuth_sid", "shinyOAuth_cookie_ack", "shinyOAuth_cookie_error"
        ))
        set_binding_test_inputs(app, inputs)
      }
      app$click("bookmark")
      app$wait_for_js("document.getElementById('bookmark_url').innerText.includes('?')")
      url <- app$get_value(output = "bookmark_url")
      if (store == "url") {
        serialized <- utils::URLdecode(url)
        expect_match(serialized, "keep=")
        expect_match(serialized, "public value", fixed = TRUE)
      } else {
        files <- list.files(bookmark_dir, "input[.]rds$", recursive = TRUE, full.names = TRUE)
        expect_length(files, 1L)
        saved <- readRDS(files[[1]])
        expect_identical(saved$keep, "public value")
        serialized <- jsonlite::toJSON(saved, auto_unbox = TRUE)
      }
      expect_false(grepl("shinyOAuth_(sid|cookie_ack|cookie_error)", serialized))
      expect_false(grepl(token, serialized, fixed = TRUE))
      expect_false(grepl("dont_save|app private value", serialized))
    })
  }
}

test_that("a disclosed binding cannot select login state or validate a swapped callback", {
  skip_if_not(tolower(Sys.getenv("SHINYOAUTH_BROWSER_TESTS")) == "true")
  app <- shinytest2::AppDriver$new(
    bookmark_binding_app("url", withr::local_tempdir()), load_timeout = 15000
  )
  on.exit(stop_test_app_driver(app), add = TRUE)
  app$wait_for_js("document.getElementById('binding').innerText.length === 128")
  previous <- app$get_value(output = "binding")
  # Hold delivery of the new binding; all values here belong to this local
  # fixture. No IdP authorization or token exchange is needed for rejection.
  app$run_js(paste0(
    "Shiny.addCustomMessageHandler('shinyOAuth:setBrowserToken', ",
    "function(payload) { window.pendingBinding = payload; });"
  ))
  app$click("prepare")
  app$wait_for_js("!!window.pendingBinding && !!window.pendingBinding.requestId")
  pending <- app$get_js("window.pendingBinding")
  expect_false(identical(pending$token, previous))
  set_binding_test_inputs(app, list(
    `auth-shinyOAuth_sid` = previous,
    `auth-shinyOAuth_cookie_ack` = list(requestId = pending$requestId, token = previous)
  ))
  expect_identical(app$get_value(output = "prepared_url"), "")
  expect_identical(app$get_value(output = "state_count"), "0")
  # Accept only the server-selected value, leaving the old cookie in place.
  set_binding_test_inputs(app, list(
    `auth-shinyOAuth_sid` = pending$token,
    `auth-shinyOAuth_cookie_ack` = list(requestId = pending$requestId)
  ))
  app$wait_for_js("document.getElementById('prepared_url').innerText.includes('state=')")
  url <- app$get_value(output = "prepared_url")
  callback <- paste0(
    parse_query_param(url, "redirect_uri", decode = TRUE),
    "?code=unused-local-fixture&state=", parse_query_param(url, "state")
  )
  app$get_chromote_session()$go_to(callback)
  app$wait_for_js("document.getElementById('auth_error')?.innerText === 'invalid_state'")
  # A full navigation replaces shinytest2's injected tracer; read the live DOM.
  expect_identical(app$get_js("document.getElementById('binding').innerText"), previous)
  expect_identical(app$get_js("document.getElementById('state_count').innerText"), "1")
  expect_identical(app$get_js("document.getElementById('authenticated').innerText"), "FALSE")
})
