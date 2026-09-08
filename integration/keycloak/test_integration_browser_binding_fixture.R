testthat::test_that("browser fixtures resolve the active transaction and restore its tab binding", {
  provider <- shinyOAuth::oauth_provider(
    name = "fixture",
    auth_url = "http://127.0.0.1:1/authorize",
    token_url = "http://127.0.0.1:1/token",
    issuer = NA_character_
  )
  client <- shinyOAuth::oauth_client(
    provider,
    client_id = "fixture",
    client_secret = "fixture-secret",
    redirect_uri = "http://127.0.0.1:1/callback",
    scopes = character()
  )
  app <- shiny::shinyApp(
    shiny::fluidPage(
      shinyOAuth::use_shinyOAuth(),
      shiny::actionButton("clear", "Clear"),
      shiny::actionButton("set", "Set"),
      shiny::actionButton("prepare", "Prepare login"),
      shiny::verbatimTextOutput("binding"),
      shiny::verbatimTextOutput("auth_url")
    ),
    function(input, output, session) {
      auth <- shinyOAuth::oauth_module_server(
        "auth",
        client,
        auto_redirect = FALSE
      )
      output$binding <- shiny::renderText(auth$browser_token)
      shiny::observeEvent(input$clear, auth$clear_browser_token())
      shiny::observeEvent(input$set, auth$set_browser_token())
      auth_url <- shiny::reactiveVal("")
      shiny::observeEvent(input$prepare, {
        promises::then(auth$build_auth_url(), auth_url)
        invisible(NULL)
      })
      output$auth_url <- shiny::renderText(auth_url())
    }
  )
  drv <- shinytest2::AppDriver$new(app, load_timeout = 15000)
  on.exit(keycloak_stop_app_driver(drv), add = TRUE)
  drv$wait_for_js("document.getElementById('binding').innerText.length === 128")
  initial <- drv$get_value(output = "binding")
  cookie <- find_browser_token_cookie(drv, "auth", client@redirect_uri)
  snapshot <- snapshot_browser_binding(drv, cookie)
  testthat::expect_false(identical(cookie$value, initial))
  drv$click("clear")
  drv$click("set")
  testthat::expect_false(identical(drv$get_value(output = "binding"), initial))
  restore_browser_binding(drv, snapshot)
  drv$click("set")
  testthat::expect_identical(drv$get_value(output = "binding"), initial)
  testthat::expect_identical(
    get_browser_cookie(drv, cookie$name)$value,
    cookie$value
  )

  drv$click("prepare")
  drv$wait_for_js("document.getElementById('auth_url').innerText.length > 0")
  current <- find_browser_token_cookie(drv, "auth", client@redirect_uri)
  testthat::expect_false(is.null(current))
  testthat::expect_false(identical(current$name, cookie$name))
  testthat::expect_identical(
    get_browser_cookie(drv, cookie$name)$value,
    cookie$value
  )
  active <- jsonlite::fromJSON(snapshot_browser_binding(drv, current)$record)
  testthat::expect_identical(active$cookie, current$value)
  testthat::expect_identical(active$token, drv$get_value(output = "binding"))
  testthat::expect_null(find_browser_token_cookie(
    drv,
    "auth",
    "http://127.0.0.1:1/another-callback",
    timeout = 0
  ))
})
