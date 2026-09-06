testthat::test_that("browser fixture recovery restores the origin record and cookie marker", {
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
      shiny::verbatimTextOutput("binding")
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
    }
  )
  drv <- shinytest2::AppDriver$new(app, load_timeout = 15000)
  on.exit(keycloak_stop_app_driver(drv), add = TRUE)
  drv$wait_for_js("document.getElementById('binding').innerText.length === 128")
  initial <- drv$get_value(output = "binding")
  cookie <- find_browser_token_cookie(drv, "auth")
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
})
