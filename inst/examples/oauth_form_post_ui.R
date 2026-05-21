if (
  # Example requires a local or remote Keycloak realm whose client allows
  # http://127.0.0.1:8100/callback as a valid redirect URI.
  nzchar(Sys.getenv("KEYCLOAK_BASE_URL")) &&
    nzchar(Sys.getenv("KEYCLOAK_REALM")) &&
    nzchar(Sys.getenv("KEYCLOAK_CLIENT_ID")) &&
    interactive()
) {
  library(shiny)
  library(shinyOAuth)

  provider <- oauth_provider_keycloak(
    base_url = Sys.getenv("KEYCLOAK_BASE_URL"),
    realm = Sys.getenv("KEYCLOAK_REALM")
  )

  client <- oauth_client(
    provider = provider,
    client_id = Sys.getenv("KEYCLOAK_CLIENT_ID"),
    client_secret = Sys.getenv("KEYCLOAK_CLIENT_SECRET"),
    redirect_uri = "http://127.0.0.1:8100/callback",
    scopes = c("openid", "profile", "email"),
    response_mode = "form_post"
  )

  base_ui <- fluidPage(
    uiOutput("login")
  )

  ui <- oauth_form_post_ui(base_ui, id = "auth", client = client)

  server <- function(input, output, session) {
    auth <- oauth_module_server("auth", client, auto_redirect = TRUE)

    output$login <- renderUI({
      if (auth$authenticated) {
        user_info <- auth$token@userinfo
        tagList(
          tags$p("You are logged in!"),
          tags$pre(paste(capture.output(str(user_info)), collapse = "\n"))
        )
      } else {
        tags$p("You are not logged in.")
      }
    })
  }

  runApp(
    shinyApp(ui, server, uiPattern = ".*"),
    port = 8100,
    launch.browser = FALSE
  )
}
