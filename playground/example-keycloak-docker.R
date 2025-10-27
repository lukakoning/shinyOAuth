# Run Keycloak via Docker first:
#   cd integration/keycloak && docker compose up -d
# This app will use the realm 'shinyoauth' and client 'shiny-public'.

options(shinyOAuth.print_errors = TRUE)
options(shinyOAuth.print_traceback = TRUE)

library(shiny)
library(shinyOAuth)

auth_port <- as.integer(Sys.getenv("SHINYOAUTH_APP_PORT", "3000"))

provider <- oauth_provider_keycloak(
  base_url = "http://localhost:8080",
  realm = "shinyoauth"
)
client <- oauth_client(
  provider = provider,
  client_id = Sys.getenv("KEYCLOAK_CLIENT_ID", "shiny-public"),
  client_secret = Sys.getenv("KEYCLOAK_CLIENT_SECRET", ""),
  redirect_uri = sprintf("http://localhost:%d/callback", auth_port),
  scopes = c("openid", "profile", "email")
)

ui <- fluidPage(
  use_shinyOAuth(),
  h3("shinyOAuth + Keycloak (Docker)"),
  actionButton("login_btn", "Login"),
  actionButton("logout_btn", "Logout"),
  tags$hr(),
  h4("Auth state"),
  verbatimTextOutput("auth_state"),
  tags$hr(),
  h4("User info"),
  verbatimTextOutput("user_info")
)

server <- function(input, output, session) {
  auth <- oauth_module_server("auth", client)

  observeEvent(input$login_btn, ignoreInit = TRUE, {
    auth$request_login()
  })
  observeEvent(input$logout_btn, ignoreInit = TRUE, {
    auth$logout()
  })

  output$auth_state <- renderText({
    paste(
      "authenticated:",
      isTRUE(auth$authenticated),
      "has_token:",
      !is.null(auth$token),
      "error:",
      if (!is.null(auth$error)) auth$error else "<none>"
    )
  })

  output$user_info <- renderPrint({
    if (is.null(auth$token)) {
      return("<not logged in>")
    }
    auth$token@userinfo
  })
}

app <- shinyApp(ui, server)
shiny::runApp(app, port = auth_port, host = "127.0.0.1")
