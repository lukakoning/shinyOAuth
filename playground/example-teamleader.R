# Teamleader Focus OAuth 2.0 provider configuration

devtools::load_all()
library(shiny)

provider <- oauth_provider(
  name = "teamleader",
  auth_url = "https://focus.teamleader.eu/oauth2/authorize",
  token_url = "https://focus.teamleader.eu/oauth2/access_token",
  userinfo_url = "https://api.focus.teamleader.eu/users.me"
)

client <- oauth_client(
  provider = provider,
  client_id = Sys.getenv("TEAMLEADER_CLIENT_ID"),
  client_secret = Sys.getenv("TEAMLEADER_CLIENT_SECRET"),
  redirect_uri = "http://127.0.0.1:8100"
)


# UI
ui <- fluidPage(
  use_shinyOAuth(),
  h3("OAuth demo (Teamleader)"),
  uiOutput("oauth_error"),
  tags$hr(),
  h4("Auth object (summary)"),
  verbatimTextOutput("auth_print"),
  tags$hr(),
  h4("User info"),
  verbatimTextOutput("user_info")
)

# Server
server <- function(input, output, session) {
  # Start OAuth flow via module and receive results
  auth <- oauth_module_server("auth", client)

  output$auth_print <- renderText({
    authenticated <- auth$authenticated
    tok <- auth$token
    err <- auth$error

    paste0(
      "Authenticated?",
      if (isTRUE(authenticated)) " YES" else " NO",
      "\n",
      "Has token? ",
      if (!is.null(tok)) "YES" else "NO",
      "\n",
      "Has error? ",
      if (!is.null(err)) "YES" else "NO",
      "\n\n",
      "Token present: ",
      !is.null(tok),
      "\n",
      "Has refresh token: ",
      !is.null(tok) && isTRUE(nzchar(tok@refresh_token %||% "")),
      "\n",
      "Has ID token: ",
      !is.null(tok) && !is.na(tok@id_token),
      "\n",
      "Expires at: ",
      if (!is.null(tok)) tok@expires_at else "N/A"
    )
  })

  output$user_info <- renderPrint({
    req(auth$token)
    auth$token@userinfo
  })

  output$oauth_error <- renderUI({
    if (!is.null(auth$error)) {
      msg <- auth$error
      if (!is.null(auth$error_description)) {
        msg <- paste0(msg, ": ", auth$error_description)
      }
      div(class = "alert alert-danger", role = "alert", msg)
    }
  })
}

# Run
app <- shinyApp(ui, server)
shiny::runApp(app, port = 8100)
