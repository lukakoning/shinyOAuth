devtools::load_all()

options(shinyOAuth.print_errors = TRUE)
options(shinyOAuth.print_traceback = TRUE)

library(shiny)

# Configure provider and client (GitHub)
provider <- oauth_provider_github()

client <- oauth_client(
  provider = provider,
  client_id = Sys.getenv("GITHUB_OAUTH_CLIENT_ID"),
  client_secret = Sys.getenv("GITHUB_OAUTH_CLIENT_SECRET"),
  redirect_uri = "http://127.0.0.1:8100",
  scopes = character(0) # add scopes if you need more than public user info
)

# UI
ui <- fluidPage(
  # use_shinyOAuth(),
  h3("OAuth demo (GitHub)"),
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
