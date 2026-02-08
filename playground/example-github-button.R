devtools::load_all()

options(shinyOAuth.allow_insecure_urls = TRUE)
options(shinyOAuth.print_errors = TRUE)
options(shinyOAuth.print_traceback = TRUE)

library(shiny)

provider <- oauth_provider_github()

client <- oauth_client(
  provider = provider,
  client_id = Sys.getenv("GITHUB_OAUTH_CLIENT_ID"),
  client_secret = Sys.getenv("GITHUB_OAUTH_CLIENT_SECRET"),
  redirect_uri = "http://127.0.0.1:8100",
  scopes = character(0)
)

ui <- fluidPage(
  use_shinyOAuth(),
  actionButton("login", "Login with GitHub"),
  verbatimTextOutput("auth_print")
)

server <- function(input, output, session) {
  auth <- oauth_module_server("auth", client, auto_redirect = FALSE)

  observeEvent(input$login, ignoreInit = TRUE, {
    auth$request_login()
  })

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
}

shiny::runApp(shinyApp(ui, server), port = 8100)
