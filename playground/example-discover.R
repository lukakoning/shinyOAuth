devtools::load_all()

options(shinyOAuth.print_errors = TRUE)
options(shinyOAuth.print_traceback = TRUE)

library(shiny)
library(shinyjs)

# Configure provider and client (Google OIDC)
provider <- oauth_provider_oidc_discover(
  # Microsoft example
  issuer = "https://login.microsoftonline.com/common/v2.0",
  # Optional overrides
  name = "example-idp",
  id_token_validation = TRUE,
  # Allow only asymmetric algs by default; include "HS256" only if you use it
  allowed_algs = c("RS256", "ES256")
)

client <- oauth_client(
  provider = provider,
  client_id = Sys.getenv("GOOGLE_OAUTH_CLIENT_ID"),
  client_secret = Sys.getenv("GOOGLE_OAUTH_CLIENT_SECRET"),
  redirect_uri = "http://localhost:8100",
  scopes = c("openid", "email", "profile")
)

# UI
ui <- fluidPage(
  use_shinyOAuth(),
  useShinyjs(),
  h3("OAuth demo (Google OIDC)"),
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
    tok <- auth$token
    err <- auth$error

    paste0(
      "Has token? ",
      if (!is.null(tok)) "YES" else "NO",
      "\n",
      "Has error? ",
      if (!is.null(err)) "YES" else "NO",
      "\n\n",
      "Token (str):\n",
      paste(capture.output(str(tok)), collapse = "\n")
    )
  })

  output$user_info <- renderPrint({
    req(auth$token)
    auth$token@user
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
