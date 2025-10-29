# Minimal Shiny app for Cloud Run using shinyOAuth (GitHub)
# Reads configuration from environment variables:
# - GITHUB_OAUTH_CLIENT_ID
# - GITHUB_OAUTH_CLIENT_SECRET
# - OAUTH_REDIRECT_URI (must exactly match your Cloud Run URL registered in GitHub OAuth app)

library(shiny)
library(shinyOAuth)

# Helpful diagnostics in container logs
options(shinyOAuth.print_errors = TRUE)
options(shinyOAuth.print_traceback = TRUE)

# Provider and client configured via env vars
provider <- oauth_provider_github()
client <- oauth_client(
  provider      = provider,
  client_id     = Sys.getenv("GITHUB_OAUTH_CLIENT_ID", ""),
  client_secret = Sys.getenv("GITHUB_OAUTH_CLIENT_SECRET", ""),
  # For Cloud Run, set this to the service URL, e.g. https://<service>-<hash>-<region>.a.run.app
  redirect_uri  = Sys.getenv("OAUTH_REDIRECT_URI", paste0("http://127.0.0.1:", Sys.getenv("PORT", "8100"))),
  scopes        = character(0) # add scopes if you need more than public user info
)

ui <- fluidPage(
  use_shinyOAuth(),
  titlePanel("shinyOAuth on Cloud Run (GitHub)"),
  fluidRow(
    column(
      width = 4,
      div(style = "margin-bottom: 1rem;",
          actionButton("login_btn", "Login with GitHub", class = "btn-primary"),
          actionButton("logout_btn", "Logout", class = "btn-secondary", style = "margin-left: .5rem;")
      ),
      uiOutput("oauth_error"),
      tags$hr(),
      h4("Auth summary"),
      verbatimTextOutput("auth_print"),
      tags$hr(),
      h4("User info"),
      verbatimTextOutput("user_info")
    )
  )
)

server <- function(input, output, session) {
  # Keep login manual to avoid redirecting Cloud Run health checks
  auth <- oauth_module_server(
    "auth",
    client,
    auto_redirect = FALSE
  )

  observeEvent(input$login_btn, {
    auth$request_login()
  })

  observeEvent(input$logout_btn, {
    auth$logout()
  })

  output$auth_print <- renderText({
    authenticated <- auth$authenticated
    tok <- auth$token
    err <- auth$error

    paste0(
      "Authenticated? ", if (isTRUE(authenticated)) "YES" else "NO", "\n",
      "Has token? ", if (!is.null(tok)) "YES" else "NO", "\n",
      "Has error? ", if (!is.null(err)) "YES" else "NO", "\n\n",
      "Token (str):\n",
      paste(capture.output(str(tok)), collapse = "\n")
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

shinyApp(ui, server)
