# Minimal Shiny app for Cloud Run using shinyOAuth (GitHub)
# Reads configuration from environment variables:
# - GITHUB_OAUTH_CLIENT_ID
# - GITHUB_OAUTH_CLIENT_SECRET
# - OAUTH_REDIRECT_URI (must exactly match your Cloud Run URL registered in GitHub OAuth app)

library(shiny)
library(shinyOAuth)

# Helpful diagnostics in container logs (only when SHINYOAUTH_DEBUG is set)
debug_enabled <- tolower(Sys.getenv("SHINYOAUTH_DEBUG", "false")) == "true"
options(shinyOAuth.print_errors = debug_enabled)
options(shinyOAuth.print_traceback = debug_enabled)

# Provider and client configured via env vars.
#
# Cloud Run will fail the deployment if the process exits during startup.
# In practice, missing/invalid OAuth env vars can cause `oauth_client()` to
# throw (e.g., empty client_id), which would crash the container before it
# starts listening on $PORT.
provider <- oauth_provider_github()

client_id <- Sys.getenv("GITHUB_OAUTH_CLIENT_ID", "")
client_secret <- Sys.getenv("GITHUB_OAUTH_CLIENT_SECRET", "")
redirect_uri <- Sys.getenv("OAUTH_REDIRECT_URI", "")

client_or_error <- tryCatch(
  {
    if (!nzchar(client_id) || !nzchar(client_secret) || !nzchar(redirect_uri)) {
      stop("Missing required environment variables")
    }
    oauth_client(
      provider = provider,
      client_id = client_id,
      client_secret = client_secret,
      redirect_uri = redirect_uri,
      scopes = character(0) # add scopes if you need more than public user info
    )
  },
  error = function(e) {
    e
  }
)

if (inherits(client_or_error, "error")) {
  ui <- fluidPage(
    use_shinyOAuth(),
    titlePanel("shinyOAuth on Cloud Run (GitHub)"),
    div(
      class = "alert alert-warning",
      role = "alert",
      tags$p(
        "OAuth client configuration is missing or invalid. The app is running so",
        "Cloud Run health checks can succeed, but login is disabled until the",
        "required environment variables are set."
      ),
      tags$ul(
        tags$li(tags$code("GITHUB_OAUTH_CLIENT_ID")),
        tags$li(tags$code("GITHUB_OAUTH_CLIENT_SECRET")),
        tags$li(tags$code("OAUTH_REDIRECT_URI"))
      ),
      tags$details(
        tags$summary("Startup error"),
        tags$pre(conditionMessage(client_or_error))
      )
    )
  )
  server <- function(input, output, session) {}
  shinyApp(ui, server)
} else {
  client <- client_or_error

  ui <- fluidPage(
    use_shinyOAuth(),
    titlePanel("shinyOAuth on Cloud Run (GitHub)"),
    fluidRow(
      column(
        width = 4,
        div(
          style = "margin-bottom: 1rem;",
          actionButton("login_btn", "Login with GitHub", class = "btn-primary"),
          actionButton(
            "logout_btn",
            "Logout",
            class = "btn-secondary",
            style = "margin-left: .5rem;"
          )
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
        "Authenticated? ",
        if (isTRUE(authenticated)) "YES" else "NO",
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

  shinyApp(ui, server)
}
