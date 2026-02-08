if (
  # Example requires configured Microsoft Entra ID (Azure AD) tenant:
  nzchar(Sys.getenv("MS_TENANT")) && interactive() && requireNamespace("later")
) {
  library(shiny)
  library(shinyOAuth)

  # Configure provider and client (Microsoft Entra ID with your tenant
  client <- oauth_client(
    provider = oauth_provider_microsoft(
      # Provide your own tenant ID here (set as environment variable MS_TENANT)
      tenant = Sys.getenv("MS_TENANT")
    ),
    # Default Azure CLI app ID (public client; activated in many tenants):
    client_id = "04b07795-8ddb-461a-bbee-02f9e1bf7b46",
    redirect_uri = "http://localhost:8100",
    scopes = c("openid", "profile", "email")
  )

  # UI
  ui <- fluidPage(
    use_shinyOAuth(),
    h3("OAuth demo (Microsoft Entra ID)"),
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

  # Need to open app in 'localhost:8100' to match with redirect_uri
  # of the public Azure CLI app (above). Browser must use 'localhost'
  # too to properly set the browser cookie. But Shiny only redirects to
  # '127.0.0.1' & blocks process once it runs. So we disable browser
  # launch by Shiny & then use 'later::later()' to open the browser
  # ourselves a short moment after the app starts
  later::later(
    function() {
      utils::browseURL("http://localhost:8100")
    },
    delay = 0.25
  )

  # Run app
  runApp(shinyApp(ui, server), port = 8100, launch.browser = FALSE)
}
