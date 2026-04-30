# Launch Keycloak with:
#   docker run -p 127.0.0.1:8080:8080 -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin quay.io/keycloak/keycloak:26.4.0 start-dev
# Go to localhost:8080, login with admin/admin, then 'Clients' -> 'Create client'
# -> set type 'OpenID Connect'; set client ID 'test' -> set PKCE 'S256'
# -> set redirect URI to 'http://127.0.0.1:8100' -> Save

devtools::load_all()

library(shiny)

# Configure provider and client
provider <- oauth_provider_keycloak(
  base_url = "http://localhost:8080",
  realm = "master"
)
client <- oauth_client(
  provider = provider,
  client_id = "test",
  redirect_uri = "http://127.0.0.1:8100",
  scopes = c("openid")
)

# UI
ui <- fluidPage(
  use_shinyOAuth(),
  h3("OAuth demo (Keycloak)"),
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

  observeEvent(list(auth$error, auth$error_description), {
    if (interactive() && !is.null(auth$error_description)) {
      rlang::inform(c(
        "OAuth error details",
        "i" = paste0("error: ", auth$error),
        "i" = paste0("error_description: ", auth$error_description)
      ))
    }
  }, ignoreInit = TRUE)

  output$oauth_error <- renderUI({
    if (is.null(auth$error)) {
      return(NULL)
    }

    msg <- if (identical(auth$error, "access_denied")) {
      "Sign-in was canceled or denied. Please try again."
    } else {
      "Authentication failed. Please try again."
    }

    div(class = "alert alert-danger", role = "alert", msg)
  })
}

# Run
app <- shinyApp(ui, server)
shiny::runApp(app, port = 8100)
