# Keycloak: client_secret_jwt (HMAC) playground
#
# What this shows
# - Using RFC 7523 client assertions signed with your Keycloak client's SECRET
#   (token_auth_style = "client_secret_jwt").
# - Runs a tiny Shiny app that performs the Authorization Code flow with PKCE.
#
# 1) Start Keycloak locally (Docker)
#    - Windows bash shell command:
#
#      docker run --rm \
#        -p 127.0.0.1:8080:8080 \
#        -e KC_BOOTSTRAP_ADMIN_USERNAME=admin \
#        -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
#        quay.io/keycloak/keycloak:26.4.0 start-dev
#
# 2) In Keycloak Admin UI (http://localhost:8080)
#    - Log in with admin/admin (from the command above)
#    - Create a realm (or use "master"). Below assumes realm = master.
#    - Clients -> Create client
#      - Client type: OpenID Connect
#      - Client ID: so-hmac
#      - Capabilities -> Client authentication: ON (confidential)
#      - Standard flow: ON
#      - Valid redirect URIs: http://127.0.0.1:8101
#      - Web origins: http://127.0.0.1:8101
#      - PKCE method: S256 (recommended)
#      - Save
#    - Credentials tab
#      - Client Authenticator: Signed JWT with Client Secret
#      - Signature algorithm: HS256 (default here; HS384/HS512 also work)
#      - Note the client Secret value (or regenerate if you prefer)
#
# 3) Provide your client credentials to this script
#    - Set environment variables (recommended):
#        OAUTH_CLIENT_ID=so-hmac
#        OAUTH_CLIENT_SECRET=<the client secret from Credentials tab>
#    - Or edit the values below inline.
#
# 4) Run this script; a Shiny app will open on http://127.0.0.1:8101

devtools::load_all()

options(shinyOAuth.print_errors = TRUE)
options(shinyOAuth.print_traceback = TRUE)

library(shiny)

# ---------- Config ----------
issuer <- "http://localhost:8080/realms/master"

client_id <- Sys.getenv("OAUTH_CLIENT_ID", unset = "so-hmac")
client_secret <- Sys.getenv("OAUTH_CLIENT_SECRET", unset = "")
redirect_uri <- "http://127.0.0.1:8101"

stopifnot(nzchar(client_secret))

# Provider via OIDC discovery; force client_secret_jwt
provider <- oauth_provider_oidc_discover(
  issuer = issuer,
  name = "keycloak-hmac",
  token_auth_style = "client_secret_jwt"
)

client <- oauth_client(
  provider = provider,
  client_id = client_id,
  client_secret = client_secret,
  redirect_uri = redirect_uri,
  scopes = c("openid")
)

# ---------- Shiny app ----------
ui <- fluidPage(
  use_shinyOAuth(),
  h3("Keycloak client_secret_jwt demo"),
  uiOutput("oauth_error"),
  tags$hr(),
  h4("Auth object (summary)"),
  verbatimTextOutput("auth_print"),
  tags$hr(),
  h4("User info"),
  verbatimTextOutput("user_info")
)

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

app <- shinyApp(ui, server)
shiny::runApp(app, port = 8101)
