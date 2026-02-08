# Keycloak: private_key_jwt (asymmetric) playground
#
# What this shows
# - Using RFC 7523 client assertions signed with YOUR client private key
#   (token_auth_style = "private_key_jwt").
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
#      - Client ID: so-pk
#      - Capabilities -> Client authentication: ON (confidential)
#      - Standard flow: ON
#      - Valid redirect URIs: http://127.0.0.1:8102
#      - Web origins: http://127.0.0.1:8102
#      - PKCE method: S256 (recommended)
#      - Save
#    - Credentials tab
#      - Client Authenticator: Signed JWT issued by the client
#        (this is the private_key_jwt method)
#      - Optionally restrict Signature algorithm to RS256
#    - Keys tab (client level)
#      - Generate new keys OR Import your client public key (certificate/JWKS)
#      - If you generate keys in Keycloak, download the private key archive,
#        extract the client private key, and save it as PEM locally, e.g.,
#        playground/client-private-key.pem
#      - Note the Key ID (kid) shown for the client key; copy it for use below
#
# 3) Provide your client credentials to this script
#    - Set environment variables (recommended):
#        OAUTH_CLIENT_ID=so-pk
#        OAUTH_CLIENT_PRIVATE_KEY_PATH=playground/client-private-key.pem
#        # Optional but recommended if your key has a known kid:
#        OAUTH_CLIENT_PRIVATE_KEY_KID=<kid-from-client-keys-tab>
#    - Or edit the values below inline.
#
# 4) Run this script; a Shiny app will open on http://127.0.0.1:8102

devtools::load_all()

options(shinyOAuth.print_errors = TRUE)
options(shinyOAuth.print_traceback = TRUE)

library(shiny)

# ---------- Config ----------
issuer <- "http://localhost:8080/realms/master"

client_id <- Sys.getenv("OAUTH_CLIENT_ID", unset = "so-pk")
key_path <- Sys.getenv("OAUTH_CLIENT_PRIVATE_KEY_PATH", unset = "")
key_kid <- Sys.getenv("OAUTH_CLIENT_PRIVATE_KEY_KID", unset = "")
redirect_uri <- "http://127.0.0.1:8102"

if (!nzchar(key_path) || !file.exists(key_path)) {
  stop("Set OAUTH_CLIENT_PRIVATE_KEY_PATH to a readable PEM file path")
}

# Provider via OIDC discovery; force private_key_jwt
provider <- oauth_provider_oidc_discover(
  issuer = issuer,
  name = "keycloak-pk",
  token_auth_style = "private_key_jwt"
)

# Read PEM as a single string
pem <- readChar(key_path, file.info(key_path)$size)

client <- oauth_client(
  provider = provider,
  client_id = client_id,
  # client_secret is not used for private_key_jwt
  client_secret = "",
  redirect_uri = redirect_uri,
  scopes = c("openid"),
  client_private_key = pem,
  client_private_key_kid = if (nzchar(key_kid)) key_kid else NULL
)

# ---------- Shiny app ----------
ui <- fluidPage(
  use_shinyOAuth(),
  h3("Keycloak private_key_jwt demo"),
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
shiny::runApp(app, port = 8102)
