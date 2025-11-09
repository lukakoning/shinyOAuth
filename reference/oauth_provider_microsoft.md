# Create a Microsoft (Entra ID) [OAuthProvider](https://lukakoning.github.io/shinyOAuth/reference/OAuthProvider.md)

Pre-configured
[OAuthProvider](https://lukakoning.github.io/shinyOAuth/reference/OAuthProvider.md)
for Microsoft Entra ID (formerly Azure AD) using the v2.0 endpoints.
Accepts a tenant identifier and configures the authorization, token, and
userinfo endpoints directly (no discovery).

## Usage

``` r
oauth_provider_microsoft(
  name = "microsoft",
  tenant = c("common", "organizations", "consumers"),
  id_token_validation = NULL
)
```

## Arguments

- name:

  Optional friendly name for the provider. Defaults to "microsoft"

- tenant:

  Tenant identifier ("common", "organizations", "consumers", or
  directory GUID). Defaults to "common"

- id_token_validation:

  Optional override (logical). If `NULL` (default), it's enabled
  automatically when `tenant` looks like a GUID, otherwise disabled

## Value

[OAuthProvider](https://lukakoning.github.io/shinyOAuth/reference/OAuthProvider.md)
object configured for Microsoft identity platform

## Details

The `tenant` can be one of the special values "common", "organizations",
or "consumers", or a specific directory (tenant) ID GUID (e.g.,
"00000000-0000-0000-0000-000000000000").

When `tenant` is a specific GUID, the provider will enable strict ID
token validation (issuer match). When using the multi-tenant aliases
("common", "organizations", "consumers"), the exact issuer depends on
the account that signs in and therefore ID token validation is disabled
by default to avoid false negatives. You can override this via
`id_token_validation` if you know the environment guarantees a fixed
issuer.

Microsoft issues RS256 ID tokens; `allowed_algs` is restricted
accordingly. The userinfo endpoint is provided by Microsoft Graph
(https://graph.microsoft.com/oidc/userinfo).

When configuring your
[OAuthClient](https://lukakoning.github.io/shinyOAuth/reference/OAuthClient.md),
if you do not have the option to register an app or simply wish to test
during development, you may be able to use the default Azure CLI public
app, with `client_id` '9391afd1-7129-4938-9e4d-633c688f93c0' (uses
`redirect_uri` 'http://localhost:8100').

## Examples

``` r
if (
  # Example requires configured Microsoft Entra ID (Azure AD) tenant:
  nzchar(Sys.getenv("MS_TENANT"))
  && interactive()
  && requireNamespace("later")
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
```
