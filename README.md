# shinyOAuth

<!-- badges: start -->
[![R-CMD-check](https://github.com/lukakoning/shinyOAuth/actions/workflows/R-CMD-check.yaml/badge.svg)](https://github.com/lukakoning/shinyOAuth/actions/workflows/R-CMD-check.yaml)
[![Integration tests (Keycloak)](https://github.com/lukakoning/shinyOAuth/actions/workflows/integration-tests.yml/badge.svg)](https://github.com/lukakoning/shinyOAuth/actions/workflows/integration-tests.yml)
<!-- badges: end -->

'[shinyOAuth](https://lukakoning.github.io/shinyOAuth/)' is an R package implementing provider‑agnostic OAuth 2.0 and OpenID Connect (OIDC) 
authorization and authentication for [Shiny](https://github.com/rstudio/shiny) apps. It is built
with modern S7 classes and security in mind.

OAuth 2.0/OIDC lets users sign in to your app using accounts they already have (e.g., Google, Microsoft, GitHub, 
and many more), or via your self-hosted identity provider (e.g., Keycloak), or
via an identity-as-a-service provider (e.g., Auth0, Okta).

To achieve this, your app redirects unauthenticated users to the identity provider, they authenticate there, 
and are redirected back to your app with an authorization code. Your app exchanges this code for tokens 
which prove the user's identity, and optionally allow your app to call the provider's APIs on the user's behalf
(e.g., to fetch data associated with the user's account).

This package streamlines this flow for Shiny applications,
enabling developers to add OAuth 2.0/OIDC authorization/authentication to their apps with
minimal code. The provided Shiny module handles redirecting unauthenticated users, 
managing state/PKCE/nonce for secure code-token exchange, 
verifying OIDC tokens, automatically fetching user info and performing token refresh,
using asynchronous execution, and more. The package is highly configurable 
and works with various OAuth 2.0/OIDC providers and protocol features.

## Features

- Shiny module: `oauth_module_server()` gives you a ready‑to‑use OAuth authentication flow
  with secure defaults. Easily read authentication status, token details, & user info as reactive values
  in your Shiny server logic

- S7 classes: `OAuthProvider`, `OAuthClient`, `OAuthToken`, for a structured representation
  of key elements of the OAuth 2.0/OIDC flow

- Functions: `prepare_call()`, `handle_callback()`, `introspect_token()`, `refresh_token()`, and more,
  should you wish to manually implement parts of the OAuth 2.0/OIDC flow

- Provider helpers: you can configure your own OAuth 2.0/OIDC providers, 
  but the package also includes an `oauth_provider_oidc_discover()` function for quick OIDC setup, and
  contains built-in configurations for popular providers (e.g., GitHub, Google, Microsoft, Keycloak, Auth0).
  
- Security best practices: AES-GCM–sealed state payloads (AEAD), server-side state validation coupled with 
  local cookie verification, HTTPS enforcement, PKCE (S256), ID token signature/claims validation (including nonce),
  userinfo subject match, and more (see `vignette("authentication-flow", package = "shinyOAuth")` ([link](https://lukakoning.github.io/shinyOAuth/articles/authentication-flow.html)) for
  more details)

- Provides hooks for auditing & logging key events,
  like login successes or failures (see `vignette("audit-logging", package = "shinyOAuth")` ([link](https://lukakoning.github.io/shinyOAuth/articles/audit-logging.html)) for more details)

## Installation

Install the development version from GitHub:

```r
remotes::install_github("lukakoning/shinyOAuth")
```

Or, install from CRAN (once accepted for release):
```r
install.packages("shinyOAuth")
```

## Usage

For complete usage documentation (i.e., making a manual login button, making authenticated
API calls, setting various options, and a security checklist) see: `vignette("usage", package = "shinyOAuth")` ([link](https://lukakoning.github.io/shinyOAuth/articles/usage.html)).

### Minimal example

Below is a minimal example using a GitHub OAuth 2.0 app. If you want to try
this example yourself, you can register an app at your [GitHub Developer Settings](https://github.com/settings/developers).

```r
library(shiny)
library(shinyOAuth)

# GitHub OAuth provider has been preconfigured in the package
#  - You can quickly configure OIDC providers with `oauth_provider_oidc_discover()`
#  - You can manually configure every other provider with `oauth_provider()`
provider <- oauth_provider_github()

# Build client using your app's ID, secret, & redirect URI:
client <- oauth_client(
  provider = provider,
  client_id = Sys.getenv("GITHUB_OAUTH_CLIENT_ID"),
  client_secret = Sys.getenv("GITHUB_OAUTH_CLIENT_SECRET"),
  redirect_uri = "http://127.0.0.1:8100",
  scopes = c("read:user", "user:email")
)

# Simple UI
ui <- fluidPage(
  # Include JavaScript dependency:
  use_shinyOAuth(),
  # Show login information:
  uiOutput("login_information")
)

# Server which obtains authentication 
server <- function(input, output, session) {
  # Start authentication module; will automatically redirect unauthenticated users
  #   to the provider's login page and handle the callback
  # Returns reactive values with authentication status, token details, user info,
  #   etc.
  auth <- oauth_module_server("auth", client)

  # Render login information:
  output$login_information <- renderUI({
    if (auth$authenticated) {
      user_info <- auth$token@userinfo
      tagList(
        tags$p("You are logged in! Your details:"),
        tags$pre(paste(capture.output(str(user_info)), collapse = "\n"))
      )
    } else {
      tags$p("You are not logged in.")
    }
  })
}

runApp(shinyApp(ui, server), port = 8100)
```

### Logging/auditing

The package provides hooks for logging/auditing crucial events 
(e.g., callbacks issued & received, login success/failures).
See `vignette("audit-logging", package = "shinyOAuth")` ([link](https://lukakoning.github.io/shinyOAuth/articles/audit-logging.html)) for details.

## More information

### What happens during the authentication flow?

For an in-depth step-by-step explanation of what happens during the authentication flow, see: 
`vignette("authentication-flow", package = "shinyOAuth")` ([link](https://lukakoning.github.io/shinyOAuth/articles/authentication-flow.html)).

### What do I need to consider for production use?

For a checklist of security considerations and best practices for production use, see:
`vignette("usage", package = "shinyOAuth")` ([link](https://lukakoning.github.io/shinyOAuth/articles/usage.html#security-checklist)).
