# shinyOAuth

<!-- badges: start -->
[![R-CMD-check](https://github.com/lukakoning/shinyOAuth/actions/workflows/R-CMD-check.yaml/badge.svg)](https://github.com/lukakoning/shinyOAuth/actions/workflows/R-CMD-check.yaml)
[![Integration tests (Keycloak)](https://github.com/lukakoning/shinyOAuth/actions/workflows/integration-tests.yml/badge.svg)](https://github.com/lukakoning/shinyOAuth/actions/workflows/integration-tests.yml)
[![CRAN status](https://www.r-pkg.org/badges/version/shinyOAuth)](https://CRAN.R-project.org/package=shinyOAuth)
<!-- badges: end -->

[shinyOAuth](https://lukakoning.github.io/shinyOAuth/) lets users sign in to
[Shiny](https://github.com/rstudio/shiny) apps with existing accounts, and your
app can call APIs with their permission. It supports OAuth 2.0 authorization
and OpenID Connect (OIDC) authentication.

Users can sign in through Google, Microsoft, a self-hosted provider such as
Keycloak, or an identity service such as Auth0 or Okta. Your app
redirects them to the provider, where they sign in, then exchanges the returned
authorization code for tokens. An OAuth access token lets your app call APIs on
the user's behalf. OIDC adds an ID token that the package validates to identify
the user.

The Shiny module handles redirects, protects the login exchange, validates OIDC
tokens, fetches user information and refreshes tokens. To keep provider requests
from blocking other sessions, enable `async = TRUE` and configure background
workers as described in [Asynchronous execution](https://lukakoning.github.io/shinyOAuth/articles/usage.html#asynchronous-execution).

## Features

- Shiny module: `oauth_module_server()` manages login, callbacks and token refresh.
  It returns reactive values for login status, tokens and user information.

- S7 classes: `OAuthProvider`, `OAuthClient` and `OAuthToken` describe the provider,
  your app's registration and the tokens it receives.

- Functions for custom integrations: use `prepare_call()`, `handle_callback()`,
  `introspect_token()` and `refresh_token()` to manage the flow yourself.

- Provider setup: use built-in helpers for GitHub, Google, Microsoft, Keycloak
  and Auth0, discover OIDC settings with `oauth_provider_oidc_discover()`, or
  configure a provider yourself.

- Login protection: HTTPS enforcement, PKCE, browser-bound state and OIDC token
  validation. DPoP, mTLS, JAR and PAR are available for providers that require them.
  See `vignette("authentication-flow", package = "shinyOAuth")`
  ([online guide](https://lukakoning.github.io/shinyOAuth/articles/authentication-flow.html)).

- Diagnostics: record login successes, failures and other events with audit hooks
  or OpenTelemetry. See `vignette("audit-logging", package = "shinyOAuth")`
  ([online guide](https://lukakoning.github.io/shinyOAuth/articles/audit-logging.html))
  and `vignette("opentelemetry", package = "shinyOAuth")`
  ([online guide](https://lukakoning.github.io/shinyOAuth/articles/opentelemetry.html)).

## Installation

Install from [CRAN](https://CRAN.R-project.org/package=shinyOAuth):

```r
install.packages("shinyOAuth")
```

Install the development version from GitHub:

```r
if (!requireNamespace("remotes", quietly = TRUE)) {
  install.packages("remotes")
}

remotes::install_github("lukakoning/shinyOAuth")
```

## Usage

See `vignette("usage", package = "shinyOAuth")`
([online guide](https://lukakoning.github.io/shinyOAuth/articles/usage.html))
for login buttons, authenticated API calls, configuration and a deployment checklist.

### Minimal example

Register a GitHub OAuth app in your [GitHub Developer Settings](https://github.com/settings/developers),
using `http://127.0.0.1:8100` as the callback URL. Set `GITHUB_OAUTH_CLIENT_ID`
and `GITHUB_OAUTH_CLIENT_SECRET` in your R environment before running the
example. The [environment setup instructions](https://lukakoning.github.io/shinyOAuth/articles/usage.html#github-app-registration)
show how to store these values in `.Renviron`.

```r
library(shiny)
library(shinyOAuth)

# GitHub OAuth 2.0 provider has been preconfigured in the package
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
ui <- oauth_ui(fluidPage(
  # Show login information:
  uiOutput("login_information")
), id = "auth", client = client)

# Server which obtains authentication
server <- function(input, output, session) {
  # Start authentication module; will automatically redirect unauthenticated users
  #   to the provider's login page and handle the callback
  # Returns reactive values with authentication status, token details, user info,
  #   etc.
  auth <- oauth_module_server("auth", client)

  # Render login information:
  output[["login_information"]] <- renderUI({
    if (auth[["authenticated"]]) {
      user_info <- auth[["token"]]@userinfo
      tagList(
        tags[["p"]]("You are logged in! Your details:"),
        tags[["pre"]](paste(capture.output(str(user_info)), collapse = "\n"))
      )
    } else {
      tags[["p"]]("You are not logged in.")
    }
  })
}

runApp(
  shinyApp(ui, server), port = 8100,
  launch.browser = FALSE
)

# Open the app in your regular browser at http://127.0.0.1:8100
# (viewers in RStudio/Positron/etc. cannot perform necessary redirects)
```

> On Posit Connect or Connect Cloud, open the direct app URL in a
> new browser tab or window to test login. The dashboard's embedded preview can
> prevent OAuth redirects. On Connect Cloud, copy the sharing URL from
> Settings > URL. Register the exact public callback URL with your provider.
> See [deployment instructions](https://lukakoning.github.io/shinyOAuth/articles/usage.html#posit-connect-and-connect-cloud).

### Logging/auditing

Use audit hooks to record callbacks and login outcomes, or send logs and traces
to a monitoring service through OpenTelemetry.

For R hook examples, see `vignette("audit-logging", package = "shinyOAuth")`
([online guide](https://lukakoning.github.io/shinyOAuth/articles/audit-logging.html)).
For exporter setup, see `vignette("opentelemetry", package = "shinyOAuth")`
([online guide](https://lukakoning.github.io/shinyOAuth/articles/opentelemetry.html)).

## More information

[Authentication flow](https://lukakoning.github.io/shinyOAuth/articles/authentication-flow.html)
explains login requests, callbacks and token checks. Before deployment, work
through the [security checklist](https://lukakoning.github.io/shinyOAuth/articles/usage.html#security-checklist).
You can also read these guides in R with `vignette("authentication-flow", package = "shinyOAuth")`
and `vignette("usage", package = "shinyOAuth")`.

### For developers: tests & integration tests

The 'testthat' tests are in `tests/testthat/`. Integration tests in
`integration/keycloak/` use a local Keycloak instance in Docker or Podman and
include browser tests with 'shinytest2' and 'chromote'. Demo deployments are in
`integration/gcp/` for Google Cloud Run and `integration/posit/` for Posit Connect Cloud.
