# Usage

## Overview

shinyOAuth provides a Shiny module for OAuth 2.0 authorization and
OpenID Connect (OIDC) authentication.
[`oauth_module_server()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_module_server.md)
manages redirects, callback validation, token exchange, and session
state.
[`oauth_ui()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_ui.md)
supplies the browser setup required by the module.

This vignette covers provider and client configuration, manual login
buttons, authenticated API calls, token refresh, and deployment. The
examples use a GitHub OAuth App. Install shinyOAuth with
`install.packages("shinyOAuth")`. For the protocol flow and validation
rules, see [Authentication
flow](https://lukakoning.github.io/shinyOAuth/articles/authentication-flow.md).

## GitHub app registration

1.  Register an **OAuth App** in [GitHub’s developer
    settings](https://github.com/settings/developers). Set both the
    homepage URL and authorization callback URL to
    `http://127.0.0.1:8100` for this local example.

2.  Store the app’s client ID and client secret in your R environment.
    You can open your user `.Renviron` with
    `file.edit(path.expand("~/.Renviron"))` and add:

    ``` text
    GITHUB_OAUTH_CLIENT_ID=your-client-id
    GITHUB_OAUTH_CLIENT_SECRET=your-client-secret
    ```

    Restart R after saving. Keep the secret out of app source files and
    Git.

## Minimal Shiny module example

Save the following code as `app.R` and run it. Open
`http://127.0.0.1:8100` in a regular browser. Use the registered
address; switching between `localhost` and `127.0.0.1` can interrupt
login.

``` r
library(shiny)
library(shinyOAuth)

# Configure these once, outside server().
provider <- oauth_provider_github()
client <- oauth_client(
  provider = provider,
  client_id = Sys.getenv("GITHUB_OAUTH_CLIENT_ID"),
  client_secret = Sys.getenv("GITHUB_OAUTH_CLIENT_SECRET"),
  redirect_uri = "http://127.0.0.1:8100",
  scopes = c("read:user", "user:email")
)

ui <- oauth_ui(fluidPage(
  h2("My app"),
  textOutput("greeting")
))

server <- function(input, output, session) {
  auth <- oauth_module_server("auth", client)

  output$greeting <- renderText({
    req(auth$authenticated)
    paste("Hello,", auth$token@userinfo$login)
  })
}

runApp(shinyApp(ui, server), port = 8100, launch.browser = FALSE)
```

The browser opens GitHub’s login or permission page, then returns to
your app and displays your GitHub username. Use a regular browser: IDE
viewers may prevent the redirects needed for login.

## Provider, client, and token objects

shinyOAuth represents the flow with three S7 classes. An `OAuthProvider`
holds the service’s endpoint URLs and protocol settings; a provider
helper such as
[`oauth_provider_github()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_provider_github.md)
creates it. An `OAuthClient`, created with
[`oauth_client()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_client.md),
holds your app’s credentials, redirect URI, and requested scopes. After
authentication, the module returns an `OAuthToken` as `auth$token`,
containing tokens and available user information.

The **redirect URI**, also called the callback URL, is the address where
the provider sends the browser back. Register it with the provider and
use the same value in
[`oauth_client()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_client.md),
including scheme, host, port, and path. **Scopes** are named
permissions, such as `read:user`; the provider defines which names are
available.

Create your provider and client outside `server()` so they remain
available when the browser returns from login. Create the module inside
`server()` so each user has their own login state.

## Authentication state and user information

`auth` is a Shiny `reactiveValues` object. Read it inside `render*()`,
[`reactive()`](https://rdrr.io/pkg/shiny/man/reactive.html), or
`observe*()`, just as you would read other reactive values.

- `auth$authenticated` tells you whether login passed the configured
  checks.
- `auth$token@userinfo` contains the user’s profile, when fetched.
  Fields depend on the provider: GitHub uses `login` for the username.
- `auth$error` and `auth$error_description` describe a failed login.
  Show a simple message to users and use [audit
  logging](https://lukakoning.github.io/shinyOAuth/articles/audit-logging.md)
  to investigate.

The token is an S7 object: access its properties with `@`, as in
`auth$token@userinfo`. See
[`OAuthToken`](https://lukakoning.github.io/shinyOAuth/reference/OAuthToken.html)
for the available properties.

Use `req(auth$authenticated)` before server code reads private data or
performs an action that requires login. Hiding a UI element alone does
not protect the server code behind it. Your app must also check any
access rules, such as which accounts or groups may view a report. A
successful login by itself does not grant access to everything in your
app.

## Manual login and logout buttons

The default is to start login automatically. To let users choose when to
sign in, replace the example’s UI and server with:

``` r
ui <- oauth_ui(fluidPage(
  actionButton("login", "Sign in"),
  actionButton("logout", "Sign out"),
  textOutput("status")
))

server <- function(input, output, session) {
  auth <- oauth_module_server("auth", client, auto_redirect = FALSE)

  observeEvent(input$login, auth$request_login())
  observeEvent(input$logout, auth$logout())

  output$status <- renderText({
    if (isTRUE(auth$authenticated)) {
      paste("Signed in as", auth$token@userinfo$login)
    } else {
      "You are signed out. Use Sign in to continue."
    }
  })
}
```

`auth$logout()` clears the app’s local login and attempts to revoke its
tokens if the provider supports revocation. It does not sign the user
out of their GitHub, Google, or other provider account. The provider may
therefore remember them on their next visit.

## Authenticated API requests

Use
[`perform_resource_req()`](https://lukakoning.github.io/shinyOAuth/reference/perform_resource_req.md)
to send an API request with the authenticated user’s access token. For
example, add `tableOutput("repositories")` to the UI and this output to
`server()`:

``` r
output$repositories <- renderTable({
  req(auth$authenticated)

  repos <- tryCatch({
    response <- perform_resource_req(
      auth$token,
      "https://api.github.com/user/repos",
      query = list(per_page = 10)
    )
    httr2::resp_check_status(response)
    httr2::resp_body_json(response, simplifyVector = TRUE)
  }, error = function(e) NULL)

  validate(need(!is.null(repos), "Could not load repositories. Try again later."))
  validate(need(length(repos) > 0, "No repositories to show."))
  repos[, c("name", "private"), drop = FALSE]
})
```

Only send tokens to an API you intend to authorize. The example requests
one page of results; fetching more pages depends on the API. Use
[`resource_req()`](https://lukakoning.github.io/shinyOAuth/reference/resource_req.md)
to build an `httr2` request without sending it, or pass a prepared
`httr2` request to
[`perform_resource_req()`](https://lukakoning.github.io/shinyOAuth/reference/perform_resource_req.md).
See the [Spotify
example](https://lukakoning.github.io/shinyOAuth/articles/example-spotify.md)
for another complete app.

## Provider configuration and OIDC discovery

Use a built-in helper when available, such as
[`oauth_provider_google()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_provider_google.md),
[`oauth_provider_microsoft()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_provider_microsoft.md),
or
[`oauth_provider_keycloak()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_provider_keycloak.md).
Each helper’s help page describes its setup. For an OpenID Connect
service with a discovery URL, you can let shinyOAuth look up the
service’s settings:

``` r
provider <- oauth_provider_oidc_discover(
  issuer = "https://login.example.com"
)
client <- oauth_client(
  provider = provider,
  client_id = Sys.getenv("OAUTH_CLIENT_ID"),
  client_secret = Sys.getenv("OAUTH_CLIENT_SECRET"),
  redirect_uri = "https://my-app.example.com",
  scopes = c("openid", "profile", "email")
)
```

Replace the example URLs and credentials with your own registration. An
**issuer** is the provider’s identifier URL; copy it from the provider’s
configuration. Discovery makes a network request, so run it during app
setup. If your registration specifies a client authentication method,
supply the matching `token_auth_style` to the provider helper; discovery
describes the service’s capabilities, not the settings of your
individual registration.

OpenID Connect (OIDC) is a login protocol: it supplies a signed **ID
token** that shinyOAuth checks to identify the user. OAuth 2.0 grants
permission to call APIs using an **access token**. GitHub and Spotify
use OAuth without OIDC; their helpers fetch profile information through
their own APIs. With OIDC, read validated identity details from
`auth$token@id_token_claims` and check `auth$token@id_token_validated`.
An access token alone is not proof of identity. The [authentication
guide](https://lukakoning.github.io/shinyOAuth/articles/authentication-flow.md)
explains more.

For a local Keycloak server using HTTP, opt in before creating the
provider:

``` r
options(shinyOAuth.allow_insecure_oidc_loopback = TRUE)
provider <- oauth_provider_keycloak(
  base_url = "http://localhost:8080", realm = "shinyoauth"
)
```

This option is for local development only. Production provider URLs need
HTTPS. The ordinary HTTP host option allows local app addresses; it does
not relax OIDC discovery.

## Asynchronous execution

By default, network work runs in the app’s R process. A slow provider
can make other sessions on that process wait too. To run the module’s
network work in background R processes, install `mirai` and `promises`,
then configure workers before `server()`:

``` r
mirai::daemons(2)
shiny::onStop(function() mirai::daemons(0))

server <- function(input, output, session) {
  auth <- oauth_module_server("auth", client, async = TRUE)
  # Add your outputs and observers here.
}
```

Alternatively, configure
`future::plan(future::multisession, workers = 2)` and use
`async = TRUE`. If both backends are configured, mirai takes priority.
[`future::sequential()`](https://future.futureverse.org/reference/sequential.html)
runs in the same R process and does not avoid blocking.

For an app using future instead of mirai, configure its worker plan
before starting the server and release the workers when the app stops:

``` r
future::plan(future::multisession, workers = 2)
shiny::onStop(function() future::plan(future::sequential))

server <- function(input, output, session) {
  auth <- oauth_module_server("auth", client, async = TRUE)
  # Add your outputs and observers here.
}
```

This setting covers the module’s operations; API calls you write in your
own outputs still run where you call them. Discovery during app setup
also stays synchronous. See
[`oauth_module_server()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_module_server.html)
for advanced exceptions and the [options
reference](https://lukakoning.github.io/shinyOAuth/articles/package-options.md)
for timeouts and retries.

## Token expiry and session length

Access tokens usually expire. If the provider supplies a refresh token,
the module can obtain a replacement before expiry with
`refresh_proactively = TRUE`. Otherwise, users need to sign in again
when their token expires.

Use `reauth_after_seconds` to set a maximum time since interactive
login; refreshing a token does not restart that timer. For OIDC, the
module also requests a fresh provider login and checks its time.
OAuth-only providers can only be given an ordinary authorization
request.

Keep `indefinite_session = FALSE` unless you deliberately want the local
session to continue with an expired token or after refresh fails.
Setting it to `TRUE` also disables the `reauth_after_seconds` limit; it
does not extend the token’s validity at the provider.

## Deployment

Replace the local callback URL with the app’s public HTTPS URL, and
register that same URL with the provider. Open the app directly in a
browser tab. An app embedded in another page may not be able to complete
login. On Posit Connect Cloud, use the app’s direct URL as described in
its [URL settings
guide](https://docs.posit.co/connect-cloud/user/manage/content_settings.html#url).

### Multiple R processes

The default configuration stores pending logins in one R process. If a
login can start on one process and return to another, those processes
need:

- A shared `state_store` with an atomic `$take()` operation: reading and
  deleting a pending login must happen as one indivisible operation.
- The same secret `state_key`, so each process can read the encrypted
  login details. Supply at least 32 random bytes, stored in your
  deployment’s secret manager.
- Matching provider and client settings.

Use
[`custom_cache()`](https://lukakoning.github.io/shinyOAuth/reference/custom_cache.md)
to connect a shared database or Redis store. Plain
[`cachem::cache_disk()`](https://cachem.r-lib.org/reference/cache_disk.html)
is unsuitable for shared login state because separate reads and deletes
can let two requests use the same entry. See
[`custom_cache()`](https://lukakoning.github.io/shinyOAuth/reference/custom_cache.html)
for the backend contract.

### Security checklist

- Use HTTPS in production and keep credentials on the server.
- Request only the scopes your app needs.
- Check login and app-specific access rules in server code before using
  private data.
- Keep tokens, complete login URLs, and detailed provider errors out of
  the UI and logs.
- Render untrusted text through Shiny’s ordinary text/tag functions. Do
  not pass it to
  [`HTML()`](https://rstudio.github.io/htmltools/reference/HTML.html) as
  markup; keep table escaping enabled.
- Wrap the UI with
  [`oauth_ui()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_ui.md)
  (or
  [`oauth_form_post_ui()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_form_post_ui.md)
  when required). These send a browser privacy header that keeps
  callback URLs out of referrers.
- Keep the provider’s validation defaults and choose any extra
  protections to match your provider and deployment requirements.

The module uses a short-lived browser cookie to link a returning login
to the browser that started it. JavaScript must be able to read this
cookie, so preventing injected scripts (cross-site scripting, or XSS) in
your app matters. This link cannot establish which account you expected
to sign in: check that account yourself when your app has such a
requirement.

## Troubleshooting

Use [audit
logging](https://lukakoning.github.io/shinyOAuth/articles/audit-logging.md)
to identify the failing operation. Common configuration issues include:

- **Rejected redirect URI:** check that the registered callback URL and
  `redirect_uri` match, including scheme, host, port, and path.
- **Callback validation failure:** use the registered app address in a
  regular browser and create the client outside `server()`. For multiple
  R processes, check the shared state store and key.
- **Rejected client credentials:** check the environment variables after
  restarting R and match `token_auth_style` to the app registration.
- **Missing profile fields:** check requested scopes and the provider’s
  profile format. Some providers return identity information only in ID
  token claims.
- **Rejected API request:** check permissions, token expiry, and whether
  the API accepts tokens from the configured provider.

Keep token and callback validation enabled while diagnosing
configuration errors.

## Further configuration

The [`oauth_module_server()`
examples](https://lukakoning.github.io/shinyOAuth/reference/oauth_module_server.html#ref-examples)
include complete apps for automatic login, a manual login button, and
fetching GitHub repositories with the user’s access token. The
[`oauth_provider()`
examples](https://lukakoning.github.io/shinyOAuth/reference/oauth_provider.html#ref-examples)
cover manual OAuth/OIDC setup, discovery, and named providers; the
[Microsoft
example](https://lukakoning.github.io/shinyOAuth/reference/oauth_provider_microsoft.html#ref-examples)
also shows authentication-state summaries and error handling.

- [Advanced
  security](https://lukakoning.github.io/shinyOAuth/articles/advanced-security.md):
  form POST callbacks, certificates (mTLS), signed requests (JAR) and
  responses (JARM), pushed requests (PAR), and tokens tied to a key
  (DPoP).
- [Authentication
  flow](https://lukakoning.github.io/shinyOAuth/articles/authentication-flow.md):
  what the module checks and why.
- [Package
  options](https://lukakoning.github.io/shinyOAuth/articles/package-options.md):
  logging, network limits, and debugging settings.
- [OpenTelemetry](https://lukakoning.github.io/shinyOAuth/articles/opentelemetry.md):
  exporting logs and timing information.
