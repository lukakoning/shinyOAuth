# Wrap a Shiny UI to enable OAuth 2.0/OIDC form_post callbacks

Accept the provider's login callback as an HTTP POST and continue login
with
[`oauth_module_server()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_module_server.md).
Use this when you select `response_mode = "form_post"` or
`"form_post.jwt"`, either because the provider requires it or to keep
callback parameters out of the browser URL. The POST arrives before a
Shiny session exists; this wrapper receives it and makes the validated
callback available to the server module. For query-string callbacks, use
[`oauth_ui()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_ui.md).

## Usage

``` r
oauth_form_post_ui(
  base_ui,
  id,
  client,
  callback_path = NULL,
  request_uri_resolver = NULL
)
```

## Arguments

- base_ui:

  Existing Shiny UI object, or a UI function accepting `req`.

- id:

  Shiny module id used by
  [`oauth_module_server()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_module_server.md).
  This must match the `id` argument passed to the server module.

- client:

  [OAuthClient](https://lukakoning.github.io/shinyOAuth/reference/OAuthClient.md)
  object used by
  [`oauth_module_server()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_module_server.md).

- callback_path:

  Optional URL path to accept POST callbacks on. Defaults to the path
  component of `client@redirect_uri`.

- request_uri_resolver:

  Optional function accepting the Rook `req` environment and returning
  the trusted, public absolute request URI without relying on query
  parameters. Return `NULL` to reject the route. This is intended for
  HTTPS-terminating proxies whose backend request has an HTTP Rook
  scheme. The function must verify the proxy trust boundary before using
  forwarded headers; its result is still required to match the
  configured redirect origin and `callback_path`.

## Value

A Shiny UI function. Pass it to
[`shiny::shinyApp()`](https://rdrr.io/pkg/shiny/man/shinyApp.html) and,
for non-root callback paths, use `uiPattern = ".*"` so Shiny routes the
callback path to this UI function.

## Details

Set `response_mode` on your
[`oauth_client()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_client.md),
wrap your UI here, and use the same `id` and `client` in
[`oauth_module_server()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_module_server.md).
The wrapper includes the browser setup and privacy header supplied by
[`oauth_ui()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_ui.md).
For a callback path below the app root, pass `uiPattern = ".*"` to
[`shiny::shinyApp()`](https://rdrr.io/pkg/shiny/man/shinyApp.html) so
Shiny routes the callback to this wrapper.

The wrapper checks the incoming address and login state, stores the
callback temporarily, and redirects the browser to a normal Shiny page
with a single-use handle. Raw callback values do not appear in that
redirected URL. For `"form_post.jwt"`, it also validates the signed
response using JWT Secured Authorization Response Mode (JARM). Every
POST receives its own random handle. Handles expire after 120 seconds or
the smaller of `state_payload_max_age` and the state store lifetime. The
module still verifies the browser binding before consuming login state.
Pending responses use a bounded pool in the state store: 256 partitions
of eight slots, with each login assigned to one partition. When a
partition is full, a new POST replaces its oldest response. An expired
or replaced handle fails validation; it can never select the replacement
response. Completed logins remove their remaining candidates. Shared
stores still require atomic `take`; no additional backend methods are
needed. Concurrent writers can also replace a candidate; handle
validation fails closed in that case. Pending form-post handles issued
by an older version must be restarted after upgrading.

## Deployment behind a proxy

If a proxy receives HTTPS and forwards HTTP to Shiny, supply a
`request_uri_resolver` that reconstructs the public address after
verifying the request came from your trusted proxy. The default resolver
does not trust forwarded headers. The resulting address must match the
configured redirect origin and callback path. See the [advanced security
vignette](https://lukakoning.github.io/shinyOAuth/articles/advanced-security.html).

Callback size limits are documented in the [package options
reference](https://lukakoning.github.io/shinyOAuth/articles/package-options.html).

## Examples

``` r
if (
  # Example requires a local or remote Keycloak realm whose client allows
  # http://127.0.0.1:8100/callback as a valid redirect URI.
  nzchar(Sys.getenv("KEYCLOAK_BASE_URL")) &&
    nzchar(Sys.getenv("KEYCLOAK_REALM")) &&
    nzchar(Sys.getenv("KEYCLOAK_CLIENT_ID")) &&
    interactive()
) {
  library(shiny)
  library(shinyOAuth)

  options(shinyOAuth.allow_insecure_oidc_loopback = TRUE)

  provider <- oauth_provider_keycloak(
    base_url = Sys.getenv("KEYCLOAK_BASE_URL"),
    realm = Sys.getenv("KEYCLOAK_REALM")
  )

  client <- oauth_client(
    provider = provider,
    client_id = Sys.getenv("KEYCLOAK_CLIENT_ID"),
    client_secret = Sys.getenv("KEYCLOAK_CLIENT_SECRET"),
    redirect_uri = "http://127.0.0.1:8100/callback",
    scopes = c("openid", "profile", "email"),
    response_mode = "form_post"
  )

  base_ui <- fluidPage(
    uiOutput("login")
  )

  ui <- oauth_form_post_ui(base_ui, id = "auth", client = client)

  server <- function(input, output, session) {
    auth <- oauth_module_server("auth", client, auto_redirect = TRUE)

    output$login <- renderUI({
      if (auth$authenticated) {
        user_info <- auth$token@userinfo
        tagList(
          tags$p("You are logged in!"),
          tags$pre(paste(capture.output(str(user_info)), collapse = "\n"))
        )
      } else {
        tags$p("You are not logged in.")
      }
    })
  }

  runApp(
    shinyApp(ui, server, uiPattern = ".*"),
    port = 8100,
    launch.browser = FALSE
  )
}
```
