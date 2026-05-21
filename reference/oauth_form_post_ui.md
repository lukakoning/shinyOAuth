# Wrap a Shiny UI to enable OAuth 2.0/OIDC form_post callbacks

`oauth_form_post_ui()` enables the OpenID Foundation OAuth 2.0 Form Post
Response Mode for apps that use
[`oauth_module_server()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_module_server.md).
It wraps your existing Shiny UI so a provider can POST an authorization
response to the app's redirect URI. The POST body is stored server-side
under a short-lived one-time handle, and the browser is redirected back
to the app with only that opaque handle in the query string.

For most apps, this helper is not needed because the default transport
for authorization responses is the query string, which works without
this UI wrapper. You only need to use this helper if your provider
requires or strongly recommends form_post response mode.

To request form_post response mode from the provider, wrap your UI with
this helper, configure your
[OAuthClient](https://lukakoning.github.io/shinyOAuth/reference/OAuthClient.md)
with `response_mode = "form_post"`, and ensure the `redirect_uri` is set
to a URL that routes to this UI wrapper (e.g., the app's root URL or a
specific callback path). This helper handles the plain form_post
response mode, where the POST body contains authorization response
parameters such as `code`, `state`, `error`, and `iss`. It does not
decode JWT Secured Authorization Response Mode (JARM) responses such as
`response_mode = "form_post.jwt"`.

## Usage

``` r
oauth_form_post_ui(base_ui, id, client, callback_path = NULL)
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

## Value

A Shiny UI function. Pass it to
[`shiny::shinyApp()`](https://rdrr.io/pkg/shiny/man/shinyApp.html) and,
for non-root callback paths, use `uiPattern = ".*"` so Shiny routes the
callback path to this UI function.

## Details

When this wrapper is used, it also injects
[`use_shinyOAuth()`](https://lukakoning.github.io/shinyOAuth/reference/use_shinyOAuth.md)
automatically for the wrapped GET UI, so you do not need a separate
top-level
[`use_shinyOAuth()`](https://lukakoning.github.io/shinyOAuth/reference/use_shinyOAuth.md)
call.

The server-side callback handle is single-use and is rejected if it is
older than the smaller of `client@state_payload_max_age` and the
configured `state_store` TTL. The raw POST body and transient handle
query parameters are also bounded by the
`shinyOAuth.callback_max_form_post_*` options described in the usage
vignette.

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
