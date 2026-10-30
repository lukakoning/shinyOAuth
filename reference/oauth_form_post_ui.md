# Wrap a Shiny UI to enable OAuth 2.0/OIDC form_post callbacks

Accepts the provider's login callback as an HTTP POST for
`response_mode = "form_post"` or `"form_post.jwt"`. These modes keep
callback parameters out of the browser URL. The POST arrives before a
Shiny session exists; the wrapper receives it and makes the validated
callback available to
[`oauth_module_server()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_module_server.md).
[`oauth_ui()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_ui.md)
handles query-string callbacks.

## Usage

``` r
oauth_form_post_ui(
  base_ui,
  id = NULL,
  client = NULL,
  callback_path = NULL,
  request_uri_resolver = NULL,
  clients = NULL
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
  component of `client@redirect_uri` and must match it when supplied.
  This is the public callback path; use `request_uri_resolver` to map a
  trusted proxy's backend path to the registered public URI.

- request_uri_resolver:

  Optional function accepting the Rook `req` environment and returning
  the trusted, public absolute request URI without relying on query
  parameters. Return `NULL` to reject the route. This is intended for
  HTTPS-terminating proxies whose backend request has an HTTP Rook
  scheme. The function must verify the proxy trust boundary before using
  forwarded headers; its result is still required to match the
  configured redirect origin and `callback_path`. Registered fixed query
  parameters must also occur unchanged in the incoming request.
  Continuation URLs preserve only registered application parameters.

- clients:

  Optional client registry as in
  [`oauth_ui()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_ui.md).
  With a registry, omit `id`, `client`, and `callback_path`; each
  client's redirect URI sets its route, and both query and form-post
  clients are supported.

## Value

A Shiny UI function for
[`shiny::shinyApp()`](https://rdrr.io/pkg/shiny/man/shinyApp.html).

## Details

The wrapper and
[`oauth_module_server()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_module_server.md)
share the same `id` and `client`. The wrapper includes browser setup and
response headers. Callback paths below the app root require
`uiPattern = ".*"` in
[`shiny::shinyApp()`](https://rdrr.io/pkg/shiny/man/shinyApp.html) so
Shiny routes those requests to the wrapper.

The wrapper receives the login result before the Shiny session starts,
then sends the browser to a clean app URL. Raw callback values stay out
of that URL. The server module completes the usual login checks.

## Advanced callback storage

Responses are held briefly in the client's state store under single-use
handles. They expire after at most 120 seconds, or sooner if the state
policy requires it. Pending responses are not replaced to make room for
new ones; a full callback pool rejects additional responses until space
becomes available. Shared stores need atomic `take` and `set_if_absent`;
see
[`custom_cache()`](https://lukakoning.github.io/shinyOAuth/reference/custom_cache.md).
Pending callbacks created by an older version must be restarted after
upgrading. `form_post.jwt` also verifies the signed authorization
response (JARM).

## Deployment behind a proxy

The default resolver uses the server-observed address and ignores
forwarded headers. For an HTTPS-terminating proxy, a custom
`request_uri_resolver` can reconstruct the public address from headers
accepted at that proxy's trust boundary. The wrapper checks the result
against the configured redirect origin and callback path. See the
[advanced security
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

    output[["login"]] <- renderUI({
      if (auth[["authenticated"]]) {
        user_info <- auth[["token"]]@userinfo
        tagList(
          tags[["p"]]("You are logged in!"),
          tags[["pre"]](paste(capture.output(str(user_info)), collapse = "\n"))
        )
      } else {
        tags[["p"]]("You are not logged in.")
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
