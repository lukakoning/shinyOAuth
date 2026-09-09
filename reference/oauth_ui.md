# Set up a Shiny UI for shinyOAuth

Wrap your complete UI in `oauth_ui()` when using
[`oauth_module_server()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_module_server.md).
It adds the browser code needed for login and protects callback
responses from caching and referrer disclosure. Supply `id` and `client`
to accept query callbacks before rendering any application UI or
scripts.

## Usage

``` r
oauth_ui(
  base_ui,
  id = NULL,
  client = NULL,
  request_uri_resolver = NULL,
  clients = NULL
)
```

## Arguments

- base_ui:

  Your app's complete UI, such as a
  [`fluidPage()`](https://rdrr.io/pkg/shiny/man/fluidPage.html) or
  [`tagList()`](https://rstudio.github.io/htmltools/reference/tagList.html).
  Can also be a UI function, optionally accepting the Shiny request.

- id:

  Shiny module ID, required with `client` for GET callbacks.

- client:

  [OAuthClient](https://lukakoning.github.io/shinyOAuth/reference/OAuthClient.md)
  used by the server module, required with `id`.

- request_uri_resolver:

  Optional trusted public request URI resolver; see
  [`oauth_form_post_ui()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_form_post_ui.md)
  for proxy requirements.

- clients:

  Optional named list of
  [OAuthClient](https://lukakoning.github.io/shinyOAuth/reference/OAuthClient.md)
  objects keyed by module ID, mutually exclusive with `id` and `client`.

## Value

A UI function to use as the `ui` argument to
[`shiny::shinyApp()`](https://rdrr.io/pkg/shiny/man/shinyApp.html).

## Details

Build the page as usual, for example with
[`fluidPage()`](https://rdrr.io/pkg/shiny/man/fluidPage.html), then use
`ui <- oauth_ui(ui, id = "auth", client = client)`, using the same
module ID and client as the server. Pass the result to
[`shiny::shinyApp()`](https://rdrr.io/pkg/shiny/man/shinyApp.html). UI
functions are supported too, including functions accepting the Shiny
request. This wrapper includes
[`use_shinyOAuth()`](https://lukakoning.github.io/shinyOAuth/reference/use_shinyOAuth.md)
setup. With `client`, it also serves client-hosted Request Objects at
the app root using independent, single-use handles. Shared-worker apps
need a shared `client@state_store` with atomic `take()`; a memory store
supports one process.

For `response_mode = "form_post"` or `"form_post.jwt"`, use
[`oauth_form_post_ui()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_form_post_ui.md)
instead; it includes this setup and accepts POST callbacks.

GET callbacks are validated and sealed into short-lived, single-use
bridge handles in the client's state store, then redirected to a clean
URL before application HTML is rendered. Logical state is consumed only
after the Shiny module verifies browser binding. The storage
requirements and quotas are the same as
[`oauth_form_post_ui()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_form_post_ui.md).
Register any fixed application query parameters in
`client@redirect_uri`; other inbound parameters are discarded. For
non-root callback paths use `uiPattern = ".*"` in
[`shiny::shinyApp()`](https://rdrr.io/pkg/shiny/man/shinyApp.html).

For multiple providers, supply
`clients = list(auth_a = client_a, auth_b = client_b)` instead of `id`
and `client`. Names are the server module IDs. The registry accepts
query and form-post callbacks on configured routes. Each client must
select a multi-server defense. Shared routes require
`authorization_server_mode = "multi_issuer"` and distinct trusted
issuers. An RFC 9207 `iss` or signed JARM issuer selects the configured
client; the complete callback is then verified before a bridge handle is
stored. Encrypted JARM on a shared route requires an outer `iss`
(verified against the decrypted response); otherwise use distinct
routes. Do not nest wrappers to route multiple providers.

Without `id` and `client`, ordinary pages still render, but raw OAuth
GET callbacks fail closed with a setup error. Earlier `oauth_ui(ui)`
query-flow applications must add those arguments. When integrating
[`use_shinyOAuth()`](https://lukakoning.github.io/shinyOAuth/reference/use_shinyOAuth.md)
directly, provide an equivalent dedicated callback endpoint: third-party
or application scripts must not execute on an unsanitized callback page.

HTML responses include `Cache-Control: no-store`, `Pragma: no-cache`,
and `Referrer-Policy: no-referrer`. The browser reads these headers
before loading page resources. The meta tag from
[`use_shinyOAuth()`](https://lukakoning.github.io/shinyOAuth/reference/use_shinyOAuth.md)
takes effect only once the browser reads that tag, so it may miss early
resource requests. You can also set the same HTTP header at your web
server.

## See also

[`oauth_module_server()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_module_server.md),
[`oauth_form_post_ui()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_form_post_ui.md),
[`use_shinyOAuth()`](https://lukakoning.github.io/shinyOAuth/reference/use_shinyOAuth.md)

## Examples

``` r
ui <- oauth_ui(
  shiny::fluidPage(
    shiny::h2("My app"),
    shiny::uiOutput("login")
  )
)

# After creating your OAuth client, enable the callback bridge:
# ui <- oauth_ui(ui, id = "auth", client = client)
# Use this UI with your app's server function:
# shiny::shinyApp(ui = ui, server = server)
```
