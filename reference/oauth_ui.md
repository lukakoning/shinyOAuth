# Set up a Shiny UI for shinyOAuth

Wrap your complete UI when using
[`oauth_module_server()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_module_server.md).
This adds the browser setup for login and handles the provider's return
before showing your app. Supply the same `id` and `client` as the server
module.

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
request. This is the recommended setup for ordinary query-callback apps.
It includes
[`use_shinyOAuth()`](https://lukakoning.github.io/shinyOAuth/reference/use_shinyOAuth.md)
setup; do not add a separate call inside the wrapped UI. For POST login
returns (`response_mode = "form_post"` or `"form_post.jwt"`), use
[`oauth_form_post_ui()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_form_post_ui.md)
instead. For callback paths below the app root, pass `uiPattern = ".*"`
to [`shiny::shinyApp()`](https://rdrr.io/pkg/shiny/man/shinyApp.html).

## Several login modules

Supply `clients = list(auth_a = client_a, auth_b = client_b)` instead of
`id` and `client`. Names must match server module IDs. The wrapper
handles each configured query or POST route; do not nest several
wrappers.

## Advanced routing and storage

Each client in a registry must select a multi-server defense. Shared
routes require `authorization_server_mode = "multi_issuer"` and distinct
trusted issuers. An RFC 9207 `iss` or signed JARM issuer selects the
configured client; the callback is then fully verified. Encrypted JARM
on a shared route needs an outer `iss` identifying one configured
issuer, which the inner signed response must match.

Callbacks use short-lived, single-use state-store records and a clean
continuation URL before application HTML or scripts load. Shared workers
need a shared state store with atomic consumption; see
[`oauth_form_post_ui()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_form_post_ui.md)
and
[`custom_cache()`](https://lukakoning.github.io/shinyOAuth/reference/custom_cache.md).
Register fixed application query parameters in `redirect_uri`; other
incoming parameters are discarded. Client-hosted Request Objects also
use this store and are served at the app root.

Without `id` and `client`, ordinary pages render but raw login callbacks
are rejected. A custom
[`use_shinyOAuth()`](https://lukakoning.github.io/shinyOAuth/reference/use_shinyOAuth.md)
integration must provide equivalent callback handling; application
scripts must not run on raw callback pages.

The wrapper sets no-store cache headers and
`Referrer-Policy: no-referrer` before page resources load. A meta tag
alone may be read too late to protect early requests. A web server may
set the same headers.

## See also

[`oauth_module_server()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_module_server.md),
[`oauth_form_post_ui()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_form_post_ui.md),
[`use_shinyOAuth()`](https://lukakoning.github.io/shinyOAuth/reference/use_shinyOAuth.md)

## Examples

``` r
base_ui <- shiny::fluidPage(
  shiny::h2("My app"),
  shiny::uiOutput("login")
)

# After creating your OAuth client, wrap the UI once with callback handling:
# ui <- oauth_ui(base_ui, id = "auth", client = client)
# Use this UI with your app's server function:
# shiny::shinyApp(ui = ui, server = server)
```
