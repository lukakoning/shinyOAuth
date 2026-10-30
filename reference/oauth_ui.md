# Set up a Shiny UI for shinyOAuth

Adds browser setup for
[`oauth_module_server()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_module_server.md)
and handles the provider's return before showing the app. The UI wrapper
and server module share the same `id` and `client`.

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

The wrapper accepts a complete UI object or a UI function, including one
accepting the Shiny request. It includes
[`use_shinyOAuth()`](https://lukakoning.github.io/shinyOAuth/reference/use_shinyOAuth.md)
and returns a UI function for
[`shiny::shinyApp()`](https://rdrr.io/pkg/shiny/man/shinyApp.html).
[`oauth_form_post_ui()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_form_post_ui.md)
provides the equivalent handling for POST returns
(`response_mode = "form_post"` or `"form_post.jwt"`). Callback paths
below the app root require `uiPattern = ".*"` in
[`shiny::shinyApp()`](https://rdrr.io/pkg/shiny/man/shinyApp.html) so
Shiny routes those requests to the wrapper.

## Several login modules

A registry such as
`clients = list(auth_a = client_a, auth_b = client_b)` replaces the
single `id` and `client` pair. Names match the server module IDs; one
wrapper handles all configured query and POST routes.

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
Continuation URLs retain only application query parameters registered in
`redirect_uri`. Client-hosted Request Objects also use this store and
are served at the app root.

Without `id` and `client`, ordinary pages render but raw login callbacks
are rejected. Callback handling in a custom
[`use_shinyOAuth()`](https://lukakoning.github.io/shinyOAuth/reference/use_shinyOAuth.md)
integration belongs to its HTTP layer; the dependency alone does not
process callbacks.

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
