# Add JavaScript dependency to the UI of a Shiny app

Adds shinyOAuth's JavaScript so
[`oauth_module_server()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_module_server.md)
can redirect the browser and manage its temporary login cookie. This
low-level helper supplies the browser dependency for custom HTTP
integrations.

[`oauth_ui()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_ui.md),
[`oauth_form_post_ui()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_form_post_ui.md)
and
[`oauth_connections_ui()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_connections_ui.md)
already include this dependency, callback handling and response headers.

## Usage

``` r
use_shinyOAuth(inject_referrer_meta = TRUE)
```

## Arguments

- inject_referrer_meta:

  If TRUE (default), adds a meta tag to the page: an instruction asking
  the browser not to share the page's address when loading images,
  scripts, or other files. Some files may start loading before the
  browser reads this instruction. The UI wrappers also set the HTTP
  header, which applies from the start of page loading.

## Value

A `tagList` that loads the browser code once.

## Details

The UI wrappers process callbacks before rendering application HTML,
redirect to a clean URL, and send `Referrer-Policy: no-referrer`,
`Cache-Control: no-store` and `Pragma: no-cache`. A custom HTTP
integration provides that handling separately. This dependency cannot
set HTTP headers; its optional referrer meta tag takes effect only after
the browser reads it.

## See also

[`oauth_ui()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_ui.md),
[`oauth_form_post_ui()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_form_post_ui.md),
[`oauth_connections_ui()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_connections_ui.md),
[`oauth_module_server()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_module_server.md)

## Examples

``` r
# Low-level browser setup for a custom HTTP integration.
# Supply equivalent callback handling and response headers separately.
# For ordinary apps, use oauth_ui(ui, id = "auth", client = client).
ui <- shiny::fluidPage(
  use_shinyOAuth()
  # ...
)
```
