# Add JavaScript dependency to the UI of a Shiny app

Add shinyOAuth's JavaScript to a page so
[`oauth_module_server()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_module_server.md)
can redirect the browser and manage its temporary login cookie. Use this
inside an existing
[`fluidPage()`](https://rdrr.io/pkg/shiny/man/fluidPage.html) or
[`tagList()`](https://rstudio.github.io/htmltools/reference/tagList.html)
when you integrate the browser dependency directly and configure
response headers elsewhere, such as in your web server or another UI
wrapper.

## Usage

``` r
use_shinyOAuth(inject_referrer_meta = TRUE)
```

## Arguments

- inject_referrer_meta:

  If TRUE (default), adds a meta tag to the page: an instruction asking
  the browser not to share the page's address when loading images,
  scripts, or other files. Some files may start loading before the
  browser reads this instruction. Use
  [`oauth_ui()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_ui.md)
  to provide this protection from the start of page loading.

## Value

A `tagList` that loads the browser code once.

## Details

[`oauth_ui()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_ui.md)
combines this browser setup with the HTTP header
`Referrer-Policy: no-referrer`, which prevents callback URLs from being
sent as referrers when page resources load. When using
`use_shinyOAuth()` directly, set that header in your HTTP response
configuration for protection from the start of page loading; the
optional meta tag takes effect later.
[`oauth_ui()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_ui.md)
and
[`oauth_form_post_ui()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_form_post_ui.md)
already include this dependency. The dependency alone does not provide a
callback bridge. Do not load application or third-party scripts on raw
OAuth callback pages; use `oauth_ui(ui, id, client)` or a dedicated
equivalent endpoint to redirect to a clean URL before rendering the app.
Callback responses must also send `Cache-Control: no-store` and
`Pragma: no-cache`.

## See also

[`oauth_module_server()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_module_server.md)

## Examples

``` r
ui <- shiny::fluidPage(
  use_shinyOAuth()
  # ...
)
```
