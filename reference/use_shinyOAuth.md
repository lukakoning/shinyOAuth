# Add JavaScript dependency to the UI of a Shiny app

Adds shinyOAuth's client-side JavaScript dependency to your Shiny UI.
This is required so the module can handle redirects and manage its
browser-side session token.

Without this call in the UI,
[`oauth_module_server()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_module_server.md)
will not work.

## Usage

``` r
use_shinyOAuth(inject_referrer_meta = TRUE)
```

## Arguments

- inject_referrer_meta:

  If TRUE (default), injects a
  `<meta name="referrer" content="no-referrer">` tag into the document
  head. This reduces the risk of leaking OAuth callback query parameters
  (like `code` and `state`) via the `Referer` header to third-party
  subresources during the initial callback page load.

## Value

A `tagList` that loads the `inst/www/shinyOAuth.js` dependency once.

## Details

Place this near the top-level of your UI (e.g., inside
[`fluidPage()`](https://rdrr.io/pkg/shiny/man/fluidPage.html) or
[`tagList()`](https://rstudio.github.io/htmltools/reference/tagList.html)),
similar to how you would use `shinyjs::useShinyjs()`.

## See also

[`oauth_module_server()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_module_server.md)

## Examples

``` r
ui <- shiny::fluidPage(
  use_shinyOAuth(),
  # ...
)
```
