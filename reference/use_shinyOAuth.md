# Add JavaScript dependency to the UI of a Shiny app

Adds the package's client-side JavaScript helpers as an htmlDependency
to your Shiny UI. This enables features such as redirection and setting
the browser cookie token.

Without adding this to the UI of your app, the
[`oauth_module_server()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_module_server.md)
will not function.

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

A tagList containing a singleton dependency tag that ensures the JS file
`inst/www/shinyOAuth.js` is loaded

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
