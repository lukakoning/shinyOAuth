# Set up a Shiny UI for shinyOAuth

Wrap your complete UI in `oauth_ui()` when using
[`oauth_module_server()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_module_server.md).
It adds the browser code needed for login and a privacy header that
keeps the returning callback address out of requests to other sites.

## Usage

``` r
oauth_ui(base_ui)
```

## Arguments

- base_ui:

  Your app's complete UI, such as a
  [`fluidPage()`](https://rdrr.io/pkg/shiny/man/fluidPage.html) or
  [`tagList()`](https://rstudio.github.io/htmltools/reference/tagList.html).
  Can also be a UI function, optionally accepting the Shiny request.

## Value

A UI function to use as the `ui` argument to
[`shiny::shinyApp()`](https://rdrr.io/pkg/shiny/man/shinyApp.html).

## Details

Build the page as usual, for example with
[`fluidPage()`](https://rdrr.io/pkg/shiny/man/fluidPage.html), then use
`ui <- oauth_ui(ui)`. Pass the result to
[`shiny::shinyApp()`](https://rdrr.io/pkg/shiny/man/shinyApp.html). UI
functions are supported too, including functions accepting the Shiny
request. This wrapper includes
[`use_shinyOAuth()`](https://lukakoning.github.io/shinyOAuth/reference/use_shinyOAuth.md)
setup.

For `response_mode = "form_post"` or `"form_post.jwt"`, use
[`oauth_form_post_ui()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_form_post_ui.md)
instead; it includes this setup and accepts POST callbacks.

The privacy header is `Referrer-Policy: no-referrer`. The browser reads
it before loading page resources. The meta tag from
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

# Use this UI with your app's server function:
# shiny::shinyApp(ui = ui, server = server)
```
