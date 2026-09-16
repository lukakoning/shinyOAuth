# Handle callbacks and establish the connection owner's browser session

Wrap the application's UI with the same manager and module ID used by
[`oauth_connections_server()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_connections_server.md).
Browser retention establishes its HttpOnly owner cookie on an ordinary
page request before Shiny starts. OAuth callbacks use the existing
validated callback bridge and clean continuation.

## Usage

``` r
oauth_connections_ui(
  base_ui,
  id,
  manager,
  request_uri_resolver = NULL,
  app_base_path = "/",
  launch_routes = list(),
  additional_clients = list()
)
```

## Arguments

- base_ui:

  A Shiny UI object or request-dependent UI function.

- id:

  Module ID shared with
  [`oauth_connections_server()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_connections_server.md).

- manager:

  Configuration from
  [`oauth_connections()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_connections.md).

- request_uri_resolver:

  Optional trusted function mapping a Rook request to its public
  absolute URI. Required when a trusted reverse proxy changes the
  apparent scheme/host. Do not trust arbitrary forwarded headers. The
  resolved origin must match the manager's configured origin.

- app_base_path:

  Public path at which the Shiny application is hosted, default `"/"`.
  Must begin and end with `/`. The wrapper inserts a document base
  before scripts so Shiny dependencies load from the app root even on
  nested callback pages. Do not supply a separate HTML `base` element.
  Managed JAR Request Object URLs are also published beneath this path.

- launch_routes:

  List of
  [`smart_launch_route()`](https://lukakoning.github.io/shinyOAuth/reference/smart_launch_route.md)
  configurations, empty by default. EHR entry requires browser retention
  and top-level navigation.

- additional_clients:

  Optional named list of ordinary OAuth/OIDC clients used by separate
  [`oauth_module_server()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_module_server.md)
  modules. Names are their full module IDs. These clients keep their
  existing login lifecycle and are not managed connections. Use this
  single UI wrapper instead of nesting
  [`oauth_ui()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_ui.md).
  Their callback routes must be distinct from managed callbacks and
  SMART launch routes, on this app's origin and inside `app_base_path`.
  All clients must select an appropriate multi-server authorization
  mode, even when the manager contains one client.

## Value

A request UI function for `shinyApp(..., uiPattern = ".*")`.

## Details

Raw GET and form POST callbacks never create or rotate an owner. A POST
may lack a SameSite owner cookie. With Strict owner cookies, a validated
callback first serves an inert same-origin document that navigates to
the clean continuation, allowing the browser to send its existing
cookie. The document does not establish an owner or exchange
credentials. A managed continuation must carry a still-valid owner
before credentials can be exchanged. A validated ordinary callback for
`additional_clients` can establish a new empty manager owner
independently. An invalid cookie on an ordinary page is cleared using an
HTTP response and a same-origin redirect; the next request establishes a
new empty browser owner.

The cookie is scoped to its host. Separate applications on that host
must be trusted; different ports or paths do not isolate their cookies.
The wrapper adds no owner cookie for session-only or account retention.

## See also

[`oauth_browser_owner()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_browser_owner.md),
[`oauth_ui()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_ui.md)

## Examples

``` r
# Replace this example provider and client ID with your registered application.
provider <- oauth_provider(
  name = "Example service",
  auth_url = "https://example.com/authorize",
  token_url = "https://example.com/token",
  token_auth_style = "public"
)
client <- oauth_client(
  provider = provider,
  client_id = "example-client",
  redirect_uri = "http://127.0.0.1:8100/callback/service",
  resource_bases = c(api = "https://api.example.com")
)

# Create the manager once, outside server(). Default retention is one Shiny session.
manager <- oauth_connections(
  clients = list(service = client),
  app_origin = "http://127.0.0.1:8100"
)
ui <- oauth_connections_ui(
  shiny::fluidPage(
    shiny::actionButton("connect", "Connect to service"),
    shiny::verbatimTextOutput("connections")
  ),
  id = "auth",
  manager = manager
)
server <- function(input, output, session) {
  auth <- oauth_connections_server("auth", manager)
  shiny::observeEvent(input[["connect"]], auth[["connect"]]("service"))
  output[["connections"]] <- shiny::renderPrint(auth[["connections"]]())
}

# Construct the app without launching it or contacting the provider.
app <- shiny::shinyApp(
  ui,
  server,
  uiPattern = ".*",
  options = list(port = 8100)
)
```
