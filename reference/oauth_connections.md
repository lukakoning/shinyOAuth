# Configure several independently managed OAuth connections

Create one manager outside `server()` for a named set of client/API
configurations from
[`oauth_client()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_client.md)
or
[`smart_client()`](https://lukakoning.github.io/shinyOAuth/reference/smart_client.md).
Use
[`oauth_connections_ui()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_connections_ui.md)
to handle callbacks and
[`oauth_connections_server()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_connections_server.md)
for each Shiny session. Each successful authorization creates a separate
connection, including repeated authorizations at the same client.
Connections are independent local records. Providers may reuse an
upstream grant, so revoking one can invalidate tokens held by other
connections. Within a manager, refreshes sharing one credential are
serialized. Rotation or an uncertain refresh invalidates other records
holding the same credential; authorize those records again. Their
identity and permissions are never replaced by another connection's
response. Successful revocation also invalidates known copies of that
credential. Distinct tokens may still share an upstream grant whose
revocation effects the manager cannot predict. Retired credential
digests survive connection replacement and expiry for at least the
store's maximum age and the longest client state lifetime. A separate
registry holds at most 10,000 digests or pending reservations. A full
registry rejects refresh or skips remote revocation before sending
credentials; it does not evict retirement evidence. Existing unrelated
access remains usable.

## Usage

``` r
oauth_connections(
  clients,
  app_origin,
  retention = c("shiny", "browser", "account"),
  retention_seconds = 28800,
  owner_policy = NULL,
  store = NULL,
  keys = NULL,
  callback_policy = "distinct_routes"
)

# S3 method for class 'OAuthConnections'
print(x, ...)
```

## Arguments

- clients:

  Non-empty named list of
  [OAuthClient](https://lukakoning.github.io/shinyOAuth/reference/OAuthClient.md)
  objects, at most 64. Each client must configure non-empty
  `resource_bases`. Names select local configurations (for example
  `hospital_a`), independently of OAuth `client_id`: a letter followed
  by letters, digits, `_` or `-`, at most 64 characters.

- app_origin:

  Public application origin, including a non-default port. HTTPS is
  required for retained owners, except an explicit browser-owner HTTP
  loopback exception. Session-only development also permits loopback
  HTTP.

- retention:

  `"shiny"` (default) discards connections at Shiny session end.
  `"browser"` restores the browser owner's connections after navigation;
  `"account"` uses a trusted local application login. Retention does not
  request refresh tokens or extend provider authorization.

- retention_seconds:

  Maximum lifetime of each stored grant, in seconds. Positive and
  finite, no larger than the store's `max_age`. Refresh never resets it.
  Browser retention is also capped by the owner's absolute expiry.

- owner_policy:

  [`oauth_browser_owner()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_browser_owner.md)
  or
  [`oauth_account_owner()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_browser_owner.md)
  matching the retained mode. Must be `NULL` for session-only retention.

- store:

  A store from
  [`oauth_connection_store_memory()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_connection_store_memory.md).
  Required for retained modes; session-only mode creates a memory store
  by default. Only the supplied memory store in one R process is
  supported.

- keys:

  Named list with `credentials` and `owner`, each a deployment-held raw
  vector of 32 bytes. Required for retained modes. Session-only mode
  creates ephemeral keys if omitted. Keep these keys outside credential
  storage.

- callback_policy:

  `"distinct_routes"` (default) gives each client its own registered
  callback route. With several clients, configure every client with
  `authorization_server_mode = "multi_redirect_uri"` and the complete
  set of routes in `authorization_server_redirect_uris`. Every client's
  declared set must include all manager callback routes; additional
  application routes are permitted. Routes are compared by canonical
  origin and path. `"issuer"` allows shared routes for distinct
  authorization-server issuers. `"shared_routes"` additionally supports
  several clients or registrations at one issuer through a protected
  pending-state index. Both opt-in policies require explicit
  `authorization_server_mode = "multi_issuer"` clients, with RFC 9207
  issuer responses or signed JARM. Encrypted JARM requires distinct
  routes. Routing never substitutes for callback authentication.

- x:

  A connection manager to print.

- ...:

  Unused print arguments.

## Value

An `OAuthConnections` server-side configuration object. Printing shows
only the retention mode and client count. It contains client
configuration and deployment keys and must never be sent to the browser.

## Details

A manager is bound to one UI/server module ID and one public origin.
Create another manager for another namespace. The memory store and owner
registries survive Shiny sessions, not R restarts; copies in another R
process fail closed.

In session-only mode, a pending authorization survives navigation
through the existing single-use OAuth state and browser binding, while
existing grants are discarded with the old Shiny session.
Browser/account mode additionally binds authorization to the initiating
local owner and its session generation.

These are optional package interfaces, not SMART protocol objects. This
manager supports generic OAuth clients and the SMART discovery, scope
and launch policies configured by
[`smart_client()`](https://lukakoning.github.io/shinyOAuth/reference/smart_client.md).

## See also

[`oauth_connections_ui()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_connections_ui.md),
[`oauth_connections_server()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_connections_server.md)

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
