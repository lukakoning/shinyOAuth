# Connect, restore and use several OAuth authorizations in a Shiny session

Let users connect several accounts or services, choose a saved
connection, and call its API from your Shiny server. Call this once
inside `server()` with the manager and ID used by
[`oauth_connections_ui()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_connections_ui.md).
Connection summaries show status without exposing tokens; server code
can obtain a current token from the selected connection when another R
package needs it.

## Usage

``` r
oauth_connections_server(
  id,
  manager,
  async = FALSE,
  refresh_proactively = FALSE,
  refresh_lead_seconds = 60,
  refresh_check_interval_ms = 10000
)
```

## Arguments

- id:

  Module ID shared with
  [`oauth_connections_ui()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_connections_ui.md).

- manager:

  Configuration from
  [`oauth_connections()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_connections.md).

- async:

  Whether authorization and refresh use the existing async worker
  transport. Owner checks and store mutations stay in the original R
  process.

- refresh_proactively:

  Refresh before expiry when a refresh credential is available.
  Otherwise the manager attempts refresh at expiry.

- refresh_lead_seconds:

  Non-negative number of seconds before expiry used for proactive
  refresh. Background checks never extend owner inactivity limits.

- refresh_check_interval_ms:

  Positive polling interval in milliseconds, at least 100. Safely
  retryable automatic refresh failures wait at least 30 seconds across
  all connections sharing the same refresh credential and registration;
  an uncertain refresh requires reconnecting.

## Value

A server-side list with:

- `connect(client_name)`: request a new authorization without discarding
  others. EHR-only clients report `fresh_ehr_launch_required` and return
  `FALSE`; use their registered
  [`smart_launch_route()`](https://lukakoning.github.io/shinyOAuth/reference/smart_launch_route.md)
  to start authorization.

- `connections()`: reactive list of redacted connection summaries.

- `connection(connection_id = NULL)`: an
  [OAuthConnection](https://lukakoning.github.io/shinyOAuth/reference/OAuthConnection.md)
  for requests, refresh, scope checks and server-side `$access_token()`
  retrieval for external SDKs.

- `reauthorize(connection_id)`: end this local authorization and start
  its replacement with the retained scope limit, without upstream
  revocation. Local state preparation is checked first; rejection
  preserves current access. The replacement summary includes
  `replaces_connection_id`. Failed/cancelled replacement leaves the old
  reference invalid. Unrelated authorizations remain usable;
  shared-credential protections still apply. EHR-only clients require a
  fresh EHR launch instead.

- `touch()`: record explicit user activity after checking the current
  owner; returns `TRUE` invisibly.

- `disconnect(connection_id, revoke = TRUE)`: remove local usability
  first, then return separate `local` and `remote` revocation results.
  For token targets, `remote$access` summarizes all acquired API tokens;
  incomplete or failed cleanup takes priority over successful cleanup.

- `disconnect_all(revoke = TRUE)`: cancel pending authorizations and
  disconnect this owner's stored connections; return a list of results.

- `logout(revoke = TRUE, reload = TRUE)`: end the local owner session,
  disconnect its connections, and normally reload the UI. This does not
  log the user out of the external OAuth provider or the app's own
  account authentication system.

- `errors()`: reactive list of per-client module error codes, with no
  raw provider text. An ended owner is reported as `owner_unavailable`.

## Details

Use `auth$connections()` to populate a selection control, then
`connection <- auth$connection(selected_id)` for the chosen account.
`connection$request()` calls a configured API;
`connection$access_token()` supplies a current token for another R
package. See
[`vignette("multiple-authorizations", package = "shinyOAuth")`](https://lukakoning.github.io/shinyOAuth/articles/multiple-authorizations.md)
([online
guide](https://lukakoning.github.io/shinyOAuth/articles/multiple-authorizations.html))
for a complete app and
[`vignette("external-integrations", package = "shinyOAuth")`](https://lukakoning.github.io/shinyOAuth/articles/external-integrations.md)
([online
guide](https://lukakoning.github.io/shinyOAuth/articles/external-integrations.html))
for API client and database examples.

## Advanced lifetime and refresh behavior

Each Shiny session needs its own connection references, even when the
manager retains the saved authorizations. A new session obtains these
after owner verification. The manager coordinates refresh across its
connections without changing the original authentication time or
retention expiry. Reactive connection reads also recheck expiry at
`refresh_check_interval_ms`, including references used without
`connections()` or `errors()`. These checks notify reactive expressions
when connection status changes; unchanged polling does not rerun
application requests or extend owner inactivity limits. Notifications to
application code reflect only this owner's record changes. Without an
ID, `connection()` returns NULL when no authorization remains, selects
the sole retained authorization, or raises `shinyOAuth_access_error`
with reason `selection_required` when several remain. Expired, limited
and uncertain authorizations count toward ambiguity; disconnected rows
do not.

Reactive expressions that read `connection()`, `$access_token()` or
`$has_scopes()` do not rerun on token refresh alone if the login and
permissions stay the same. Token acquisition never extends owner idle
limits or replays application requests. See
[`vignette("external-integrations", package = "shinyOAuth")`](https://lukakoning.github.io/shinyOAuth/articles/external-integrations.md)
([online
guide](https://lukakoning.github.io/shinyOAuth/articles/external-integrations.html)).
Resource requests and status reads do not reset owner inactivity,
including reactive reads after automatic refresh. `touch()` explicitly
records activity, for example from an input event handler. Connecting,
explicitly refreshing and disconnecting also count as activity.

Remote revocation is best effort: at most ten seconds per
disconnect/logout batch, at most two seconds and one HTTP attempt per
credential. Results are `accepted`, `unsupported`, `missing`, `failed`
or `not_attempted` for access and refresh credentials. `accepted`
describes the endpoint response, not proof of prior token validity.
Local disconnect remains effective if revocation fails. A provider may
revoke an entire authorization grant or related credentials (RFC 7009
section 2.1). Separate connection IDs do not establish independent
provider grants, even after repeated consent or account selection.
Consequently, default `revoke = TRUE` may also end access for sibling
connections or other applications covered by the provider's revocation
policy. With `revoke = FALSE`, disconnect removes local access without
requesting remote revocation. This also applies to credentials returned
by work already in flight. Removed credentials remain valid remotely
until the provider expires or revokes them. Local summaries and
`is_usable()` reflect local state, independently of remote provider
changes.

The API checks its owning session's reactive context. Session setup
requires a matching HTTP Origin on the Shiny request. Raw HTTP routes
cannot import credentials or select an owner. The manager supports one R
process.

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
