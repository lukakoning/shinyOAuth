# Connect, restore and use several OAuth authorizations in a Shiny session

Call once inside `server()` with the manager and ID used by
[`oauth_connections_ui()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_connections_ui.md).
The returned methods select stored connections by opaque IDs and recheck
the local owner for every operation. Tokens are kept on the server and
are not returned by summaries or test exports.

## Usage

``` r
oauth_connections_server(
  id,
  manager,
  async = FALSE,
  refresh_proactively = FALSE,
  refresh_lead_seconds = 60,
  refresh_check_interval = 10000
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

- refresh_check_interval:

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

- `connection(connection_id)`: an
  [OAuthConnection](https://lukakoning.github.io/shinyOAuth/reference/OAuthConnection.md)
  for requests and refresh.

- `touch()`: record explicit user activity after checking the current
  owner. Call from an input event handler; returns `TRUE` invisibly.

- `disconnect(connection_id, revoke = TRUE)`: remove local usability
  first, then return separate `local` and `remote` revocation results.

- `disconnect_all(revoke = TRUE)`: cancel pending authorizations and
  disconnect this owner's stored connections; return a list of results.

- `logout(revoke = TRUE, reload = TRUE)`: invalidate the local
  owner/session generation first, disconnect its connections, and
  normally reload the UI. This does not log the user out of the external
  OAuth provider or the app's own account authentication system.

- `errors()`: reactive list of per-client module error codes, with no
  raw provider text. An ended owner is reported as `owner_unavailable`.

## Details

References expire with this Shiny session even when their stored grants
survive. A new session obtains new references after owner verification.
The existing module never holds managed tokens, so its refresh observers
cannot compete with the manager. Refresh uses the store's revision and
exclusive claim and preserves the original authentication time and
retention expiry. Reactive connection reads also recheck expiry at
`refresh_check_interval`, including references used without
`connections()` or `errors()`. These checks notify dependent expressions
when lifecycle state changes; unchanged polling does not rerun
application requests or extend owner inactivity limits. Notifications to
application code reflect only this owner's record changes. Resource
requests and status reads never reset owner inactivity, including when
reactive expressions rerun after automatic refresh. Call `touch()` from
a user input event handler to count an application action as activity.
Do not call it from polling observers or ordinary reactive readers.
Connecting, explicitly refreshing and disconnecting also count as
activity.

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
policy. Use `revoke = FALSE` when preserving those authorizations is
required. This also applies to credentials returned by work already in
flight. Removed credentials remain valid remotely until the provider
expires or revokes them. Local summaries and `is_usable()` do not detect
such remote changes: handle API authorization failures and obtain a new
authorization.

Use this API inside its owning session's reactive context. Session setup
requires a matching HTTP Origin on the Shiny request. Raw HTTP routes
cannot import credentials or select an owner. This initial manager
supports one R process. Local browser tests cover two-site retention,
account login/logout and switching, and independent refresh using
synthetic providers. Independent external SMART application
interoperability remains a separate validation gate.

## Examples

``` r
if (FALSE) { # \dontrun{
# Outside server(), using clients with resource_bases already configured:
clients <- list(hospital_a = client_a, hospital_b = client_b)
manager <- oauth_connections(
  clients, app_origin = "https://app.example", retention = "browser",
  store = oauth_connection_store_memory(), owner = oauth_browser_owner(),
  keys = deployment_keys
)
ui <- oauth_connections_ui(app_ui, "health", manager)
server <- function(input, output, session) {
  health <- oauth_connections_server("health", manager)
  shiny::observeEvent(input$connect, health$connect(input$client_name))
  data <- shiny::reactive({
    connection <- health$connection(input$connection_id)
    shiny::req(connection$is_usable())
    connection$request("fhir", "Patient/123")
  })
}
shiny::shinyApp(ui, server, uiPattern = ".*")
} # }
```
