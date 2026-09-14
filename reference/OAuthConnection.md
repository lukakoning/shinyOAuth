# OAuthConnection R6 class

Make API requests using a Shiny session's current OAuth credentials and
the client/API configuration supplied by an
[OAuthClient](https://lukakoning.github.io/shinyOAuth/reference/OAuthClient.md).
For example, a hospital connection selects that hospital's API address
and reads the session's current token for each request. Create it inside
`server()` with
[`oauth_connection()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_connection.md)
or the `connection(id)` method of
[`oauth_connections_server()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_connections_server.md).
Use `$request()` to call an approved API, `$is_usable()` to check local
availability and `$summary()` for status without credentials.

## Details

The existing reactive token already updates on refresh; this object
combines that lookup with client selection, API-address restrictions and
session checks. With
[`oauth_connection()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_connection.md),
the application supplies the matching module's token source; the manager
resolves its own stored records. These are optional shinyOAuth
conveniences, not SMART on FHIR protocol objects.

Each operation resolves the current credentials, so refresh and logout
are reflected without replacing the reference.
[`oauth_module_server()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_module_server.md)
owns the lifecycle of ordinary references;
[`oauth_connections_server()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_connections_server.md)
owns managed references and supplies `$refresh()`. Every reference
expires when its Shiny session closes. A manager can retain the
underlying grant across redirects; a new session obtains a new reference
after verifying the local owner.

Call `$is_usable()`, `$summary()` and `$request()` in the owning
session's reactive context. If the connection cannot be resolved,
`$is_usable()` returns `FALSE`; `$summary()` and `$request()` raise an
error. The ID is read-only and cloning is disabled. The class generator
is internal; the public factories establish the session binding required
by applications. Managed resource and status reads do not count as owner
activity. Record user actions with the manager's `touch()` method in an
input event handler; automatic reactive updates must not prolong an idle
owner's session.

## See also

[`oauth_connection()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_connection.md),
[OAuthClient](https://lukakoning.github.io/shinyOAuth/reference/OAuthClient.md),
[`perform_resource_req()`](https://lukakoning.github.io/shinyOAuth/reference/perform_resource_req.md)

## Active bindings

- `id`:

  Read-only opaque character string identifying this reference. A
  manager uses the stored grant's ID across sessions and refreshes;
  [`oauth_connection()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_connection.md)
  generates an ID lasting only for that reference. The ID is never an
  access token and does not authorize access by itself.

## Methods

### Public methods

- [`OAuthConnection$new()`](#method-OAuthConnection-initialize)

- [`OAuthConnection$is_usable()`](#method-OAuthConnection-is_usable)

- [`OAuthConnection$refresh()`](#method-OAuthConnection-refresh)

- [`OAuthConnection$summary()`](#method-OAuthConnection-summary)

- [`OAuthConnection$identity()`](#method-OAuthConnection-identity)

- [`OAuthConnection$request()`](#method-OAuthConnection-request)

- [`OAuthConnection$smart_context()`](#method-OAuthConnection-smart_context)

- [`OAuthConnection$smart_resource()`](#method-OAuthConnection-smart_resource)

- [`OAuthConnection$print()`](#method-OAuthConnection-print)

------------------------------------------------------------------------

### `OAuthConnection$new()`

Initialize a reference. This constructor is for internal use;
applications should use
[`oauth_connection()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_connection.md)
or the manager's `connection(id)` method to establish session ownership.
Calling it again on an initialized reference is an error.

#### Usage

    OAuthConnection$new(id, client, resolve, refresh = NULL)

#### Arguments

- `id`:

  Opaque character string identifying the reference.

- `client`:

  The
  [OAuthClient](https://lukakoning.github.io/shinyOAuth/reference/OAuthClient.md)
  to bind to this reference.

- `resolve`:

  Internal function with no arguments that enforces session ownership
  and returns a list with `client` identical to this reference's client
  and `token` containing the current
  [OAuthToken](https://lukakoning.github.io/shinyOAuth/reference/OAuthToken.md)
  or `NULL`. It must raise an error when the owning session is
  unavailable.

- `refresh`:

  Optional internal function implementing a manager's coordinated
  refresh. Legacy session references leave this `NULL`.

#### Returns

A new `OAuthConnection` instance.

------------------------------------------------------------------------

### `OAuthConnection$is_usable()`

Check whether the current token is locally usable. This checks token
presence, known unexpired lifetime and the client's required scopes. It
does not refresh the token, contact the provider or guarantee remote
authorization. Request-specific scopes are checked by `$request()`.

#### Usage

    OAuthConnection$is_usable()

#### Returns

A single logical value: `TRUE` for an `active` or `limited` connection,
otherwise `FALSE`, including when resolution fails.

------------------------------------------------------------------------

### `OAuthConnection$refresh()`

Refresh a connection created by
[`oauth_connections_server()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_connections_server.md)
under the manager's exclusive store claim. The manager rechecks the
owner and current record before installing replacement credentials.
References created with
[`oauth_connection()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_connection.md)
use their existing module's refresh lifecycle and cannot invoke this
method.

#### Usage

    OAuthConnection$refresh(scopes = NULL)

#### Arguments

- `scopes`:

  Optional non-empty character vector requesting fewer permissions for
  this connection, or `NULL` (default). Scopes must be covered by the
  current grant and client configuration, and retain the client's
  required scopes. SMART clients use semantic coverage.

#### Details

After explicit narrowing succeeds, subsequent refreshes (including
automatic refreshes and refreshes in another retained Shiny session)
request the accepted scope limit. Widening requires a new authorization.
This is a local connection policy: OAuth refresh-token scope itself is
not reduced by requesting a narrower access token. Existing connections
that have never selected narrowing continue to omit request scope.
Providers may reject requested scopes; there is no retry without them.
OIDC clients that require UserInfo must retain `openid`; narrowing that
removes it is rejected before exchange. Include any additional scopes
needed by the provider's profile endpoint in the client's
`required_scopes`.

#### Returns

`TRUE` after a successful commit, or a promise resolving to `TRUE` when
the manager uses async transport. Failure raises a redacted error.

------------------------------------------------------------------------

### `OAuthConnection$summary()`

Resolve the current connection and return status information without
credentials, identity claims or token extension fields. Raises an error
when called outside the owning session or after that session closes.

#### Usage

    OAuthConnection$summary()

#### Details

Managed lifecycle states take precedence: `refreshing` means a refresh
claim is in progress, `uncertain` requires a new authorization after an
ambiguous refresh outcome, `disconnected` means local access was
removed, and `unavailable` means the stored credentials could not be
restored. Otherwise token status is evaluated in this order:

- `disconnected`: there is no current token.

- `expiry_unknown`: the token's expiry is unknown.

- `expired`: the token has reached its expiry time.

- `insufficient_scope`: the grant lacks a client-required scope.

- `limited`: required scopes are covered, but some other requested
  scopes are absent from the grant.

- `active`: all requested scopes are covered.

Scope checks use the token's current `granted_scopes`, which may be
assumed or carried forward when an ordinary OAuth provider omits scope
information. SMART clients require explicit evidence and use semantic
coverage for both connection and operation permissions. See
[OAuthToken](https://lukakoning.github.io/shinyOAuth/reference/OAuthToken.md)
for the distinction from verified scope evidence.

#### Returns

A named list with the following entries:

- `connection_id`: the reference's character ID.

- `client_label`: the client's application-defined character label.

- `status`: one of the character values listed in this method's details.

- `expires_at`: numeric seconds since the Unix epoch, `NA_real_` when
  there is no token or its expiry is unknown, or `Inf` for a
  non-expiring token.

- `resource_ids`: character vector of the client's approved resource
  IDs.

------------------------------------------------------------------------

### `OAuthConnection$identity()`

Read explicitly selected OIDC identity fields from the current usable
connection. Requires `openid` and a cryptographically validated ID
token. This method never returns raw tokens or fetches profile data.

#### Usage

    OAuthConnection$identity(claims = c("iss", "sub"), userinfo = character())

#### Arguments

- `claims`:

  Character vector of ID-token claim names, defaulting to
  `c("iss", "sub")`. Use
  [`character()`](https://rdrr.io/r/base/character.html) to select none.

- `userinfo`:

  Character vector of previously fetched UserInfo field names,
  defaulting to none. UserInfo must have a `sub` exactly matching the
  validated ID token before any requested profile fields are returned.

#### Details

Call inside the owning session's reactive context. The result contains
sensitive identity data: select only what the application needs and keep
it out of logs and generic status displays. `$summary()` and printing
continue to omit identity. Ordinary OAuth connections without validated
OIDC identity cannot use this accessor.

These are the last validated identity/profile snapshots; an OAuth
refresh can retain earlier ID-token claims and does not establish fresh
user authentication. This accessor does not log the user into your
application or establish an account-retention owner. It does not count
as owner activity.

#### Returns

A list with `id_token_claims` and `userinfo`, each containing only
selected fields that exist. Missing fields are omitted.

------------------------------------------------------------------------

### `OAuthConnection$request()`

Resolve the current token and perform an authenticated request within a
named resource base. The connection must be usable, and its current
grant must cover any scopes required for this operation.

#### Usage

    OAuthConnection$request(
      resource_id,
      path = "",
      query = NULL,
      method = "GET",
      required_scopes = character(),
      configure = NULL
    )

#### Arguments

- `resource_id`:

  Single character string naming an entry in the client's
  `resource_bases`.

- `path`:

  Single character string resolved relative to the selected base
  directory; `""` selects the base itself. Absolute and root-relative
  URLs, including pagination links, must remain within the same approved
  origin and base path. Dot segments and ambiguous encodings are
  rejected.

- `query`:

  Optional named list of query parameters, or `NULL`.

- `method`:

  Single HTTP method string, defaulting to `"GET"`. `TRACE` and `TRACK`
  are rejected by the resource transport.

- `required_scopes`:

  Character vector of scopes required for this operation, in addition to
  the client's required scopes. They must have been requested by the
  client and be covered by the current grant.
  [`character()`](https://rdrr.io/r/base/character.html) adds no
  operation-specific scope check.

- `configure`:

  Optional function taking an unauthenticated
  [`httr2::request()`](https://httr2.r-lib.org/reference/request.html)
  and returning it with only body and application headers changed. Use
  [`httr2::req_body_json()`](https://httr2.r-lib.org/reference/req_body.html),
  [`httr2::req_body_form()`](https://httr2.r-lib.org/reference/req_body.html),
  [`httr2::req_body_raw()`](https://httr2.r-lib.org/reference/req_body.html)
  and
  [`httr2::req_headers()`](https://httr2.r-lib.org/reference/req_headers.html).
  Set the HTTP method with `method` above. URL, transport policies,
  authentication and Host headers cannot be changed.

#### Details

Uses
[`perform_resource_req()`](https://lukakoning.github.io/shinyOAuth/reference/perform_resource_req.md)
with the configured client for Bearer, DPoP and mTLS authentication.
Redirects are never followed. Transport error messages are redacted to
exclude resource paths, queries and response bodies. Scope requirements
are supplied by the application; they cannot be inferred from an
arbitrary API's HTTP method and path.

#### Returns

An [httr2](https://httr2.r-lib.org/reference/httr2-package.html)
response object. Invalid resources, unusable connections, insufficient
scopes and transport failures raise errors.

------------------------------------------------------------------------

### `OAuthConnection$smart_context()`

Read interpreted context for a usable SMART connection in this session.

#### Usage

    OAuthConnection$smart_context()

#### Returns

The sensitive context list documented in
[`smart_context()`](https://lukakoning.github.io/shinyOAuth/reference/smart_context.md).

------------------------------------------------------------------------

### `OAuthConnection$smart_resource()`

Fetch the contextual Patient or validated fhirUser through the approved
FHIR base, using current read permissions. Prefer
[`smart_patient()`](https://lukakoning.github.io/shinyOAuth/reference/smart_context.md)
and
[`smart_fhir_user()`](https://lukakoning.github.io/shinyOAuth/reference/smart_context.md)
in application code.

#### Usage

    OAuthConnection$smart_resource(kind)

#### Arguments

- `kind`:

  Either `"patient"` or `"fhirUser"`.

#### Returns

An [httr2](https://httr2.r-lib.org/reference/httr2-package.html)
response. Missing context, scope or resource binding raises an error
before an authenticated request is sent.

------------------------------------------------------------------------

### `OAuthConnection$print()`

Print the class name and session-binding description, with credentials
redacted. This does not resolve the current token.

#### Usage

    OAuthConnection$print(...)

#### Arguments

- `...`:

  Unused; accepted for compatibility with
  [`base::print()`](https://rdrr.io/r/base/print.html).

#### Returns

This reference, invisibly.

## Examples

``` r
if (FALSE) { # \dontrun{
# Configure outside server(), using an existing provider:
client <- oauth_client(
  provider, client_id = "registered-app",
  redirect_uri = "https://app.example/callback", scopes = c("read", "write"),
  resource_bases = c(api = "https://api.example/v1"),
  required_scopes = "read"
)
server <- function(input, output, session) {
  auth <- oauth_module_server("auth", client)
  connection <- oauth_connection(client, shiny::reactive(auth$token))
  output$status <- shiny::renderText(connection$summary()$status)
  records <- shiny::reactive({
    shiny::req(connection$is_usable())
    response <- connection$request("api", "records", required_scopes = "read")
    httr2::resp_body_json(response)
  })
}
} # }
```
