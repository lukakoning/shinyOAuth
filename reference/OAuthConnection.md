# OAuthConnection R6 class

A connection lets your Shiny server use the current login to call an API
or supply a token to another R package. It checks that the login and
permissions are still available, so your app does not need to keep its
own token cache.

## Details

Inside reactive server code, obtain a connection with
`connection <- shiny::req(auth$connection())`, where `auth` comes from
[`oauth_module_server()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_module_server.md).
With
[`oauth_connections_server()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_connections_server.md),
select a saved login using `auth$connection(connection_id)`.

Use `$access_token()` for another R package or database driver,
`$request()` for an API in the client's `resource_bases`, and
`$has_scopes()` to check permissions for optional app features.
`$request(refresh = TRUE)` can refresh before sending. See
[`vignette("external-integrations", package = "shinyOAuth")`](https://lukakoning.github.io/shinyOAuth/articles/external-integrations.md)
([online
guide](https://lukakoning.github.io/shinyOAuth/articles/external-integrations.html))
for a complete example.

## Connection lifetime

A connection belongs to one login and one Shiny session. Token refresh
keeps the same connection and ID. Logout, replacement or session closure
invalidates the old connection; obtain a new one after the next login. A
connection manager can retain the underlying login across navigation,
but a new session gets its own connection reference.

Methods check the owning Shiny session. `$is_usable()` returns `FALSE`
when access is unavailable; request and token methods raise errors.

## Advanced lifecycle behavior

Reactive expressions that read `connection()`, `$access_token()` or
`$has_scopes()` do not rerun on token refresh alone if the login and
permissions stay the same. Status reads such as `$summary()` may update
more often. Reads do not extend a managed owner's inactivity limit. The
manager's `touch()` method records explicit user activity.

Use the module's `connection()` for coordinated token acquisition,
refresh and token targets. The
[`oauth_connection()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_connection.md)
wrapper follows a supplied token reactive across logins and does not
support those features.

## See also

[`oauth_connection()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_connection.md),
[OAuthClient](https://lukakoning.github.io/shinyOAuth/reference/OAuthClient.md),
[`perform_resource_req()`](https://lukakoning.github.io/shinyOAuth/reference/perform_resource_req.md)

## Active bindings

- `id`:

  Read-only opaque character string identifying this reference. A single
  module preserves it across refresh and replaces it on login. A manager
  uses the stored grant's ID across sessions and refreshes;
  [`oauth_connection()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_connection.md)
  generates an ID lasting only for that reference.

## Methods

### Public methods

- [`OAuthConnection$new()`](#method-OAuthConnection-initialize)

- [`OAuthConnection$access_token()`](#method-OAuthConnection-access_token)

- [`OAuthConnection$has_scopes()`](#method-OAuthConnection-has_scopes)

- [`OAuthConnection$is_usable()`](#method-OAuthConnection-is_usable)

- [`OAuthConnection$refresh()`](#method-OAuthConnection-refresh)

- [`OAuthConnection$summary()`](#method-OAuthConnection-summary)

- [`OAuthConnection$identity()`](#method-OAuthConnection-identity)

- [`OAuthConnection$request()`](#method-OAuthConnection-request)

- [`OAuthConnection$smart_context()`](#method-OAuthConnection-smart_context)

- [`OAuthConnection$targets()`](#method-OAuthConnection-targets)

- [`OAuthConnection$smart_resource()`](#method-OAuthConnection-smart_resource)

- [`OAuthConnection$print()`](#method-OAuthConnection-print)

------------------------------------------------------------------------

### `OAuthConnection$new()`

Initialize a reference. This constructor is for internal use;
applications should use a module's `connection()` method or the legacy
[`oauth_connection()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_connection.md)
wrapper to establish session ownership.

#### Usage

    OAuthConnection$new(
      id,
      client,
      resolve,
      refresh = NULL,
      acquire = NULL,
      is_current = NULL
    )

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

  Optional internal function implementing the owner's coordinated
  refresh. Legacy wrappers leave this `NULL`.

- `acquire`:

  Internal coordinated credential refresh for external use, accepting
  `async` and returning TRUE or a promise resolving to TRUE.

- `is_current`:

  Optional internal reactive predicate. FALSE permanently ends
  permission notifications for this authorization reference.

#### Returns

A new `OAuthConnection` instance.

------------------------------------------------------------------------

### `OAuthConnection$access_token()`

Get a current bearer token for an SDK or database driver, refreshing
when needed. Obtain this connection from a module's `connection()`
method. The method refreshes credentials when needed, without starting
login, requesting new permissions or retrying the SDK operation.

#### Usage

    OAuthConnection$access_token(
      required_scopes = character(),
      min_valid_for = 60,
      force_refresh = FALSE,
      async = FALSE,
      target = NULL
    )

#### Arguments

- `required_scopes`:

  Permissions needed for this operation, in addition to client
  requirements.

- `min_valid_for`:

  Minimum remaining lifetime in seconds (default 60). Allow time for the
  operation and clock differences. Unknown or insufficient expiry
  triggers refresh; an unusable replacement raises an error.

- `force_refresh`:

  Require a new token even if a cached one is usable.

- `async`:

  If `TRUE`, return a promise, including for a cached token. If `FALSE`,
  return a string or raise an error; a synchronous call cannot wait for
  an already running async refresh.

- `target`:

  Optional API name from `token_targets`. `NULL` selects the client's
  default. Its token is acquired when needed.

#### Details

Errors can indicate an unavailable login, insufficient permission,
pending or failed refresh, or an unsuitable token lifetime. Stable
reason names include `authorization_unavailable`, `insufficient_scope`,
`refresh_pending`, `refresh_unavailable`, `interaction_required`,
`lifetime_unavailable`, `unsupported_token_binding`, `unknown_target`
and `unsupported_target`. See
[`vignette("external-integrations", package = "shinyOAuth")`](https://lukakoning.github.io/shinyOAuth/articles/external-integrations.md)
([online
guide](https://lukakoning.github.io/shinyOAuth/articles/external-integrations.html))
for error recovery and async examples.

DPoP and mTLS-bound tokens require their signing key or certificate; use
`$request()` instead of exporting a bearer string. Exported tokens
retain all provider-issued permissions, which may exceed the app's local
operation limits. Recheck the current login and permissions before using
an async token snapshot.

#### Returns

A bearer-token string, or a promise resolving to one. Token failures
inherit `shinyOAuth_access_error` with a reason in
`condition$context$reason`. Argument and configuration errors can occur
before a promise is returned.

------------------------------------------------------------------------

### `OAuthConnection$has_scopes()`

Check recorded operation permissions for optional-feature UI, without
refreshing or requiring an unexpired access token.

#### Usage

    OAuthConnection$has_scopes(scopes, target = NULL)

#### Arguments

- `scopes`:

  Character vector of operation scopes to check.

- `target`:

  Optional declared token-target name; defaults to the client's primary
  target. An unacquired target returns FALSE, without acquisition.

#### Returns

TRUE when the current authorization covers the configured scopes,
otherwise FALSE. Malformed arguments raise input errors.

------------------------------------------------------------------------

### `OAuthConnection$is_usable()`

Check whether the current token is locally usable. This checks token
presence, known unexpired lifetime and the client's required scopes.
Request-specific scopes are checked by `[["request"]]()`.

#### Usage

    OAuthConnection$is_usable()

#### Returns

A single logical value: `TRUE` for an `active` or `limited` connection,
otherwise `FALSE`, including when resolution fails.

------------------------------------------------------------------------

### `OAuthConnection$refresh()`

Refresh a connection obtained from either module's `connection()`
method. Its owner coordinates refresh and verifies ownership before
updating it. References created with
[`oauth_connection()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_connection.md)
use their existing module's refresh lifecycle and cannot invoke this
method.

#### Usage

    OAuthConnection$refresh(scopes = NULL, target = NULL)

#### Arguments

- `scopes`:

  Optional non-empty character vector requesting fewer permissions for
  this connection, or `NULL` (default). Scopes must be covered by the
  current grant and client configuration, and retain the client's
  required scopes. SMART clients use semantic coverage.

- `target`:

  Optional declared token-target name. With targets, narrowing applies
  only to the selected entry and persists across target switching and
  reauthorization. Other targets keep their own retained scope limits.

#### Details

Successful narrowing persists across later automatic refreshes and
retained sessions. A new authorization is needed to request broader
permissions. It changes the app's accepted permissions, not the
provider's underlying consent. Providers may reject narrowing; the
request is not retried without the requested scopes.

Microsoft API targets do not support explicit narrowing because their
tokens can include earlier consent. The call fails before sending with
reason `unsupported_scope_narrowing`, leaving the current login usable.
Use a separate registration or change provider consent for a token with
fewer permissions.

OIDC clients that require a profile must retain `openid`. Include any
further profile permissions in client `required_scopes`. See
[`vignette("token-targets", package = "shinyOAuth")`](https://lukakoning.github.io/shinyOAuth/articles/token-targets.md)
([online
guide](https://lukakoning.github.io/shinyOAuth/articles/token-targets.html))
for OIDC consent and provider-specific refresh rules.

#### Returns

`TRUE` after a successful commit, or a promise resolving to `TRUE` when
the module uses async transport. Failure raises a redacted error.

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

Scope checks enforce retained target limits and use the token's current
`granted_scopes`, which may be assumed or carried forward when an
ordinary OAuth provider omits scope information. SMART clients require
explicit evidence and use semantic coverage for both connection and
operation permissions. See
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

- `replaces_connection_id`: present on managed replacement
  authorizations; identifies the locally ended connection passed to
  `reauthorize()`.

------------------------------------------------------------------------

### `OAuthConnection$identity()`

Read explicitly selected fields from the authorization's
cryptographically validated OIDC identity.

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

Available inside the owning session's reactive context for connections
with validated OIDC identity.

Ordinary connections require a usable access token with `openid`
currently granted. Target connections retain their validated identity
while the authorization remains available in the owning session, even
when the primary access token expires or its current scopes no longer
include `openid`.

These are the last validated identity/profile snapshots; an OAuth
refresh can retain earlier ID-token claims.

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
      configure = NULL,
      refresh = FALSE,
      target = NULL,
      min_valid_for = 60
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
  authentication and Host headers cannot be changed. Configuration runs
  once. Both refresh modes recheck the current authorization afterward,
  before sending the request.

- `refresh`:

  If `TRUE`, obtain a usable token before sending the request. Default
  `FALSE` uses the current token. This is synchronous and cannot wait
  for an async refresh. Failed API calls are not refreshed or replayed;
  ordinary HTTP retries are disabled for this call. DPoP nonce handling
  remains available. The destination and `configure` result are checked
  before refresh, and permission is checked again before sending.

- `target`:

  Optional declared token-target name. Target clients require an
  explicit association through that declaration's `resource_ids`.

- `min_valid_for`:

  Minimum remaining lifetime when `refresh = TRUE`, in seconds. Has the
  same meaning as on `$access_token()`.

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

**\[experimental\]**

Read interpreted context for a usable SMART connection in this session.

#### Usage

    OAuthConnection$smart_context()

#### Returns

The sensitive context list documented in
[`smart_context()`](https://lukakoning.github.io/shinyOAuth/reference/smart_context.md).

------------------------------------------------------------------------

### `OAuthConnection$targets()`

Inspect declared targets without exposing credentials.

#### Usage

    OAuthConnection$targets()

#### Returns

A named list of target status and granted scopes. A target with no
response yet has status `not_acquired`; this is not proof of denied
consent.

------------------------------------------------------------------------

### `OAuthConnection$smart_resource()`

**\[experimental\]**

Fetch the contextual Patient or validated fhirUser through the approved
FHIR base, using current read permissions.
[`smart_patient()`](https://lukakoning.github.io/shinyOAuth/reference/smart_context.md)
and
[`smart_fhir_user()`](https://lukakoning.github.io/shinyOAuth/reference/smart_context.md)
are the corresponding public helpers.

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
redacted.

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
  auth <- oauth_module_server("auth", client, refresh_proactively = TRUE)
  output[["status"]] <- shiny::renderText({
    connection <- shiny::req(auth[["connection"]]())
    connection[["summary"]]()[["status"]]
  })
  records <- shiny::reactive({
    connection <- shiny::req(auth[["connection"]]())
    response <- httr2::request("https://api.example/v1/records") |>
      httr2::req_auth_bearer_token(connection[["access_token"]]("read")) |>
      httr2::req_perform()
    httr2::resp_body_json(response)
  })
}
} # }
```
