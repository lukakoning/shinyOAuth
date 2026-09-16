# Configure ownership of retained OAuth connections

Choose who may use saved OAuth connections: the browser that created
them, or an account already authenticated by your application. Supply
the policy to
[`oauth_connections()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_connections.md)
with the matching retention mode. These factories do not set cookies,
authenticate users or enable retention on
[`oauth_module_server()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_module_server.md)
calls by themselves.

## Usage

``` r
oauth_browser_owner(
  idle_timeout = 1800,
  absolute_timeout = 28800,
  same_site = c("Lax", "Strict"),
  allow_http_loopback = FALSE,
  max_entries = 1000L
)

oauth_account_owner(
  resolver,
  idle_timeout,
  absolute_timeout,
  reauth_after_seconds,
  max_entries = 1000L
)

# S3 method for class 'OAuthOwnerPolicy'
print(x, ...)
```

## Arguments

- idle_timeout:

  Maximum owner inactivity in seconds. Resource and status reads do not
  count as activity. Use the server manager's `touch()` from a user
  input event handler; connecting, explicit refresh and disconnect also
  count.

- absolute_timeout:

  Maximum owner lifetime in seconds, independent of activity. Must be at
  least `idle_timeout`.

- same_site:

  Owner-cookie policy, `"Lax"` for top-level authorization navigation or
  `"Strict"`. Embedded cross-site ownership is not supported. With
  `"Strict"`,
  [`oauth_connections_ui()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_connections_ui.md)
  serves an intermediate same-origin document after validating a
  callback, before checking the existing owner.

- allow_http_loopback:

  Explicit development-only exception for HTTP on localhost or a
  loopback address. Default `FALSE` requires HTTPS. The exception cannot
  provide a Secure, host-prefixed owner cookie.

- max_entries:

  Maximum owner-registry entries per manager, a positive whole number.
  Browser mode counts browsers that authorize a service. A separate
  provisional visitor pool has the same limit; its oldest entries may be
  replaced and expire after at most five minutes, unless a live
  authorization transaction protects them until its expiry. When all
  visitor entries have pending authorizations, new visitors are
  rejected. Account mode counts authentication generations, including
  retired generations until their local reauthentication deadline. This
  limit is independent of the connection store's `max_entries`.

- resolver:

  Trusted application function accepting the current Shiny session. On
  every call it must validate the application's local login and return
  `NULL` if unauthenticated, otherwise a plain list containing
  `subject`, `session_id`, `generation`, `authenticated_at` and
  `expires_at`. The first three are non-empty strings; the timestamps
  are finite Unix seconds. Subject is the stable local account ID.
  Session ID and generation identify the current local authentication
  session. Do not derive these from unverified Shiny inputs, URL values,
  email addresses or the external provider's token response.

- reauth_after_seconds:

  Maximum age of the verified local authentication, in seconds. Required
  for account retention; refresh cannot reset this age.

- x:

  An `OAuthOwnerPolicy` to print.

- ...:

  Unused print arguments.

## Value

An `OAuthOwnerPolicy` configuration object. Browser policies use an
opaque server-issued cookie and server-side owner registry. Account
policies use the trusted local-session resolver described below.

## Details

Browser retention identifies an authorized browser session, not a
verified person. The owner cookie is HttpOnly, host-only, has root path
and uses Secure and a `__Host-` name on HTTPS. It contains no token or
patient data. Server-side idle and absolute limits are authoritative. A
cookie is never accepted as an owner without a matching live server
record for this application origin.

Cookie rotation invalidates the previous session generation immediately
and preserves the original absolute lifetime. Local logout removes the
live owner session. The manager checks that generation before code
exchange and credential commit, with no grace period for pending
authorization, and handles credential cleanup after logout. An external
provider login cannot establish a local owner or implicitly link browser
connections to an account.

A full owner registry rejects new retained owners without evicting live
sessions or retirement records. Browser session end does not release
ownership; logout or idle/absolute expiry does. Account logout retains
its retired generation until `authenticated_at + reauth_after_seconds`
so it cannot be enrolled again. Size `max_entries` for that entire
window, not only simultaneous Shiny sessions.

Account retention requires finite idle, absolute and local
reauthentication lifetimes. The internal session registry re-runs
`resolver` when resolving or validating an owner and checks the intended
subject/session generation. Expiry or logout retires that generation
until a fresh local authentication session is supplied. A resolver error
fails closed with a redacted error. The application remains responsible
for validating its local session, including signature, expiry,
revocation and account changes. Supplying this configuration is not
proof that an arbitrary user ID is authenticated.

## See also

[`oauth_connection_store_memory()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_connection_store_memory.md)
