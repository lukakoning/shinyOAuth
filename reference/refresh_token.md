# Refresh an OAuth 2.0 token

Use a refresh token to obtain a new access token without sending the
user through login again. Call this when your application manages token
lifetime itself, for example before continuing API requests with an
expiring token. Assign the returned
[OAuthToken](https://lukakoning.github.io/shinyOAuth/reference/OAuthToken.md)
to keep the updated credentials.
[`oauth_module_server()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_module_server.md)
can manage refresh during a Shiny session with
`refresh_proactively = TRUE` when a refresh token is available.

## Usage

``` r
refresh_token(
  oauth_client,
  token,
  async = FALSE,
  introspect = NULL,
  shiny_session = NULL
)
```

## Arguments

- oauth_client:

  [OAuthClient](https://lukakoning.github.io/shinyOAuth/reference/OAuthClient.md)
  object

- token:

  [OAuthToken](https://lukakoning.github.io/shinyOAuth/reference/OAuthToken.md)
  object containing the refresh token

- async:

  If `TRUE`, return a promise resolving to the result. Configure mirai
  daemons or a future plan first; mirai takes priority. Use a
  non-sequential future plan to move work outside the main R process.
  Default `FALSE` waits and returns the result directly.

- introspect:

  `NULL` (default) or a logical. After a successful refresh, introspect
  the new access token when either this argument is `TRUE` or the client
  was configured with `introspect = TRUE`. A per-call `FALSE` cannot
  disable a configured client requirement. When enabled, refresh fails
  if introspection is unsupported, inactive, or missing required
  `introspect_elements`. The raw introspection result is not stored
  separately, but a successful introspection response may backfill
  `token@cnf`.

- shiny_session:

  Optional captured Shiny session details for audit events. Normally
  supplied by the module; leave `NULL` when calling directly.

## Value

An updated
[OAuthToken](https://lukakoning.github.io/shinyOAuth/reference/OAuthToken.md)
object with refreshed credentials.

**What changes:**

- `access_token`: Always updated to the fresh token

- `expires_at`: Computed from `expires_in` when provided; otherwise a
  fallback lifetime set by `shinyOAuth.default_expires_in` (3600 seconds
  by default)

- `refresh_token`: Updated if the provider rotates it; otherwise
  preserved

- `id_token`: Updated only if the provider returns one (and it
  validates); otherwise the original from login is preserved

- `userinfo`: Refreshed if `userinfo_required = TRUE`; otherwise
  preserved

- `cnf`: Updated from the token response when present, and may be
  backfilled from refresh-time introspection when enabled. When the
  refresh response omits new observable `cnf`, shinyOAuth does not carry
  forward a prior `x5t#S256` thumbprint onto the refreshed token; mTLS
  sender-constrained state is kept only when the new token or its
  introspection response supplies fresh `cnf`

**Validation failures cause errors:** If the provider returns a new ID
token that fails validation (wrong issuer, audience, expired, or subject
mismatch with original), or if userinfo subject doesn't match the new ID
token, the refresh fails with an error. In
[`oauth_module_server()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_module_server.md),
this clears the session and sets `authenticated = FALSE`, unless
`indefinite_session = TRUE` keeps it with `token_stale = TRUE`.

## Details

The provider may replace the refresh token too; otherwise the old
refresh token is kept. Required userinfo is fetched again, and
configured client introspection must succeed before the refreshed token
is returned.

OIDC refresh responses may omit the ID token, in which case the original
is kept. If a new ID token is returned, an original must be available
and the subject, issuer, and audience must remain consistent, as must
`auth_time` and nonce when applicable. Full signature and claim
validation runs when `id_token_validation = TRUE`. Userinfo is checked
against a validated ID token when both are available;
`userinfo_id_token_match = TRUE` requires that baseline.

Refresh does not establish a new interactive login. Use the module's
`reauth_after_seconds` argument when a fresh login is required.

## Examples

``` r
# get_userinfo(), introspect_token(), and refresh_token() are typically
# called by oauth_module_server() according to your provider/client and
# module settings, rather than directly by application code. The module
# also calls revoke_token() during logout when the provider supports it.
# These helpers are exported for custom login flows, on-demand profile or
# token checks, and applications that manage token lifetime themselves.
#
# The examples below require a real token from a completed login.
# Inside a reactive expression in server(), after creating auth with
# oauth_module_server() and confirming auth$authenticated:
if (interactive()) {
  token <- auth$token
  user_info <- get_userinfo(client, token)

  # Requires an introspection endpoint. NA means activity is unknown.
  result <- introspect_token(client, token)
  isTRUE(result$active)

  # Requires a refresh token. Keep the returned replacement.
  token <- refresh_token(client, token)

  # Requires a revocation endpoint to invalidate the token at the provider.
  result <- revoke_token(client, token, which = "refresh")
}
```
