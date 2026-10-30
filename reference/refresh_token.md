# Refresh an OAuth 2.0 token

Obtains a new access token using a refresh token, without an interactive
login. This low-level helper returns a new
[OAuthToken](https://lukakoning.github.io/shinyOAuth/reference/OAuthToken.md);
it does not replace the input object.
[`oauth_module_server()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_module_server.md)
and
[`oauth_connections_server()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_connections_server.md)
manage token replacement and automatic refresh for their connections.

## Usage

``` r
refresh_token(
  client,
  token,
  async = FALSE,
  introspect = NULL,
  shiny_session = NULL,
  oauth_client = NULL
)
```

## Arguments

- client:

  [OAuthClient](https://lukakoning.github.io/shinyOAuth/reference/OAuthClient.md)
  object

- token:

  [OAuthToken](https://lukakoning.github.io/shinyOAuth/reference/OAuthToken.md)
  object containing the refresh token

- async:

  If `TRUE`, return a promise resolving to the result, using configured
  mirai daemons or a future plan; mirai takes priority. A non-sequential
  backend moves work outside the main R process. Default `FALSE` waits
  and returns the result directly.

- introspect:

  `NULL` (default) or a logical. After a successful refresh, introspect
  the new access token when either this argument is `TRUE` or the client
  was configured with `introspect = TRUE`. A per-call `FALSE` cannot
  disable a configured client requirement. When enabled, refresh fails
  if introspection is unsupported, inactive, or missing required
  `introspection_checks`. The raw introspection result is not stored
  separately, but a successful introspection response may backfill
  `token@cnf`.

- shiny_session:

  Optional captured Shiny session details for audit events, normally
  supplied by the module.

- oauth_client:

  Compatibility alias for `client`. Supply only one spelling.

## Value

An updated
[OAuthToken](https://lukakoning.github.io/shinyOAuth/reference/OAuthToken.md)
object with refreshed credentials.

Updated fields:

- `access_token`: Always updated to the fresh token

- `expires_at`: Computed from `expires_in` when provided; otherwise a
  fallback lifetime set by `shinyOAuth.default_expires_in` (3600 seconds
  by default)

- `refresh_token`: Updated if the provider rotates it; otherwise
  preserved

- `id_token`: Updated only if the provider returns one (and it
  validates); otherwise the latest stored ID token is preserved

- `original_id_token`: Retained from login for continuity checks, even
  if intermediate refresh ID tokens omit `nonce` or `auth_time`

- `userinfo`: Refreshed if `userinfo_required = TRUE`; otherwise
  preserved

- `extra_fields`: Replaced by the additional parameters in the refresh
  response, or an empty list if none are returned. Not merged with
  earlier responses; explicit JSON `null` values remain named `NULL`
  entries.

- `initial_extra_fields`: Preserved from the initial code exchange. This
  historical snapshot does not establish current access permissions.

- `cnf`: Updated from the token response when present, and may be
  backfilled from refresh-time introspection when enabled. When the
  refresh response omits new observable `cnf`, shinyOAuth does not carry
  forward a prior `x5t#S256` thumbprint onto the refreshed token; mTLS
  sender-constrained state is kept only when the new token or its
  introspection response supplies fresh `cnf`

Refresh fails if a new ID token fails validation, or if the UserInfo
subject differs from the new ID token's subject. Validation includes
issuer, audience, expiry and agreement with the original login's
subject. In
[`oauth_module_server()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_module_server.md),
this clears the session and sets `authenticated = FALSE`, unless
`indefinite_session = TRUE` keeps it with `token_stale = TRUE`.

## Details

The provider may replace the refresh token too; otherwise the old
refresh token is kept. Required userinfo is fetched again, and
configured client introspection must succeed before the refreshed token
is returned.

For ordinary OAuth clients, refresh explicitly requests the token's
retained `granted_scopes` when known. This preserves prior scope
reductions and makes an omitted response `scope` refer to that requested
set. Tokens without known scopes omit the request parameter. SMART uses
its own original-grant rules.

OIDC refresh responses may omit the ID token, in which case the original
is kept. If a new ID token is returned, an original must be available
and the subject, issuer, and audience must remain consistent, as must
`auth_time` and nonce when applicable. Full signature and claim
validation runs when `id_token_validation = TRUE`. Userinfo is checked
against a validated ID token when both are available;
`userinfo_id_token_match = TRUE` requires that baseline.

Refresh preserves the original interactive login time. The module's
`reauth_after_seconds` sets a separate limit on that login's age. A
returned ID token must have an `iat` at or after the refresh request
start, allowing the provider's configured clock leeway and same-second
issuance.

Within one R process, overlapping asynchronous calls for the same client
and refresh token share one promise and result. Token snapshots, client
settings, and validation options must match; conflicting calls fail
before dispatch. A synchronous or reentrant call while that refresh is
pending raises an error. Coordination covers one R process; completed
results are not cached. The module manages token replacement and checks
that the result still belongs to the current login. Direct calls return
a value object without that session-level assignment.

Refresh errors carry a non-secret `refresh_credential_outcome` field:
`"not_consumed"`, `"consumed"`, `"possibly_consumed"`, or `"rejected"`.
Only `"not_consumed"` permits retrying the input refresh credential.
Other outcomes, including an unavailable worker result, require new
authorization. The module applies this rule automatically, even with
indefinite sessions; unvalidated access or identity data is never
accepted.

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
# oauth_module_server() and confirming auth[["authenticated"]]:
if (interactive()) {
  token <- auth[["token"]]
  user_info <- get_userinfo(client, token)

  # Requires an introspection endpoint. NA means activity is unknown.
  result <- introspect_token(client, token)
  isTRUE(result[["active"]])

  # Returns replacement credentials using the refresh token.
  token <- refresh_token(client, token)

  # Requires a revocation endpoint to invalidate the token at the provider.
  result <- revoke_token(client, token, token_kind = "refresh")
}
```
