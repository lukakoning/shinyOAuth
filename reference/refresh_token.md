# Refresh an OAuth 2.0 token

Refreshes an OAuth session by obtaining a fresh access token using the
refresh token. When configured, also re-fetches userinfo and validates
any new ID token returned by the provider.

Per OIDC Core Section 12.2, providers may omit the ID token from refresh
responses. When omitted, the original ID token from the initial login is
preserved.

If the provider does return a new ID token during refresh,
`refresh_token()` requires that an original ID token from the initial
login is available so it can enforce subject continuity (OIDC 12.2:
`sub` MUST match). If no original ID token is available, refresh fails
with an error.

When `id_token_validation = TRUE`, any refresh-returned ID token is also
fully validated (signature and claims) in addition to the OIDC 12.2
`sub` continuity check.

When `userinfo_required = TRUE`, userinfo is re-fetched using the fresh
access token. If both a new ID token and fresh userinfo are present and
`userinfo_id_token_match = TRUE`, their subjects are verified to match.

## Usage

``` r
refresh_token(
  oauth_client,
  token,
  async = FALSE,
  introspect = FALSE,
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

  Logical, default FALSE. If TRUE and the `promises` package is
  available, the refresh is performed off the main R session using
  [`promises::future_promise()`](https://rstudio.github.io/promises/reference/future_promise.html)
  and this function returns a promise that resolves to an updated
  `OAuthToken`. If `promises` is not available, falls back to
  synchronous behavior

- introspect:

  Logical, default FALSE. After a successful refresh, if the provider
  exposes an introspection endpoint, perform a best-effort introspection
  of the new access token for audit/diagnostics. The result is not
  stored on the token object.

- shiny_session:

  Optional pre-captured Shiny session context (from
  `capture_shiny_session_context()`) to include in audit events. Used
  when calling from async workers that lack access to the reactive
  domain.

## Value

An updated
[OAuthToken](https://lukakoning.github.io/shinyOAuth/reference/OAuthToken.md)
object with refreshed credentials.

**What changes:**

- `access_token`: Always updated to the fresh token

- `expires_at`: Computed from `expires_in` when provided; otherwise
  `Inf`

- `refresh_token`: Updated if the provider rotates it; otherwise
  preserved

- `id_token`: Updated only if the provider returns one (and it
  validates); otherwise the original from login is preserved

- `userinfo`: Refreshed if `userinfo_required = TRUE`; otherwise
  preserved

**Validation failures cause errors:** If the provider returns a new ID
token that fails validation (wrong issuer, audience, expired, or subject
mismatch with original), or if userinfo subject doesn't match the new ID
token, the refresh fails with an error. In
[`oauth_module_server()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_module_server.md),
this clears the session and sets `authenticated = FALSE`.

## Examples

``` r
# Please note: `get_userinfo()`, `introspect_token()`, and `refresh_token()`
# are typically not called by users of this package directly, but are called
# internally by `oauth_module_server()`. These functions are exported
# nonetheless for advanced use cases. Most users will not need to
# call these functions directly

# Example requires a real token from a completed OAuth flow
# (code is therefore not run; would error with placeholder values below)
if (FALSE) { # \dontrun{
# Define client
client <- oauth_client(
  provider = oauth_provider_github(),
  client_id = Sys.getenv("GITHUB_OAUTH_CLIENT_ID"),
  client_secret = Sys.getenv("GITHUB_OAUTH_CLIENT_SECRET"),
  redirect_uri = "http://127.0.0.1:8100"
)

# Have a valid OAuthToken object; fake example below
# (typically provided by `oauth_module_server()` or `handle_callback()`)
token <- handle_callback(client, "<code>", "<payload>", "<browser_token>")

# Get userinfo
user_info <- get_userinfo(client, token)

# Introspect token (if supported by provider)
introspection <- introspect_token(client, token)

# Refresh token
new_token <- refresh_token(client, token, introspect = TRUE)
} # }
```
