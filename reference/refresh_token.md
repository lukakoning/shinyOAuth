# Refresh an OAuth 2.0 token

Refreshes an OAuth 2.0 access token using a refresh token.

## Usage

``` r
refresh_token(oauth_client, token, async = FALSE, introspect = FALSE)
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

## Value

An updated
[OAuthToken](https://lukakoning.github.io/shinyOAuth/reference/OAuthToken.md)
object with a new access token. If the provider issues a new refresh
token, that replaces the old one. When the provider returns an ID token
and `id_token_validation = TRUE`, it is validated. When
`userinfo_required = TRUE`, fresh userinfo is fetched and stored on the
token. `expires_at` is computed from `expires_in` when provided;
otherwise set to `Inf`.

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
