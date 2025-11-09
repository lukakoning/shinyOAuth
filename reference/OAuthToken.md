# OAuthToken S7 class

S7 class representing OAuth tokens and (optionally) user information.

## Usage

``` r
OAuthToken(
  access_token = character(0),
  refresh_token = NA_character_,
  id_token = NA_character_,
  expires_at = Inf,
  userinfo = list()
)
```

## Arguments

- access_token:

  Access token

- refresh_token:

  Refresh token (if provided by the provider)

- id_token:

  ID token (if provided by the provider; OpenID Connect)

- expires_at:

  Numeric timestamp (seconds since epoch) when the access token expires.
  `Inf` for non-expiring tokens

- userinfo:

  List containing user information fetched from the provider's userinfo
  endpoint (if fetched)

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
