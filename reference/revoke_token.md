# Revoke an OAuth 2.0 token

Ask the provider to invalidate an access or refresh token, for example
when a user disconnects their account or your application disposes of
stored credentials. The provider must support token revocation. The
Shiny module calls this during logout; use `auth$logout()` to also clear
its local session. Revocation does not end the user's login session at
the provider.

## Usage

``` r
revoke_token(
  oauth_client,
  oauth_token,
  which = c("refresh", "access"),
  async = FALSE,
  shiny_session = NULL
)
```

## Arguments

- oauth_client:

  [OAuthClient](https://lukakoning.github.io/shinyOAuth/reference/OAuthClient.md)
  object

- oauth_token:

  [OAuthToken](https://lukakoning.github.io/shinyOAuth/reference/OAuthToken.md)
  object containing tokens to revoke

- which:

  Which token to revoke: "refresh" (default) or "access"

- async:

  If `TRUE`, return a promise resolving to the result. Configure mirai
  daemons or a future plan first; mirai takes priority. Use a
  non-sequential future plan to move work outside the main R process.
  Default `FALSE` waits and returns the result directly.

- shiny_session:

  Optional captured Shiny session details for audit events. Normally
  supplied by the module; leave `NULL` when calling directly.

## Value

A list with fields:

- `supported`: logical, `TRUE` when a revocation endpoint is configured.

- `revoked`: logical or `NA`, `TRUE` when the provider accepted the
  revocation request, `NA` when revocation could not be attempted or the
  result is unknown.

- `status`: machine-readable status such as `"ok"`, `"missing_token"`,
  `"revocation_unsupported"`, or `"http_<code>"`.

## Details

Uses the client's configured credentials and `token_auth_style`. Check
the returned `status`: an absent endpoint or token, or an unsuccessful
HTTP response, leaves the revocation result unknown. A successful
response means the provider accepted the request; local logout does not
depend on it.

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
