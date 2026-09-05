# Introspect an OAuth 2.0 token

Ask the provider to check an access or refresh token. This is called
token introspection and requires a configured `introspection_url`. Use
it when you need the provider's current token status rather than only a
locally recorded expiry time: a token may have been revoked before its
expiry. To require it automatically during login and refresh, set
`introspect = TRUE` on
[`oauth_client()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_client.md).

## Usage

``` r
introspect_token(
  oauth_client,
  oauth_token,
  which = c("access", "refresh"),
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
  object to introspect

- which:

  Which token to introspect: "access" (default) or "refresh".

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

- `supported`: logical, `TRUE` when an introspection endpoint is
  configured.

- `active`: logical or `NA`, where `NA` means the provider did not
  return a usable RFC 7662 `active` value.

- `raw`: parsed introspection response list, or `NULL` when the endpoint
  is unsupported or the response could not be parsed.

- `status`: machine-readable status such as `"ok"`,
  `"introspection_unsupported"`, `"missing_token"`, `"invalid_json"`,
  `"missing_active"`, `"invalid_active"`, or `"http_<code>"`.

## Details

Read `result$active`: `TRUE` means active, `FALSE` means inactive, and
`NA` means the result is unknown. Use `isTRUE(result$active)` if your
code must require a definite confirmation.

Unsupported endpoints, missing tokens, unsuccessful HTTP responses, and
unusable response bodies return a descriptive `status`. The provider
must return `active` as a JSON boolean. Other types return
`"invalid_active"`. Requests use the client's configured credentials and
`token_auth_style`.

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
