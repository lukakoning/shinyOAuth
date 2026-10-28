# Fetch a user's profile (UserInfo)

Retrieve profile information using the user's access token. Call this
when fetching a profile on demand, reloading profile fields, or managing
tokens outside the Shiny module. It returns the provider's profile as an
R list. The Shiny module fetches and stores this information during
login when `userinfo_required = TRUE`; that result is available as
`auth[["token"]]@userinfo`.

## Usage

``` r
get_userinfo(
  client,
  token,
  token_type = NULL,
  shiny_session = NULL,
  oauth_client = NULL
)
```

## Arguments

- client:

  [OAuthClient](https://lukakoning.github.io/shinyOAuth/reference/OAuthClient.md)
  object. The client must have a `userinfo_url` configured in its
  [OAuthProvider](https://lukakoning.github.io/shinyOAuth/reference/OAuthProvider.md).

- token:

  Either an
  [OAuthToken](https://lukakoning.github.io/shinyOAuth/reference/OAuthToken.md)
  object or a raw access token string.

- token_type:

  Optional override for the access token type when `token` is provided
  as a raw string. Supported values are `Bearer` and `DPoP`.

- shiny_session:

  Optional captured Shiny session details for audit events. Normally
  supplied by the module; leave `NULL` when calling directly.

- oauth_client:

  Compatibility alias for `client`. Supply only one spelling.

## Value

A list containing the user information returned by the provider. For
JSON responses, arrays are simplified to vectors or data frames where
possible. Signed JWT responses retain arrays as lists.

## Details

Pass the client and complete
[OAuthToken](https://lukakoning.github.io/shinyOAuth/reference/OAuthToken.md)
from login, for example `get_userinfo(client, auth[["token"]])`. The
provider needs a `userinfo_url`. For OIDC, shinyOAuth checks that the
returned profile belongs to the validated login. A raw access-token
string cannot provide that identity check.

`userinfo_required = FALSE` disables automatic profile retrieval, not
the identity or signature checks on a manual call. Request and validate
the fields your app needs.

## Advanced response validation

Normal JSON profiles and signed JWT profiles are supported; encrypted
UserInfo is not. `userinfo_signed_jwt_required` requires a signed
response using `userinfo_allowed_algs`.
`userinfo_jwt_required_time_claims` can require expiry and other time
claims; present time claims are always checked.

By default, OIDC providers with a UserInfo endpoint require a validated
identity token, including for manual retrieval. Explicit
`userinfo_id_token_match = FALSE` allows retrieval without one, but when
both are available their `sub` values must always match. Standard
profile fields are checked for the expected JSON types; validate
application-specific values and extension fields yourself.

For DPoP or mTLS-bound tokens, the client supplies the matching signing
key or certificate. See the [advanced security
vignette](https://lukakoning.github.io/shinyOAuth/articles/advanced-security.html)
for those configurations.

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

  # Requires a refresh token. Keep the returned replacement.
  token <- refresh_token(client, token)

  # Requires a revocation endpoint to invalidate the token at the provider.
  result <- revoke_token(client, token, token_kind = "refresh")
}
```
