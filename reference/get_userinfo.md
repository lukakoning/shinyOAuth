# Fetch a user's profile (UserInfo)

Retrieve profile information using the user's access token. Call this
when fetching a profile on demand, reloading profile fields, or managing
tokens outside the Shiny module. It returns the provider's profile as an
R list. The Shiny module fetches and stores this information during
login when `userinfo_required = TRUE`; that result is available as
`auth$token@userinfo`.

## Usage

``` r
get_userinfo(oauth_client, token, token_type = NULL, shiny_session = NULL)
```

## Arguments

- oauth_client:

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

## Value

A list containing the user information returned by the provider.

## Details

The provider must have a `userinfo_url`: the OpenID Connect (OIDC)
UserInfo endpoint, or an OAuth provider's profile API. With OIDC, this
function checks that userinfo belongs to the same user as a validated ID
token when available. If provider policy requires that comparison, an
absent validated ID token causes an error. Prefer passing the complete
[OAuthToken](https://lukakoning.github.io/shinyOAuth/reference/OAuthToken.md),
which carries the ID token needed for this check.

Ordinary JSON profiles and signed JWT UserInfo responses are supported.
Signed responses are verified using the provider's signing keys and
`userinfo_allowed_algs`; encrypted UserInfo is not supported. Set
`userinfo_signed_jwt_required` on the provider to require a signed
response, and `userinfo_jwt_required_time_claims` on the client to
require time claims such as `exp`. Present time claims are checked even
when not required.

For certificate-bound tokens (mTLS) and key-bound tokens (DPoP), the
helper uses the client's certificate or signing key and checks the token
binding. It handles one DPoP nonce challenge with a fresh-proof retry.
See the [advanced security
vignette](https://lukakoning.github.io/shinyOAuth/articles/advanced-security.html)
for configuration.

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
