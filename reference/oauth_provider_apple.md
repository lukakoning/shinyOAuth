# Create an Apple [OAuthProvider](https://lukakoning.github.io/shinyOAuth/reference/OAuthProvider.md)

Ready-to-use
[OAuthProvider](https://lukakoning.github.io/shinyOAuth/reference/OAuthProvider.md)
settings for Sign in with Apple.

## Usage

``` r
oauth_provider_apple(name = "apple")
```

## Arguments

- name:

  Optional provider name (default "apple")

## Value

[OAuthProvider](https://lukakoning.github.io/shinyOAuth/reference/OAuthProvider.md)
object configured for Sign in with Apple

## Details

This helper resolves Sign in with Apple's current metadata from Apple's
OIDC discovery document at
`https://appleid.apple.com/.well-known/openid-configuration`.

Apple does not publish a userinfo endpoint, so this helper relies on the
validated ID token for subject and claim data and leaves
`userinfo_required = FALSE`.

When configuring your
[OAuthClient](https://lukakoning.github.io/shinyOAuth/reference/OAuthClient.md):

- use your Services ID or App ID as `client_id`

- supply `client_secret` as an Apple-signed ES256 JWT, for example via
  [`oauth_client_secret_apple()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_client_secret_apple.md)

- use an HTTPS redirect URI with a domain name; Apple does not allow IP
  literals or `localhost`

- if you request `email` or `name`, configure
  `oauth_client(..., response_mode = "form_post")` and wrap your UI with
  [`oauth_form_post_ui()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_form_post_ui.md)

Apple can return a one-time `user` JSON payload on the front-channel
form_post callback when `email` or `name` are requested. shinyOAuth does
not currently map that transient payload into the returned
[OAuthToken](https://lukakoning.github.io/shinyOAuth/reference/OAuthToken.md)
`userinfo` field, so this helper leaves `userinfo_required = FALSE` and
relies on ID token claims.

Because this helper delegates to
[`oauth_provider_oidc_discover()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_provider_oidc_discover.md),
any discovery-backed metadata Apple publishes in the future is picked up
automatically. When a particular discovery field is omitted, shinyOAuth
keeps the same defaults documented for
[`oauth_provider_oidc_discover()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_provider_oidc_discover.md).

## Examples

``` r
# Sign in with Apple requires an Apple Services ID, Team ID, key ID, and the
# corresponding P-256 private key. Network access is required for discovery.
if (interactive()) {
  apple_provider <- oauth_provider_apple()

  apple_secret <- oauth_client_secret_apple(
    client_id = "com.example.web",
    team_id = "ABCDEFGHIJ",
    key_id = "ABC123DEFG",
    private_key = openssl::read_key("AuthKey_ABC123DEFG.p8")
  )

  apple_client <- oauth_client(
    provider = apple_provider,
    client_id = "com.example.web",
    client_secret = apple_secret,
    redirect_uri = "https://example.com/oauth/callback",
    scopes = c("openid", "email", "name"),
    response_mode = "form_post"
  )
}
```
