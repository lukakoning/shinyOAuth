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
# Configure generic OAuth 2.0 provider (no OIDC)
generic_provider <- oauth_provider(
  name = "example",
  auth_url = "https://example.com/oauth/authorize",
  token_url = "https://example.com/oauth/token",
  # Optional URL for fetching user info:
  userinfo_url = "https://example.com/oauth/userinfo"
)

# Configure generic OIDC provider manually
# (This defaults to using nonce & ID token validation)
generic_oidc_provider <- oauth_provider_oidc(
  name = "My OIDC",
  base_url = "https://my-issuer.example.com"
)

# Configure a OIDC provider via OIDC discovery
# (requires network access)
if (interactive()) {
  # Using Auth0 sample issuer as an example
  oidc_discovery_provider <- oauth_provider_oidc_discover(
    issuer = "https://samples.auth0.com"
  )
}

# GitHub preconfigured provider
github_provider <- oauth_provider_github()

# Google preconfigured provider
google_provider <- oauth_provider_google()

# Microsoft preconfigured provider
# See `?oauth_provider_microsoft` for example using a custom tenant ID

# Spotify preconfigured provider
spotify_provider <- oauth_provider_spotify()

# Slack via OIDC discovery
# (requires network access)
if (interactive()) {
  slack_provider <- oauth_provider_slack()
}

# Keycloak
# (requires configured Keycloak realm; example below is therefore not run)
if (interactive()) {
  oauth_provider_keycloak(base_url = "http://localhost:8080", realm = "myrealm")
}

# Auth0
# (requires configured Auth0 domain; example below is therefore not run)
if (interactive()) {
  oauth_provider_auth0(domain = "your-tenant.auth0.com")
}

# Okta
# (requires configured Okta domain; example below is therefore not run)
if (interactive()) {
  oauth_provider_okta(domain = "dev-123456.okta.com")
}
```
