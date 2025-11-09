# Create a Keycloak [OAuthProvider](https://lukakoning.github.io/shinyOAuth/reference/OAuthProvider.md) (via OIDC discovery)

Create a Keycloak
[OAuthProvider](https://lukakoning.github.io/shinyOAuth/reference/OAuthProvider.md)
(via OIDC discovery)

## Usage

``` r
oauth_provider_keycloak(
  base_url,
  realm,
  name = paste0("keycloak-", realm),
  token_auth_style = "body"
)
```

## Arguments

- base_url:

  Base URL of the Keycloak server, e.g., "localhost:8080"

- realm:

  Keycloak realm name, e.g., "myrealm"

- name:

  Optional provider name. Defaults to `paste0('keycloak-', realm)`

- token_auth_style:

  Optional override for token endpoint authentication method. One of
  "header" (client_secret_basic), "body" (client_secret_post),
  "private_key_jwt", or "client_secret_jwt". Defaults to "body" for
  Keycloak, which works for both confidential clients and public PKCE
  clients (secretless). If you pass `NULL`, discovery will infer the
  method from the provider's `token_endpoint_auth_methods_supported`
  metadata.

## Value

[OAuthProvider](https://lukakoning.github.io/shinyOAuth/reference/OAuthProvider.md)
object configured for the specified Keycloak realm

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
# \donttest{
# Using Auth0 sample issuer as an example
oidc_discovery_provider <- oauth_provider_oidc_discover(
  issuer = "https://samples.auth0.com"
)
# }

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
# \donttest{
slack_provider <- oauth_provider_slack()
# }
  
# Keycloak
# (requires configured Keycloak realm; example below is therefore not run)
if (FALSE) { # \dontrun{
oauth_provider_keycloak(base_url = "http://localhost:8080", realm = "myrealm")
} # }

# Auth0
# (requires configured Auth0 domain; example below is therefore not run)
if (FALSE) { # \dontrun{
oauth_provider_auth0(domain = "your-tenant.auth0.com")
} # }

# Okta
# (requires configured Okta domain; example below is therefore not run)
if (FALSE) { # \dontrun{
oauth_provider_okta(domain = "dev-123456.okta.com")
} # }
```
