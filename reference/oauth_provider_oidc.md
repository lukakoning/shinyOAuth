# Create a generic OpenID Connect (OIDC) [OAuthProvider](https://lukakoning.github.io/shinyOAuth/reference/OAuthProvider.md)

Preconfigured
[OAuthProvider](https://lukakoning.github.io/shinyOAuth/reference/OAuthProvider.md)
for OpenID Connect (OIDC) compliant providers.

## Usage

``` r
oauth_provider_oidc(
  name,
  base_url,
  auth_path = "/authorize",
  token_path = "/token",
  userinfo_path = "/userinfo",
  introspection_path = "/introspect",
  use_nonce = TRUE,
  id_token_validation = TRUE,
  jwks_host_issuer_match = TRUE,
  allowed_token_types = c("Bearer"),
  ...
)
```

## Arguments

- name:

  Friendly name for the provider

- base_url:

  Base URL for OIDC endpoints

- auth_path:

  Authorization endpoint path (default: "/authorize")

- token_path:

  Token endpoint path (default: "/token")

- userinfo_path:

  User info endpoint path (default: "/userinfo")

- introspection_path:

  Token introspection endpoint path (default: "/introspect")

- use_nonce:

  Logical, whether to use OIDC nonce. Defaults to TRUE

- id_token_validation:

  Logical, whether to validate ID tokens automatically for this
  provider. Defaults to TRUE

- jwks_host_issuer_match:

  When TRUE (default), enforce that the JWKS host discovered from the
  provider matches the issuer host (or a subdomain). For providers that
  serve JWKS from a different host (e.g., Google), set
  `jwks_host_allow_only` to the exact hostname instead of disabling
  this. Disabling (`FALSE`) is not recommended unless you also pin JWKS
  via `jwks_host_allow_only` or `jwks_pins`

- allowed_token_types:

  Character vector of allowed token types for access tokens issued by
  this provider. Defaults to 'Bearer'

- ...:

  Additional arguments passed to
  [`oauth_provider()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_provider.md)

## Value

[OAuthProvider](https://lukakoning.github.io/shinyOAuth/reference/OAuthProvider.md)
object

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
