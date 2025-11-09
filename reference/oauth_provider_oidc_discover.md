# Discover and create an OpenID Connect (OIDC) [OAuthProvider](https://lukakoning.github.io/shinyOAuth/reference/OAuthProvider.md)

Uses the OpenID Connect discovery document at
`/.well-known/openid-configuration` to auto-configure an
[OAuthProvider](https://lukakoning.github.io/shinyOAuth/reference/OAuthProvider.md).
When present, `introspection_endpoint` is wired into the resulting
provider for RFC 7662 support.

## Usage

``` r
oauth_provider_oidc_discover(
  issuer,
  name = NULL,
  use_pkce = TRUE,
  use_nonce = TRUE,
  id_token_validation = TRUE,
  token_auth_style = NULL,
  allowed_algs = c("RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256",
    "ES384", "ES512", "EdDSA"),
  allowed_token_types = c("Bearer"),
  jwks_host_issuer_match = TRUE,
  issuer_match = TRUE,
  ...
)
```

## Arguments

- issuer:

  The OIDC issuer base URL (including scheme), e.g.,
  "https://login.example.com"

- name:

  Optional friendly provider name. Defaults to the issuer hostname

- use_pkce:

  Logical, whether to use PKCE for this provider. Defaults to TRUE. If
  the discovery document indicates
  `token_endpoint_auth_methods_supported` includes "none", PKCE is
  required unless `use_pkce` is explicitly set to FALSE (not
  recommended)

- use_nonce:

  Logical, whether to use OIDC nonce. Defaults to TRUE

- id_token_validation:

  Logical, whether to validate ID tokens automatically for this
  provider. Defaults to TRUE

- token_auth_style:

  Authentication style for token requests: "header"
  (client_secret_basic) or "body" (client_secret_post). If NULL
  (default), it is inferred conservatively from discovery. When PKCE is
  enabled and the provider advertises support for public clients via
  `none`, a secretless flow is preferred (modeled as `"body"` without
  credentials). Otherwise, the helper prefers `"header"`
  (client_secret_basic) when available, then `"body"`
  (client_secret_post). JWT-based methods are not auto-selected unless
  explicitly requested

- allowed_algs:

  Character vector of allowed ID token signing algorithms. Defaults to a
  broad set of common algorithms, including RSA (RS\*), RSA-PSS (PS\*),
  ECDSA (ES\*), and EdDSA. If the discovery document advertises
  supported algorithms, the intersection of advertised and
  caller-provided algorithms is used to avoid runtime mismatches. If
  there's no overlap, discovery fails with a configuration error (no
  fallback)

- allowed_token_types:

  Character vector of allowed token types for access tokens issued by
  this provider. Defaults to 'Bearer'

- jwks_host_issuer_match:

  When TRUE (default), enforce that the JWKS host discovered from the
  provider matches the issuer host (or a subdomain). For providers that
  serve JWKS from a different host, set `jwks_host_allow_only` to the
  exact hostname instead of disabling this. Disabling (`FALSE`) is not
  recommended unless you also pin JWKS via `jwks_host_allow_only` or
  `jwks_pins`

- issuer_match:

  Logical, default TRUE. When TRUE, requires the discovery issuer's
  scheme/host to match the input `issuer`. When FALSE, host mismatch is
  allowed. Prefer tightening hosts via
  `options(shinyOAuth.allowed_hosts)` when feasible

- ...:

  Additional fields passed to
  [`oauth_provider()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_provider.md)

## Value

[OAuthProvider](https://lukakoning.github.io/shinyOAuth/reference/OAuthProvider.md)
object configured from discovery

## Details

- ID token algorithms: by default this helper accepts common asymmetric
  algorithms RSA (RS\*), RSA-PSS (PS\*), ECDSA (ES\*), and EdDSA. When
  the provider advertises its supported ID token signing algorithms via
  `id_token_signing_alg_values_supported`, the helper uses the
  intersection with the caller-provided `allowed_algs`. If there is no
  overlap, discovery fails with a configuration error. There is no
  automatic fallback to the discovery-advertised set.

- Token endpoint authentication methods: supports `client_secret_basic`
  (header), `client_secret_post` (body), public clients using `none`
  (with PKCE), as well as JWT-based methods `private_key_jwt` and
  `client_secret_jwt` per RFC 7523.

  Important: discovery metadata lists methods supported across the
  provider, not per-client provisioning. This helper does not
  automatically select JWT-based methods just because they are
  advertised. By default it prefers `client_secret_basic` (header) when
  available, otherwise `client_secret_post` (body), and only uses public
  `none` for PKCE clients. If a provider advertises only JWT methods,
  you must explicitly set `token_auth_style` and configure the
  corresponding credentials on your
  [OAuthClient](https://lukakoning.github.io/shinyOAuth/reference/OAuthClient.md)
  (a private key for `private_key_jwt`, or a sufficiently strong
  `client_secret` for `client_secret_jwt`).

- Host policy: by default, discovered endpoints must be absolute URLs
  whose host matches the issuer host exactly. Subdomains are NOT
  implicitly allowed. If you want to allow subdomains, add a leading-dot
  or glob in `options(shinyOAuth.allowed_hosts)`, e.g., `.example.com`
  or `*.example.com`. If a global whitelist is supplied via
  `options(shinyOAuth.allowed_hosts)`, discovery will restrict endpoints
  to that whitelist. Scheme policy (https/http for loopback) is
  delegated to
  [`is_ok_host()`](https://lukakoning.github.io/shinyOAuth/reference/is_ok_host.md),
  so you may allow non-HTTPS hosts with
  `options(shinyOAuth.allowed_non_https_hosts)` (see
  [`?is_ok_host`](https://lukakoning.github.io/shinyOAuth/reference/is_ok_host.md)).

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
