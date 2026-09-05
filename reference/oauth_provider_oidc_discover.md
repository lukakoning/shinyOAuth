# Discover and create an OpenID Connect (OIDC) [OAuthProvider](https://lukakoning.github.io/shinyOAuth/reference/OAuthProvider.md)

Supply your provider's issuer URL to create an
[OAuthProvider](https://lukakoning.github.io/shinyOAuth/reference/OAuthProvider.md)
without entering each service URL yourself. The helper downloads the
provider's discovery document (OpenID Connect Discovery) and enables
OIDC login checks. Pass the result to
[`oauth_client()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_client.md).

## Usage

``` r
oauth_provider_oidc_discover(
  issuer,
  name = NULL,
  use_pkce = TRUE,
  use_nonce = TRUE,
  id_token_validation = TRUE,
  token_auth_style = NULL,
  allowed_algs = c("RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "EdDSA"),
  allowed_token_types = c("Bearer"),
  jwks_host_issuer_match = TRUE,
  issuer_match = c("url", "host", "none"),
  ...
)
```

## Arguments

- issuer:

  The OIDC issuer base URL (including scheme), e.g.,
  "https://login.example.com". The standard discovery-document URL
  ending in `/.well-known/openid-configuration` is also accepted and
  normalized back to the issuer base URL before validation and fetch.

- name:

  Optional friendly provider name. Defaults to the issuer hostname

- use_pkce:

  Logical, whether to use PKCE for this provider. Defaults to TRUE.
  Public clients require PKCE. Setting FALSE also prevents automatic
  selection of public-client authentication; a confidential-client
  method must be available or explicitly configured instead.

- use_nonce:

  Logical, whether to use OIDC nonce. Defaults to TRUE

- id_token_validation:

  Logical, whether to validate ID tokens automatically for this
  provider. Defaults to TRUE

- token_auth_style:

  Authentication style for token requests: "header"
  (client_secret_basic), "body" (client_secret_post), or "public"
  (public client; send `client_id` only). The alias `"none"` is also
  accepted for `"public"`. If NULL (default), it is inferred
  conservatively from discovery. When PKCE is enabled and the provider
  advertises support for public clients via `none`, discovery selects
  `"public"`. Otherwise, the helper prefers `"header"`
  (client_secret_basic) when available, then `"body"`
  (client_secret_post). JWT methods (`"client_secret_jwt"`,
  `"private_key_jwt"`) and mTLS methods (`"tls_client_auth"`,
  `"self_signed_tls_client_auth"`) must be selected explicitly. See
  [`oauth_provider()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_provider.md)
  for the supported methods and their credentials.

- allowed_algs:

  Character vector of allowed ID token signing algorithms. Defaults to a
  broad set of common algorithms, including RSA (RS\*), ECDSA (ES\*),
  and EdDSA. If the discovery document advertises supported algorithms,
  the intersection of advertised and caller-provided algorithms is used
  to avoid runtime mismatches. If there's no overlap, discovery fails
  with a configuration error (no fallback).

- allowed_token_types:

  Character vector of allowed token types for access tokens issued by
  this provider. Defaults to 'Bearer'

- jwks_host_issuer_match:

  When TRUE (default), enforce that the JWKS host discovered from the
  provider matches the issuer host exactly. For providers that serve
  JWKS from a different host, set `jwks_host_allow_only` to the exact
  hostname instead of disabling this. Disabling (`FALSE`) is not
  recommended unless you also pin JWKS via `jwks_host_allow_only` or
  `jwks_pins`.

- issuer_match:

  Character scalar controlling how strictly to validate the discovery
  document's `issuer` against the input `issuer`.

  - `"url"` (default): require the issuer used for discovery to match
    exactly after normalizing a full discovery-document input back to
    its issuer base URL, including any trailing slash (recommended).

  - `"host"`: compare only scheme + host (explicit opt-out; not
    recommended).

  - `"none"`: do not validate issuer consistency.

  Prefer `"url"` and tighten hosts via
  `options(shinyOAuth.allowed_hosts)` when feasible.

- ...:

  Additional fields passed to
  [`oauth_provider()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_provider.md)
  (for example, `pkce_method = "plain"` when a provider explicitly
  advertises only plain PKCE support and you intentionally want to allow
  that downgrade).

## Value

[OAuthProvider](https://lukakoning.github.io/shinyOAuth/reference/OAuthProvider.md)
object configured from discovery

## Details

This function makes a network request. Call it once during app setup,
outside `server()`. Copy the issuer URL exactly from your provider's
configuration, including any trailing slash. A full discovery-document
URL is also accepted.

Discovered token, UserInfo, introspection, and revocation endpoints are
copied into the provider when present. Discovering an introspection
endpoint does not itself require token introspection; set
`introspect = TRUE` on
[`oauth_client()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_client.md)
when login and refresh must perform that check.

Discovery describes what a service supports. Your app's registration may
require a particular `token_auth_style`, secret, or key; configure those
to match the registration. If PKCE is enabled and public authentication
(`none`) is advertised, automatic selection uses `"public"`. Otherwise
it prefers `"header"`, then `"body"`. JWT and mTLS methods must be
selected explicitly.

## Discovery validation

The discovered issuer must match the requested identifier by default.
Endpoints must use HTTPS. Host allowlisting does not permit HTTP: local
OIDC development requires
`options(shinyOAuth.allow_insecure_oidc_loopback = TRUE)` and a loopback
host. `options(shinyOAuth.allowed_hosts)` can further restrict endpoint
hosts. Signing-key hosts have their own policy: by default they must
match the issuer host; use `jwks_host_allow_only` for a known different
host.

The document must advertise the code flow (`response_types_supported`
includes `"code"`), non-empty `subject_types_supported`, RS256 in
`id_token_signing_alg_values_supported`, and a `jwks_uri` even when
automatic ID token validation is disabled. The permitted ID token
algorithms are the intersection of `allowed_algs` and the advertised
algorithms; an empty intersection is an error. Discovery keeps PKCE
`S256` and errors when the provider explicitly excludes it, unless you
select `pkce_method = "plain"`.

## Advanced metadata

Discovery also records capabilities for PAR, signed/encrypted requests,
JARM, DPoP, mTLS, and callback issuer identification. Client
construction checks the selected features against this metadata. See
[`oauth_provider()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_provider.md)
for individual fields and the [advanced security
vignette](https://lukakoning.github.io/shinyOAuth/articles/advanced-security.html)
for setup.

When omitted by the provider, OIDC defaults apply: the JAR `request`
parameter is unsupported, request URIs are supported, request URI
registration is not required, and response modes are
`c("query", "fragment")`. A mode still has to be implemented by
shinyOAuth to be usable. Caller-published request URI registration must
be arranged with the provider; discovery cannot check your registration.
PAR-issued handles do not need that client-hosted URI registration.

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
# For a complete app using a custom tenant ID, see:
# https://lukakoning.github.io/shinyOAuth/reference/oauth_provider_microsoft.html

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
  options(shinyOAuth.allow_insecure_oidc_loopback = TRUE)
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
