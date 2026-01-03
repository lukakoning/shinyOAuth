# OAuthProvider S7 class

S7 class representing an OAuth 2.0 provider configuration. Includes
endpoints, OIDC settings, and various security options which govern the
OAuth and OIDC flows.

This is a low-level constructor intended for advanced use. Most users
should prefer the helper constructors
[`oauth_provider()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_provider.md)
for generic OAuth 2.0 providers or
[`oauth_provider_oidc()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_provider_oidc.md)
/
[`oauth_provider_oidc_discover()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_provider_oidc_discover.md)
for OpenID Connect providers. Those helpers enable secure defaults based
on the presence of an issuer and available endpoints.

## Usage

``` r
OAuthProvider(
  name = character(0),
  auth_url = character(0),
  token_url = character(0),
  userinfo_url = NA_character_,
  introspection_url = NA_character_,
  revocation_url = NA_character_,
  issuer = NA_character_,
  use_nonce = FALSE,
  use_pkce = TRUE,
  pkce_method = "S256",
  userinfo_required = FALSE,
  userinfo_id_selector = function(userinfo) userinfo$sub,
  userinfo_id_token_match = FALSE,
  id_token_required = FALSE,
  id_token_validation = FALSE,
  extra_auth_params = list(),
  extra_token_params = list(),
  extra_token_headers = character(0),
  token_auth_style = "header",
  jwks_cache = cachem::cache_mem(max_age = 3600),
  jwks_pins = character(0),
  jwks_pin_mode = "any",
  jwks_host_issuer_match = FALSE,
  jwks_host_allow_only = NA_character_,
  allowed_algs = c("RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256",
    "ES384", "ES512", "EdDSA"),
  allowed_token_types = character(0),
  leeway = getOption("shinyOAuth.leeway", 30)
)
```

## Arguments

- name:

  Provider name (e.g., "github", "google"). Cosmetic only; used in
  logging and audit events

- auth_url:

  Authorization endpoint URL

- token_url:

  Token endpoint URL

- userinfo_url:

  User info endpoint URL (optional)

- introspection_url:

  Token introspection endpoint URL (optional; RFC 7662)

- revocation_url:

  Token revocation endpoint URL (optional; RFC 7009)

- issuer:

  OIDC issuer URL (optional; required for ID token validation). This is
  the base URL that identifies the OpenID Provider (OP). It is used
  during ID token validation to verify the `iss` claim in the ID token
  matches the expected issuer. It is also used to fetch the provider's
  JSON Web Key Set (JWKS) for verifying ID token signatures (typically
  via the OIDC discovery document located at
  `/.well-known/openid-configuration` relative to the issuer URL)

- use_nonce:

  Whether to use OIDC nonce. This adds a `nonce` parameter to the
  authorization request and validates the `nonce` claim in the ID token.
  This is recommended for OIDC flows to mitigate replay attacks

- use_pkce:

  Whether to use PKCE. This adds a `code_challenge` parameter to the
  authorization request and requires a `code_verifier` when exchanging
  the authorization code for tokens. This is prevents authorization code
  interception attacks

- pkce_method:

  PKCE code challenge method ("S256" or "plain"). "S256" is recommended.
  "plain" should only be used for non-compliant providers that do not
  support "S256"

- userinfo_required:

  Whether to fetch userinfo after token exchange. User information will
  be stored in the `userinfo` field of the returned `OAuthToken` object.
  This requires a valid `userinfo_url` to be set. If fetching the
  userinfo fails, the token exchange will fail.

  For the low-level constructor
  [`oauth_provider()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_provider.md),
  when not explicitly supplied, this is inferred from the presence of a
  non-empty `userinfo_url`: if a `userinfo_url` is provided,
  `userinfo_required` defaults to `TRUE`, otherwise it defaults to
  `FALSE`. This avoids unexpected validation errors when `userinfo_url`
  is omitted (since it is optional).

- userinfo_id_selector:

  A function that extracts the user ID from the userinfo response.#'
  Should take a single argument (the userinfo list) and return the user
  ID as a string.

  This is used when `userinfo_id_token_match` is TRUE. Optional
  otherwise; when not supplied, some features (like subject matching)
  will be unavailable. Helper constructors like
  [`oauth_provider()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_provider.md)
  and
  [`oauth_provider_oidc()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_provider_oidc.md)
  provide a default selector that extracts the `sub` field.

- userinfo_id_token_match:

  Whether to verify that the user ID ("sub") from the ID token matches
  the user ID extracted from the userinfo response. This requires both
  `userinfo_required` and `id_token_validation` to be TRUE (and thus a
  valid `userinfo_url` and `issuer` to be set, plus potentially setting
  the client's scope to include "openid", so that an ID token is
  returned). Furthermore, the provider's `userinfo_id_selector` must be
  configured to extract the user ID from the userinfo response. This
  check helps ensure the integrity of the user information by confirming
  that both sources agree on the user's identity.

  For
  [`oauth_provider()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_provider.md),
  when not explicitly supplied, this is inferred as `TRUE` only if both
  `userinfo_required` and `id_token_validation` are `TRUE`; otherwise it
  defaults to `FALSE`.

- id_token_required:

  Whether to require an ID token to be returned during token exchange.
  If no ID token is returned, the token exchange will fail. This
  requires the provider to be a valid OpenID Connect provider and may
  require setting the client's scope to include "openid".

  Note: At the S7 class level, this defaults to FALSE so that pure OAuth
  2.0 providers can be configured without OIDC. Helper constructors like
  [`oauth_provider()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_provider.md)
  and
  [`oauth_provider_oidc()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_provider_oidc.md)
  will enable this when an issuer is supplied or OIDC is explicitly
  requested.

- id_token_validation:

  Whether to perform ID token validation after token exchange. This
  requires the provider to be a valid OpenID Connect provider with a
  configured `issuer` and the token response to include an ID token (may
  require setting the client's scope to include "openid").

  Note: At the S7 class level, this defaults to FALSE. Helper
  constructors like
  [`oauth_provider()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_provider.md)
  and
  [`oauth_provider_oidc()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_provider_oidc.md)
  turn this on when an issuer is provided or when OIDC is used.

- extra_auth_params:

  Extra parameters for authorization URL

- extra_token_params:

  Extra parameters for token exchange

- extra_token_headers:

  Extra headers for token exchange requests (named character vector)

- token_auth_style:

  How to authenticate when exchanging tokens. One of:

  - "header": HTTP Basic (client_secret_basic)

  - "body": Form body (client_secret_post)

  - "client_secret_jwt": JWT client assertion signed with HMAC using
    client_secret (RFC 7523)

  - "private_key_jwt": JWT client assertion signed with an asymmetric
    key (RFC 7523)

- jwks_cache:

  JWKS cache backend. If not provided, a
  `cachem::cache_mem(max_age = 3600)` (1 hour) cache will be created.
  May be any cachem‑compatible backend, including
  [`cachem::cache_disk()`](https://cachem.r-lib.org/reference/cache_disk.html)
  for a filesystem cache shared across workers, or a custom
  implementation created via
  [`custom_cache()`](https://lukakoning.github.io/shinyOAuth/reference/custom_cache.md)
  (e.g., database/Redis backed).

  TTL guidance: Choose `max_age` in line with your identity platform’s
  JWKS rotation and cache‑control cadence. A range of 15 minutes to 2
  hours is typically sensible; the default is 1 hour. Shorter TTLs adopt
  new keys faster at the cost of more JWKS traffic; longer TTLs reduce
  traffic but may delay new keys slightly. Signature verification will
  automatically perform a one‑time JWKS refresh when a new `kid` appears
  in an ID token.

  Cache keys are internal, hashed by issuer and pinning configuration.
  Cache values are lists with elements `jwks` and `fetched_at` (numeric
  epoch seconds)

- jwks_pins:

  Optional character vector of RFC 7638 JWK thumbprints (base64url) to
  pin against. If non-empty, fetched JWKS must contain keys whose
  thumbprints match these values depending on `jwks_pin_mode`. Use to
  reduce key substitution risks by pre-authorizing expected keys

- jwks_pin_mode:

  Pinning policy when `jwks_pins` is provided. Either "any" (default; at
  least one key in JWKS must match) or "all" (every RSA/EC public key in
  JWKS must match one of the configured pins)

- jwks_host_issuer_match:

  When TRUE, enforce that the discovery `jwks_uri` host matches the
  issuer host (or a subdomain). Defaults to FALSE at the class level,
  but helper constructors for OIDC (e.g.,
  [`oauth_provider_oidc()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_provider_oidc.md)
  and
  [`oauth_provider_oidc_discover()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_provider_oidc_discover.md))
  enable this by default for safer config. The generic helper
  [`oauth_provider()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_provider.md)
  will also automatically set this to TRUE when an `issuer` is provided
  and either `id_token_validation` or `id_token_required` is TRUE
  (OIDC-like configuration). Set explicitly to FALSE to opt out. For
  providers that legitimately publish JWKS on a different host (e.g.,
  Google), prefer setting `jwks_host_allow_only` to the exact hostname
  rather than disabling this check

- jwks_host_allow_only:

  Optional explicit hostname that the jwks_uri must match. When
  provided, jwks_uri host must equal this value (exact match). You can
  pass either just the host (e.g., "www.googleapis.com") or a full URL;
  only the host component will be used. If you need to include a port or
  an IPv6 literal, pass a full URL (e.g., `https://[::1]:8443`) — the
  port is ignored and only the hostname part is used for matching. Takes
  precedence over `jwks_host_issuer_match`

- allowed_algs:

  Optional vector of allowed JWT algorithms for ID tokens. Use to
  restrict acceptable `alg` values on a per-provider basis. Supported
  asymmetric algorithms include `RS256`, `RS384`, `RS512`, `PS256`,
  `PS384`, `PS512`, `ES256`, `ES384`, `ES512`, and `EdDSA`
  (Ed25519/Ed448 via OKP). Symmetric HMAC algorithms `HS256`, `HS384`,
  `HS512` are also supported but require that you supply a
  `client_secret` and explicitly enable HMAC verification via the option
  `options(shinyOAuth.allow_hs = TRUE)`. Defaults to
  `c("RS256","RS384","RS512","PS256","PS384","PS512", "ES256","ES384","ES512","EdDSA")`,
  which intentionally excludes HS\*. Only include `HS*` if you are
  certain the `client_secret` is stored strictly server-side and is
  never shipped to, or derivable by, the browser or other untrusted
  environments. Prefer rotating secrets regularly when enabling this.

- allowed_token_types:

  Character vector of acceptable OAuth token types returned by the token
  endpoint (case-insensitive). When non-empty, the token response MUST
  include `token_type` and it must be one of the allowed values;
  otherwise the flow fails fast with a `shinyOAuth_token_error`. When
  empty, no check is performed and `token_type` may be omitted by the
  provider. Helper constructors default this more strictly: for
  [`oauth_provider()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_provider.md)
  when an `issuer` is supplied or OIDC flags are enabled,
  `allowed_token_types` defaults to `c("Bearer")` to enforce Bearer by
  default; otherwise it remains empty. You can override to widen or
  disable enforcement by setting it explicitly

- leeway:

  Clock skew leeway (seconds) applied to ID token `exp`/`iat` checks.
  Default 30. Can be globally overridden via option `shinyOAuth.leeway`

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
#> Warning: [shinyOAuth] - Configure allowed hosts for production
#> ! No host allowlist configured via `options(shinyOAuth.allowed_hosts =
#>   c(".example.com", "api.example.com"))`.
#> ℹ Restricting hosts hardens redirect and API endpoint validation.
#> ℹ See `?is_ok_host` for policy details and review the 'authentication-flow'
#>   vignette
#> This warning is displayed once per session.

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
