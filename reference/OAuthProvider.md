# OAuthProvider S7 class

S7 class describing an OAuth 2.0 or OpenID Connect provider. It stores
the provider's endpoints and the rules shinyOAuth should follow during
login, callback handling, token exchange, and optional OIDC checks.

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
  par_url = NA_character_,
  require_pushed_authorization_requests = FALSE,
  authorization_request_front_channel_mode = "compat",
  request_object_signing_alg_values_supported = character(0),
  request_object_encryption_alg_values_supported = character(0),
  request_object_encryption_enc_values_supported = character(0),
  request_object_encryption_jwk = NULL,
  require_signed_request_object = FALSE,
  request_parameter_supported = NA,
  request_uri_parameter_supported = NA,
  require_request_uri_registration = NA,
  token_endpoint_auth_signing_alg_values_supported = character(0),
  dpop_signing_alg_values_supported = character(0),
  authorization_response_iss_parameter_supported = FALSE,
  response_modes_supported = character(0),
  issuer = NA_character_,
  issuer_match = "url",
  use_nonce = FALSE,
  use_pkce = TRUE,
  pkce_method = "S256",
  userinfo_required = FALSE,
  userinfo_id_selector = function(userinfo) userinfo$sub,
  userinfo_id_token_match = FALSE,
  userinfo_signed_jwt_required = FALSE,
  id_token_required = FALSE,
  id_token_validation = FALSE,
  id_token_at_hash_required = FALSE,
  extra_auth_params = list(),
  extra_token_params = list(),
  extra_token_headers = character(0),
  mtls_endpoint_aliases = list(),
  tls_client_certificate_bound_access_tokens = FALSE,
  token_auth_style = "header",
  jwks_cache = cachem::cache_mem(max_age = 3600),
  jwks_pins = character(0),
  jwks_pin_mode = "any",
  jwks_host_issuer_match = FALSE,
  jwks_host_allow_only = NA_character_,
  allowed_algs = c("RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "EdDSA"),
  allowed_token_types = "Bearer",
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

- par_url:

  Optional Pushed Authorization Request (PAR) URL (RFC 9126). When set,
  shinyOAuth first sends the authorization request from server to
  provider and then redirects the browser with the returned
  `request_uri` handle instead of the full request payload. Most users
  only need this when their provider specifically supports or requires
  PAR.

- require_pushed_authorization_requests:

  Logical. Whether the provider requires authorization requests to be
  sent via PAR. When `TRUE`, `par_url` must also be configured.

- authorization_request_front_channel_mode:

  Character scalar controlling which browser-visible outer parameters
  shinyOAuth keeps when the actual authorization request is carried by
  JAR or PAR. Use `"compat"` (default) to keep the current
  OIDC-compatible shape with outer `client_id`, `response_type`, and
  `scope` when an issuer is configured. Use `"minimal"` for stricter
  authorization servers that expect only `client_id` alongside `request`
  or `request_uri`.

- request_object_signing_alg_values_supported:

  Optional vector of JWS algorithms that the provider advertises for
  signed Request Objects (RFC 9101). This is mainly used for early
  validation when an
  [OAuthClient](https://lukakoning.github.io/shinyOAuth/reference/OAuthClient.md)
  sends `authorization_request_mode = "request"` or
  `authorization_request_mode = "request_uri"`.

- request_object_encryption_alg_values_supported:

  Optional vector of JWE key-management algorithms that the provider
  advertises for encrypted Request Objects. This metadata is used for
  early validation when an
  [OAuthClient](https://lukakoning.github.io/shinyOAuth/reference/OAuthClient.md)
  enables Request Object encryption.

- request_object_encryption_enc_values_supported:

  Optional vector of JWE content-encryption algorithms that the provider
  advertises for encrypted Request Objects. This metadata is used for
  early validation when an
  [OAuthClient](https://lukakoning.github.io/shinyOAuth/reference/OAuthClient.md)
  enables Request Object encryption.

- request_object_encryption_jwk:

  Optional explicit recipient public key used to encrypt Request Objects
  when discovery-backed JWKS selection is not available or when you need
  to pin one specific encryption key. Accepts an OpenSSL public key, a
  PEM public-key string, a parsed JWK object, or a JWK JSON string.

- require_signed_request_object:

  Logical. Whether the provider requires signed Request Objects for
  authorization requests. When `TRUE`, clients should use
  `authorization_request_mode = "request"` or
  `authorization_request_mode = "request_uri"`.

- request_parameter_supported:

  Logical or `NA`. Whether discovery metadata explicitly advertises
  support for the authorization-request `request` parameter. `NA` means
  the provider did not say. Discovery-derived providers apply the OpenID
  Connect default (`FALSE`) when this metadata is omitted.

- request_uri_parameter_supported:

  Logical or `NA`. Whether discovery metadata explicitly advertises
  support for the authorization-request `request_uri` parameter for
  caller-managed request URIs. `NA` means the provider did not say.
  Discovery-derived providers apply the OpenID Connect default (`TRUE`)
  when this metadata is omitted. PAR-issued `request_uri` handles remain
  valid even when this metadata is `FALSE`.

- require_request_uri_registration:

  Logical or `NA`. Whether discovery metadata says caller-managed
  `request_uri` values must be pre-registered. `NA` means the provider
  did not say. Discovery-derived providers apply the OpenID Connect
  default (`FALSE`) when this metadata is omitted. shinyOAuth can
  publish caller-managed `request_uri` values through
  [`oauth_module_server()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_module_server.md).
  When this is `TRUE`, make sure the provider has a matching public
  request URI or wildcard prefix registered for the client. shinyOAuth
  stores this metadata for caller awareness, but it cannot verify
  provider-side registration state automatically.

- token_endpoint_auth_signing_alg_values_supported:

  Optional vector of JWS algorithms that the provider advertises for
  JWT-based client authentication (`client_secret_jwt` /
  `private_key_jwt`) at the token endpoint. This metadata is used for
  early validation of `OAuthClient@client_assertion_alg` and inferred
  JWT client-assertion defaults.

- dpop_signing_alg_values_supported:

  Optional vector of JWS algorithms that the provider advertises for
  DPoP proof JWTs (RFC 9449). This metadata is used for early validation
  of `OAuthClient@dpop_signing_alg` and inferred outbound DPoP signing
  defaults.

- authorization_response_iss_parameter_supported:

  Logical. Whether the provider advertises RFC 9207 support for
  returning an `iss` parameter on the authorization response. When
  `TRUE`, the
  [`oauth_client()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_client.md)
  helper can auto-enable callback issuer enforcement when the caller
  leaves `enforce_callback_issuer` unset and the provider also has a
  configured `issuer`.

- response_modes_supported:

  Optional character vector of OAuth/OIDC `response_mode` values
  advertised by the provider. Discovery-backed providers use the
  discovery metadata value, defaulting to `c("query", "fragment")` when
  omitted per OIDC Discovery/RFC 8414. Generic providers may leave this
  empty when capabilities are not known. Provider metadata may include
  response modes that shinyOAuth does not implement, such as JARM values
  ending in `.jwt`; clients still fail fast if they request one of those
  unsupported modes.

- issuer:

  Optional OIDC issuer URL. You need this when you want ID token
  validation. shinyOAuth uses it to verify the ID token `iss` claim and
  to locate the provider's signing keys (JWKS), typically through the
  OIDC discovery document at `/.well-known/openid-configuration`.

- issuer_match:

  Character scalar controlling how strictly the discovery document's
  `issuer` is validated against `issuer` when it later performs runtime
  discovery to locate the JWKS URI.

  - `"url"` (default): require the full issuer URL to match after
    trailing-slash normalization.

  - `"host"`: compare only scheme + host.

  - `"none"`: do not validate discovery issuer consistency.

  In most cases, keep the default `"url"`. Use `"host"` only for
  providers that publish tenant-independent metadata with a templated
  issuer, such as some Microsoft aliases.

- use_nonce:

  Whether to use OIDC nonce. This adds a `nonce` parameter to the
  authorization request and validates the `nonce` claim in the ID token.
  For OIDC providers, leaving this enabled is usually the right choice.

- use_pkce:

  Whether to use PKCE. This adds a `code_challenge` parameter to the
  authorization request and requires a `code_verifier` when exchanging
  the authorization code for tokens. This helps protect against
  authorization code interception attacks.

- pkce_method:

  PKCE code challenge method ("S256" or "plain"). "S256" is recommended.
  Use "plain" only if you are working with a provider that does not
  support "S256".

- userinfo_required:

  Whether to fetch userinfo after token exchange. User information will
  be stored in the `userinfo` field of the returned `OAuthToken` object.
  This requires a valid `userinfo_url` to be set. If fetching userinfo
  fails, login fails.

  For the low-level constructor
  [`oauth_provider()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_provider.md),
  when not explicitly supplied, this is inferred from the presence of a
  non-empty `userinfo_url`: if a `userinfo_url` is provided,
  `userinfo_required` defaults to `TRUE`, otherwise it defaults to
  `FALSE`. This avoids unexpected validation errors when `userinfo_url`
  is omitted (since it is optional).

- userinfo_id_selector:

  A function that extracts the user ID from the userinfo response.
  Should take a single argument (the userinfo list) and return the user
  ID as a string.

  This is used for helpers that need a provider-specific user
  identifier, such as audit fields and UserInfo-to-ID-token subject
  matching. If you configure a selector other than `function(x) x$sub`,
  that selector also defines which UserInfo value is compared against
  the validated ID token `sub`. Helper constructors like
  [`oauth_provider()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_provider.md)
  and
  [`oauth_provider_oidc()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_provider_oidc.md)
  provide a default selector that extracts the `sub` field.

- userinfo_id_token_match:

  Whether to fail closed if UserInfo cannot be bound to a validated ID
  token subject. Whenever both UserInfo and a validated ID token are
  available, shinyOAuth compares the validated ID token `sub` to the
  value returned by `userinfo_id_selector(userinfo)`. Setting this field
  to `TRUE` additionally requires a validated ID token baseline whenever
  UserInfo is fetched. This requires `userinfo_required`, a configured
  `userinfo_id_selector`, plus either `id_token_validation` or
  `use_nonce` to be `TRUE`.

  For
  [`oauth_provider()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_provider.md),
  when not explicitly supplied, this is inferred as `TRUE` when
  `userinfo_required` is `TRUE` and either `id_token_validation` or
  `use_nonce` is `TRUE`; otherwise it defaults to `FALSE`.

- userinfo_signed_jwt_required:

  Whether to require that the userinfo endpoint returns a signed JWT
  (`Content-Type: application/jwt`) whose signature can be verified
  against the provider's JWKS. This is an advanced hardening option.
  When `TRUE`:

  - If the userinfo response is not `application/jwt`, authentication
    fails.

  - If the JWT uses `alg=none` or an algorithm not in the asymmetric
    subset of `allowed_algs` (`RS*`, `ES*`, or `EdDSA`), authentication
    fails. `HS*` algorithms are not accepted for UserInfo JWTs on this
    surface even if they appear in `allowed_algs`.

  - If signature verification fails (JWKS fetch error, no compatible
    keys, or invalid signature), authentication fails.

  This prevents unsigned or weakly signed userinfo payloads from being
  treated as trusted identity data. Requires `userinfo_required = TRUE`
  and a valid `issuer` (for JWKS). Defaults to `FALSE`.

  Note:
  [`oauth_provider_oidc_discover()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_provider_oidc_discover.md)
  does not auto-enable this flag. Discovery's
  `userinfo_signing_alg_values_supported` indicates provider capability,
  not that every client actually receives signed JWTs. Pass
  `userinfo_signed_jwt_required = TRUE` explicitly if you need this
  behavior.

- id_token_required:

  Whether to require an ID token to be returned during token exchange.
  If no ID token is returned, the token exchange will fail. This only
  makes sense for OpenID Connect providers and may require the client's
  scope to include `openid`.

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
  require setting the client's scope to include `openid`).

  Note: At the S7 class level, this defaults to FALSE. Helper
  constructors like
  [`oauth_provider()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_provider.md)
  and
  [`oauth_provider_oidc()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_provider_oidc.md)
  turn this on when an issuer is provided or when OIDC is used.

- id_token_at_hash_required:

  Whether to require the `at_hash` (Access Token hash) claim in the ID
  token. When `TRUE`, login fails if the ID token does not contain an
  `at_hash` claim or if the claim does not match the access token. When
  `FALSE` (default), `at_hash` is validated only when present. Requires
  `id_token_validation = TRUE`.

- extra_auth_params:

  Extra parameters for authorization URL

- extra_token_params:

  Extra parameters for token exchange

- extra_token_headers:

  Extra headers for back-channel token-style requests (named character
  vector). shinyOAuth applies these headers to token exchange, refresh,
  introspection, revocation, and PAR requests. Use this only for headers
  you intentionally want on that full set of authorization-server calls.

- mtls_endpoint_aliases:

  Optional named list of RFC 8705 mTLS endpoint aliases. Names should
  follow the metadata keys such as `token_endpoint`,
  `userinfo_endpoint`, `introspection_endpoint`, `revocation_endpoint`,
  `par_endpoint`, or `pushed_authorization_request_endpoint`, and values
  must be absolute URLs. This is an advanced setting used when a
  provider publishes separate mTLS-specific endpoints.

- tls_client_certificate_bound_access_tokens:

  Logical. Whether the authorization server advertises RFC 8705
  capability to issue certificate-bound access tokens. This describes
  server capability; the client still has to opt into mTLS separately.
  When `TRUE`, token responses may include a `cnf` claim with an
  `x5t#S256` thumbprint that downstream requests must match with the
  same certificate.

- token_auth_style:

  How the client authenticates at the token endpoint. One of:

  - "header": HTTP Basic (client_secret_basic)

  - "body": Form body (client_secret_post)

  - "public": Public-client form body (`none` in discovery metadata);
    sends `client_id` but never `client_secret`, even if one is
    configured. The alias `"none"` is also accepted.

  - "tls_client_auth": RFC 8705 mutual TLS client authentication using a
    client certificate chained to a trusted CA

  - "self_signed_tls_client_auth": RFC 8705 mutual TLS client
    authentication using a self-signed client certificate registered out
    of band with the provider

  - "client_secret_jwt": JWT client assertion signed with HMAC using
    client_secret (RFC 7523)

  - "private_key_jwt": JWT client assertion signed with an asymmetric
    key (RFC 7523)

- jwks_cache:

  Cache used for the provider's signing keys (JWKS). If not provided,
  shinyOAuth creates an in-memory cache for 1 hour with
  `cachem::cache_mem(max_age = 3600)`. You can also use another
  cachem-compatible backend, including a shared cache created with
  [`custom_cache()`](https://lukakoning.github.io/shinyOAuth/reference/custom_cache.md).

  In most cases, a TTL between 15 minutes and 2 hours is reasonable.
  Shorter TTLs pick up new keys faster but do more network work; longer
  TTLs reduce traffic but may take longer to notice key rotation. If a
  new `kid` appears, shinyOAuth will also do a one-time refresh
  automatically.

- jwks_pins:

  Optional character vector of RFC 7638 JWK thumbprints (base64url) to
  pin against. If non-empty, fetched JWKS must contain keys whose
  thumbprints match these values depending on `jwks_pin_mode`. This is
  an advanced hardening option that lets you pre-authorize expected
  keys.

- jwks_pin_mode:

  Pinning policy when `jwks_pins` is provided. Either "any" (default; at
  least one key in JWKS must match) or "all" (every RSA/EC/OKP public
  key in JWKS must match one of the configured pins)

- jwks_host_issuer_match:

  When TRUE, enforce that the discovery `jwks_uri` host matches the
  issuer host exactly. Defaults to FALSE at the class level, but helper
  constructors for OIDC (e.g.,
  [`oauth_provider_oidc()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_provider_oidc.md)
  and
  [`oauth_provider_oidc_discover()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_provider_oidc_discover.md))
  enable this by default for safer config. The generic helper
  [`oauth_provider()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_provider.md)
  will also automatically set this to TRUE when an `issuer` is provided
  and either `id_token_validation` or `id_token_required` is TRUE
  (OIDC-like configuration). Set explicitly to FALSE to opt out. For
  providers that legitimately publish JWKS on a different host (for
  example Google), prefer setting `jwks_host_allow_only` to the exact
  hostname rather than disabling this check.

- jwks_host_allow_only:

  Optional explicit hostname that the jwks_uri must match. When
  provided, jwks_uri host must equal this value (exact match). You can
  pass either just the host (e.g., "www.googleapis.com") or a full URL;
  only the host component will be used. If you need to include a port or
  an IPv6 literal, pass a full URL (e.g., `https://[::1]:8443`) - the
  port is ignored and only the hostname part is used for matching. Takes
  precedence over `jwks_host_issuer_match`.

- allowed_algs:

  Optional vector of allowed JWT algorithms for ID tokens. Use to
  restrict acceptable `alg` values on a per-provider basis. Supported
  asymmetric algorithms include `RS256`, `RS384`, `RS512`, `ES256`,
  `ES384`, `ES512`, and `EdDSA` for OKP-backed signatures. When ID token
  `at_hash` validation is in play, Ed25519 is supported. Ed448 `at_hash`
  cannot be validated with the current crypto bindings, so shinyOAuth
  skips that optional check unless `id_token_at_hash_required = TRUE`,
  in which case Ed448 ID tokens fail fast. Symmetric HMAC algorithms
  `HS256`, `HS384`, `HS512` are also supported but require that you
  supply a `client_secret` and explicitly enable HMAC verification via
  the option `options(shinyOAuth.allow_hs = TRUE)`. Defaults to
  `c("RS256","RS384","RS512","ES256","ES384","ES512","EdDSA")`, which
  intentionally excludes HS\*. Only include `HS*` if you are certain the
  `client_secret` is stored strictly server-side and is never shipped
  to, or derivable by, the browser or other untrusted environments.

- allowed_token_types:

  Character vector of acceptable OAuth token types returned by the token
  endpoint (case-insensitive). Successful token responses must always
  include `token_type`; when `allowed_token_types` is non-empty, its
  value must also be one of the allowed values or the flow fails fast
  with a `shinyOAuth_token_error`. The
  [`oauth_provider()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_provider.md)
  helper defaults to `c("Bearer")`. When the
  [OAuthClient](https://lukakoning.github.io/shinyOAuth/reference/OAuthClient.md)
  is configured with `dpop_private_key`, shinyOAuth also accepts
  `token_type = "DPoP"` and uses DPoP proofs on supported token and
  downstream requests. Other non-Bearer token types (for example `MAC`)
  still fail fast rather than being misused. Set
  `allowed_token_types = character()` explicitly only to disable the
  value allowlist while still requiring `token_type` itself.

- leeway:

  Clock skew leeway (seconds) applied to ID token `exp`/`iat`/`nbf`
  checks and state payload `issued_at` future check. Default 30. Can be
  globally overridden via option `shinyOAuth.leeway`.

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
