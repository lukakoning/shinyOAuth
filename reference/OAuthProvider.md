# OAuthProvider S7 class

An `OAuthProvider` describes a service such as Google or GitHub: where
users sign in, where your app requests tokens, and which checks to
perform. Start with a provider helper such as
[`oauth_provider_google()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_provider_google.md)
or
[`oauth_provider_oidc_discover()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_provider_oidc_discover.md).
Use
[`oauth_provider()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_provider.md)
for manual setup; these functions return an instance of this class with
the corresponding endpoint and validation settings.

## Usage

``` r
OAuthProvider(
  name = character(0),
  auth_url = character(0),
  token_url = character(0),
  issuer = NA_character_,
  issuer_thus_oidc = TRUE,
  issuer_match = "url",
  token_auth_style = "header",
  use_pkce = TRUE,
  pkce_method = "S256",
  use_nonce = is_valid_string(issuer) && isTRUE(issuer_thus_oidc),
  userinfo_url = NA_character_,
  userinfo_required = FALSE,
  userinfo_id_selector = function(userinfo) userinfo[["sub"]],
  userinfo_id_token_match = FALSE,
  userinfo_signed_jwt_required = FALSE,
  id_token_required = is_valid_string(issuer) && isTRUE(issuer_thus_oidc),
  id_token_validation = is_valid_string(issuer) && isTRUE(issuer_thus_oidc),
  id_token_at_hash_required = FALSE,
  introspection_url = NA_character_,
  revocation_url = NA_character_,
  extra_auth_params = list(),
  extra_token_params = list(),
  extra_token_headers = character(0),
  jwks_uri = NA_character_,
  jwks_cache = cachem::cache_mem(max_age = 3600),
  jwks_pins = character(0),
  jwks_pin_mode = "any",
  jwks_host_issuer_match = is_valid_string(issuer) && (isTRUE(id_token_validation) ||
    isTRUE(id_token_required)),
  jwks_host_allow_only = NA_character_,
  userinfo_allowed_algs = NULL,
  allowed_algs = c("RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "EdDSA"),
  allowed_token_types = "Bearer",
  leeway = getOption("shinyOAuth.leeway", 30),
  par_url = NA_character_,
  par_required = FALSE,
  signed_request_object_required = FALSE,
  request_parameter_supported = NA,
  request_uri_parameter_supported = NA,
  request_uri_registration_required = NA,
  request_object_signing_alg_values_supported = character(0),
  request_object_encryption_alg_values_supported = character(0),
  request_object_encryption_enc_values_supported = character(0),
  request_object_encryption_jwk = NULL,
  authorization_request_front_channel_mode = "compat",
  authorization_response_iss_parameter_supported = FALSE,
  response_modes_supported = character(0),
  jarm_signing_alg_values_supported = character(0),
  jarm_encryption_alg_values_supported = character(0),
  jarm_encryption_enc_values_supported = character(0),
  jarm_tolerate_duplicate_top_level_iss = FALSE,
  token_endpoint_auth_signing_alg_values_supported = character(0),
  endpoint_auth_metadata = list(),
  dpop_signing_alg_values_supported = character(0),
  mtls_endpoint_aliases = list(),
  mtls_client_certificate_bound_access_tokens = FALSE
)
```

## Arguments

- name:

  Provider name (e.g., "github", "google"). Cosmetic only; used in
  logging and audit events

- auth_url:

  URL of the provider's login and permission page.

- token_url:

  URL where R exchanges the returned code for tokens.

- issuer:

  Optional authorization-server issuer URL. You need this for issuer
  validation and features such as ID-token validation. shinyOAuth uses
  it to verify issuer claims and locate signing keys (JWKS), typically
  through an OIDC discovery document.

- issuer_thus_oidc:

  Whether setting `issuer` enables OpenID Connect behavior. Default
  `TRUE`: helpers enable OIDC nonce/ID token defaults and the client
  adds the `openid` scope. Set `FALSE` for an OAuth-only server that has
  an issuer identifier but does not implement OIDC.

- issuer_match:

  Character scalar controlling how strictly the discovery document's
  `issuer` is validated against `issuer` when it later performs runtime
  discovery to locate the JWKS URI.

  - `"url"` (default): require the issuer used for discovery to match
    the discovery metadata exactly, including any trailing slash.

  - `"host"`: compare only scheme + host.

  - `"none"`: do not validate discovery issuer consistency.

  In most cases, keep the default `"url"`. Use `"host"` only for
  providers that publish tenant-independent metadata with a templated
  issuer, such as some Microsoft aliases.

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

- use_pkce:

  Whether to protect the code exchange using Proof Key for Code Exchange
  (PKCE). Leave enabled; public clients require it. It sends a
  `code_challenge` with the login request and a matching secret
  `code_verifier` during token exchange.

- pkce_method:

  PKCE code challenge method ("S256" or "plain"). "S256" is recommended.
  Use "plain" only if you are working with a provider that does not
  support "S256".

- use_nonce:

  Whether to tie the ID token to this login using a random nonce. Keep
  enabled for OIDC. The nonce is sent in the request and checked in the
  returned ID token.

- userinfo_url:

  User info endpoint URL (optional)

- userinfo_required:

  Whether to fetch a user profile after token exchange. The result is
  stored in `token@userinfo`; a failed required fetch stops login. In
  [`oauth_provider()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_provider.md),
  this defaults to `TRUE` when `userinfo_url` is supplied and `FALSE`
  otherwise.

- userinfo_id_selector:

  A function that extracts the user ID from the userinfo response.
  Should take a single argument (the userinfo list) and return the user
  ID as a string.

  This is used for helpers that need a provider-specific application
  user identifier, such as audit fields. It does not replace OIDC
  subject binding: when a validated ID token and UserInfo are both
  available, their actual `sub` claims are always compared. Helper
  constructors like
  [`oauth_provider()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_provider.md)
  and
  [`oauth_provider_oidc()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_provider_oidc.md)
  provide a default selector that extracts `sub`.

- userinfo_id_token_match:

  Whether fetched userinfo requires a validated ID token for comparison.
  When both are available, their actual `sub` values are always
  compared. `TRUE` also stops login if the validated ID token is absent.
  Requires `userinfo_required` and either `id_token_validation` or
  `use_nonce`.
  [`oauth_provider()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_provider.md)
  enables this by default when those requirements are met.

- userinfo_signed_jwt_required:

  Whether to require the user profile to arrive as a signed JWT
  (`application/jwt`). Default `FALSE`; ordinary JSON userinfo is
  accepted. When `TRUE`, requires `userinfo_required` and `issuer`; the
  signature must validate with an asymmetric algorithm from
  `userinfo_allowed_algs`. Unsigned, HMAC-signed, and encrypted userinfo
  JWTs are not accepted by the normal configuration. Discovery does not
  enable this automatically: provider support does not mean your app's
  registration requests signed userinfo.

- id_token_required:

  Whether to require an ID token to be returned during token exchange.
  If no ID token is returned, the token exchange will fail. This only
  makes sense for OpenID Connect providers and may require the client's
  scope to include `openid`.

  Both the S7 constructor and
  [`oauth_provider()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_provider.md)
  enable this when an issuer is supplied and `issuer_thus_oidc = TRUE`.
  Pure OAuth 2.0 providers keep this disabled by default.

- id_token_validation:

  Whether to perform ID token validation after token exchange. This
  requires the provider to be a valid OpenID Connect provider with a
  configured `issuer` and the token response to include an ID token (may
  require setting the client's scope to include `openid`).

  Both the S7 constructor and
  [`oauth_provider()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_provider.md)
  enable this when an issuer is provided and `issuer_thus_oidc = TRUE`.
  Set an explicit `FALSE` only when intentionally opting out of ID token
  validation.

- id_token_at_hash_required:

  Whether to require the `at_hash` (Access Token hash) claim in the ID
  token. When `TRUE`, login fails if the ID token does not contain an
  `at_hash` claim or if the claim does not match the access token. When
  `FALSE` (default), `at_hash` is validated only when present. Requires
  `id_token_validation = TRUE`.

- introspection_url:

  Optional URL where the provider can confirm whether a token is still
  active (RFC 7662).

- revocation_url:

  Optional URL where the app can ask the provider to invalidate a token,
  for example during logout (RFC 7009).

- extra_auth_params:

  Extra parameters for authorization URL

- extra_token_params:

  Extra parameters for token exchange

- extra_token_headers:

  Extra headers for back-channel token-style requests (named character
  vector), applied only to token exchange and refresh. Configure
  `oauth_client(endpoint_auth = ...)` for headers needed by PAR,
  introspection, or revocation.

- jwks_uri:

  Optional URL of the provider's public signing keys (JWKS). Normally
  these are located through OIDC discovery. Set this for manual key
  configuration, including OAuth-only JARM providers.

- jwks_cache:

  Storage for the provider's public signing keys. Defaults to
  `cachem::cache_mem(max_age = 3600)`, an in-memory cache lasting one
  hour. A
  [`custom_cache()`](https://lukakoning.github.io/shinyOAuth/reference/custom_cache.md)
  can share keys across processes. Shorter lifetimes pick up changed
  keys sooner; longer lifetimes reduce network requests. The package
  also attempts a rate-limited refresh when a key is missing or no
  longer verifies a signature.

- jwks_pins:

  Optional character vector of RFC 7638 JWK thumbprints (base64url) to
  pin against. If non-empty, fetched JWKS must contain keys whose
  thumbprints match these values depending on `jwks_pin_mode`. This is
  an advanced hardening option that lets you pre-authorize expected
  keys. Only keys matching a configured pin are eligible for signature
  verification or Request Object encryption; `jwks_pin_mode` controls
  whether the surrounding JWK Set may also contain unpinned keys.

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

- userinfo_allowed_algs:

  Optional signing algorithm allowlist for UserInfo JWTs. `NULL`
  inherits `allowed_algs` for manually configured providers. Discovery
  negotiates this independently against UserInfo metadata. Use a single
  algorithm to enforce the client's registered UserInfo signing choice.
  An empty vector rejects all signed UserInfo algorithms.

- allowed_algs:

  Optional vector of allowed JWT algorithms for ID tokens. Use to
  restrict acceptable `alg` values on a per-provider basis. Supported
  asymmetric algorithms include `RS256`, `RS384`, `RS512`, `ES256`,
  `ES384`, `ES512`, and `EdDSA` with Ed25519 OKP keys (including
  `at_hash` validation). Ed448 verification is unsupported and fails
  closed. Symmetric HMAC algorithms `HS256`, `HS384`, `HS512` are also
  supported but require that you supply a `client_secret` and explicitly
  enable HMAC verification via the option
  `options(shinyOAuth.allow_hs = TRUE)`. Defaults to
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

- par_url:

  Optional Pushed Authorization Request (PAR) URL (RFC 9126). When set,
  shinyOAuth first sends the authorization request from server to
  provider and then redirects the browser with the returned
  `request_uri` handle instead of the full request payload. Use PAR to
  keep most request details out of the browser URL, submit large
  requests, or meet a provider's PAR requirement. The provider must
  support this endpoint.

- par_required:

  Logical. Whether the provider requires authorization requests to be
  sent via PAR. When `TRUE`, `par_url` must also be configured.

- signed_request_object_required:

  Logical. Whether the provider requires signed Request Objects for
  authorization requests. When `TRUE`, clients should use
  `request_object_mode = "request"` or
  `request_object_mode = "request_uri"`. This setting enforces local
  construction only; it does not configure the authorization server.
  Register `require_signed_request_object = true` (or the server's
  equivalent) and verify unsigned requests are rejected before relying
  on downgrade-resistant request integrity.

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

- request_uri_registration_required:

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

- request_object_signing_alg_values_supported:

  Optional vector of JWS algorithms that the provider advertises for
  signed Request Objects (RFC 9101). This is mainly used for early
  validation when an
  [OAuthClient](https://lukakoning.github.io/shinyOAuth/reference/OAuthClient.md)
  sends `request_object_mode = "request"` or
  `request_object_mode = "request_uri"`.

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

- authorization_request_front_channel_mode:

  Character scalar controlling which browser-visible outer parameters
  shinyOAuth keeps when the actual authorization request is carried by
  JAR or PAR. Use `"compat"` (default) to keep OIDC-compatible
  parameters with outer `client_id`, `response_type`, and `scope` when
  an issuer is configured. Use `"minimal"` for plain OAuth browser
  redirects and for PAR deployments whose authorization endpoint accepts
  only `client_id` plus the provider-issued `request_uri` handle. OpenID
  Connect by-value `request` and caller-managed `request_uri` transports
  reject `"minimal"` because OIDC still requires outer `response_type`
  and an outer `scope` containing `openid`.

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
  response modes that shinyOAuth does not implement; clients still fail
  fast if they request one of those unsupported modes.

- jarm_signing_alg_values_supported:

  Optional vector of JWS algorithms that the provider advertises for
  signed JWT Secured Authorization Responses (JARM).

- jarm_encryption_alg_values_supported:

  Optional vector of JWE key-management algorithms that the provider
  advertises for encrypted JARM responses.

- jarm_encryption_enc_values_supported:

  Optional vector of JWE content-encryption algorithms that the provider
  advertises for encrypted JARM responses.

- jarm_tolerate_duplicate_top_level_iss:

  Logical. Whether shinyOAuth should tolerate repeated identical
  top-level `iss` members in signed JARM payloads for this provider.
  This is an interoperability escape hatch for providers that emit
  duplicate identical top-level `iss` claims. When `TRUE`, shinyOAuth
  collapses repeated identical top-level `iss` members before
  duplicate-member rejection. Conflicting duplicates and nested
  duplicate `iss` members still fail closed. Defaults to `FALSE`.

- token_endpoint_auth_signing_alg_values_supported:

  Optional vector of JWS algorithms that the provider advertises for
  JWT-based client authentication (`client_secret_jwt` /
  `private_key_jwt`) at the token endpoint. This metadata is used for
  early validation of `OAuthClient@client_assertion_alg` and inferred
  JWT client-assertion defaults.

- endpoint_auth_metadata:

  Named list of independent `introspection` and `revocation`
  authentication metadata. Each entry has `methods` and `signing_algs`
  character vectors (or `NULL` for omitted metadata). Discovery retains
  these fields and applies the RFC 8414 Basic-auth default for omitted
  revocation methods. Omitted introspection methods have no default.

- dpop_signing_alg_values_supported:

  Optional vector of JWS algorithms that the provider advertises for
  DPoP proof JWTs (RFC 9449). This metadata is used for early validation
  of `OAuthClient@dpop_signing_alg` and inferred outbound DPoP signing
  defaults.

- mtls_endpoint_aliases:

  Optional named list of RFC 8705 mTLS endpoint aliases. Names should
  follow the metadata keys such as `token_endpoint`,
  `userinfo_endpoint`, `introspection_endpoint`, `revocation_endpoint`,
  `par_endpoint`, or `pushed_authorization_request_endpoint`, and values
  must be absolute URLs. This is an advanced setting used when a
  provider publishes separate mTLS-specific endpoints.

- mtls_client_certificate_bound_access_tokens:

  Logical. Whether the authorization server advertises RFC 8705
  capability to issue certificate-bound access tokens. This describes
  server capability; the client still has to opt into mTLS separately.
  When `TRUE`, token responses may include a `cnf` claim with an
  `x5t#S256` thumbprint that downstream requests must match with the
  same certificate.

## Details

Endpoint URLs identify the provider's authorization, token, and profile
services. Provider helpers fill in these URLs and suitable defaults. A
separate
[`oauth_client()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_client.md)
holds your app's credentials and requested permissions. See the [usage
vignette](https://lukakoning.github.io/shinyOAuth/articles/usage.html)
for the complete setup.

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
