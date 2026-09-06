# OAuthClient S7 class

An `OAuthClient` holds your app's registration with a provider: its
client ID, credentials, return address, and requested permissions. It
also holds the pending login state and client-specific token validation
settings used by the Shiny module and token helpers. Create it with
[`oauth_client()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_client.md),
which resolves defaults from the provider and the supplied client
settings.

## Usage

``` r
OAuthClient(
  provider = NULL,
  client_id = character(0),
  client_secret = character(0),
  endpoint_auth = list(),
  redirect_uri = character(0),
  scopes = character(0),
  response_mode = NA_character_,
  resource = character(0),
  claims = NULL,
  enforce_callback_issuer = FALSE,
  authorization_server_mode = "single",
  authorization_server_redirect_uris = character(0),
  scope_validation = "warn",
  claims_validation = "none",
  required_acr_values = character(0),
  userinfo_jwt_required_time_claims = character(0),
  introspect = FALSE,
  introspect_elements = character(0),
  state_store = cachem::cache_mem(max_age = 300),
  state_payload_max_age = 300,
  state_entropy = 64,
  state_key = random_urlsafe(n = 128),
  client_assertion_private_key = NULL,
  client_assertion_private_key_kid = NA_character_,
  client_assertion_alg = NA_character_,
  client_assertion_audience = NA_character_,
  mtls_client_cert_file = NA_character_,
  mtls_client_key_file = NA_character_,
  mtls_client_key_password = NA_character_,
  mtls_client_ca_file = NA_character_,
  mtls_certificate_bound_access_tokens = FALSE,
  dpop_private_key = NULL,
  dpop_private_key_kid = NA_character_,
  dpop_signing_alg = NA_character_,
  dpop_require_access_token = !is.null(dpop_private_key),
  dpop_require_observed_cnf = FALSE,
  request_object_mode = "parameters",
  request_object_signing_alg = NA_character_,
  request_object_audience = NA_character_,
  request_object_encryption_alg = NA_character_,
  request_object_encryption_enc = NA_character_,
  request_object_encryption_kid = NA_character_,
  request_object_ttl = 45,
  request_object_nbf_skew = NA_real_,
  jarm_signed_response_alg = NA_character_,
  jarm_encrypted_response_alg = NA_character_,
  jarm_encrypted_response_enc = NA_character_,
  jarm_decryption_private_key = NULL,
  jarm_decryption_private_key_kid = NA_character_,
  jarm_max_lifetime = 600,
  mtls_require_observed_cnf = TRUE
)
```

## Arguments

- provider:

  The service configuration, created with a provider helper such as
  [`oauth_provider_google()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_provider_google.md)
  or
  [`oauth_provider_oidc_discover()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_provider_oidc_discover.md).

- client_id:

  The identifier assigned when you register your app with the provider.

- client_secret:

  The secret issued for your app, preferably read with
  [`Sys.getenv()`](https://rdrr.io/r/base/Sys.getenv.html). Omit it for
  registrations that do not use a secret.

  It is required for `token_auth_style = "header"`. With `"body"` and
  PKCE, an empty secret is omitted. With `"public"` (alias `"none"`), it
  is never sent for client authentication. HMAC-signed ID token
  validation still requires a non-empty secret, regardless of the client
  authentication method.

- endpoint_auth:

  Named list of authentication overrides for `par`, `introspection`, and
  `revocation`. Token exchange and refresh use the top-level
  client/provider authentication settings. Each entry may supply
  `token_auth_style`, `client_secret`, `client_assertion_private_key`,
  `client_assertion_private_key_kid`, `client_assertion_alg`,
  `client_assertion_audience`, `extra_headers` (named character vector),
  and the `mtls_client_*` certificate/key/CA fields. Introspection and
  revocation may also use a separate `client_id`. Unspecified
  credentials inherit the client's settings. Discovered endpoint methods
  and signing algorithms are checked independently. PAR inherits token
  authentication. Extra token headers apply only to token exchange and
  refresh; set `extra_headers` explicitly for every other endpoint that
  needs them.

- redirect_uri:

  The URL where users return after login. It must match the callback URL
  registered with your provider, including scheme, host, port, and path.
  Use HTTPS in production.

- scopes:

  Character vector of permissions to request. The provider defines the
  available names. For OIDC (`issuer` set and
  `issuer_thus_oidc = TRUE`), shinyOAuth adds `"openid"` automatically
  if absent. The resulting set is used in the request and subsequent
  scope checks.

- response_mode:

  How the provider returns the login result. Leave `NULL` (default) for
  a normal callback with parameters in the URL; no `response_mode`
  parameter is then sent. Use `"query"` to request that format
  explicitly, or `"form_post"` when your provider needs an HTTP POST.
  POST callbacks require
  [`oauth_form_post_ui()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_form_post_ui.md).

  Signed responses (JWT Secured Authorization Response Mode, JARM) use
  `"jwt"`, `"query.jwt"`, or `"form_post.jwt"` and require
  [`oauth_module_server()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_module_server.md).
  `"jwt"` uses the query transport for this authorization-code flow.
  `"form_post.jwt"` also needs
  [`oauth_form_post_ui()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_form_post_ui.md).
  [`handle_callback()`](https://lukakoning.github.io/shinyOAuth/reference/handle_callback.md)
  does not handle JARM. Requested modes must be in
  `response_modes_supported` when advertised; fragment modes are not
  supported.

- resource:

  Optional RFC 8707 resource indicator(s). Supply a character vector of
  absolute URIs to request audience-restricted tokens for one or more
  protected resources. Each value is sent as a repeated `resource`
  parameter on the authorization request, initial token exchange, and
  token refresh requests. Default is `character(0)`.

- claims:

  Optional request for specific OIDC user information, beyond scopes.
  Default `NULL` sends no request. Supply a list with `userinfo` and/or
  `id_token` members, for example
  `list(userinfo = list(email = list(essential = TRUE)))`. Use
  `claims_validation = "strict"` if an unmet request must stop login.

  Lists are JSON-encoded with `auto_unbox = TRUE`. Use `NULL` for an
  unconstrained claim, `value` for one required value, or `values` for a
  set. Wrap a single-element `values` vector in
  [`I()`](https://rdrr.io/r/base/AsIs.html) to keep it a JSON array, for
  example `list(values = I("example-acr"))`. A pre-encoded JSON string
  is also accepted. Your provider must support the OIDC claims
  parameter.

- enforce_callback_issuer:

  Logical or `NULL`. When `TRUE`, enforce that authorization responses
  handled through this client include an RFC 9207 `iss` parameter and
  reject callbacks unless it exactly matches `provider@issuer`. This is
  recommended when one callback URL can receive responses from more than
  one authorization server. Requires the provider to have a configured
  `issuer`.

  When `NULL` (the
  [`oauth_client()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_client.md)
  helper default), shinyOAuth auto-enables this check for providers that
  advertise `authorization_response_iss_parameter_supported = TRUE` and
  have a configured `issuer`, such as OIDC discovery providers that
  expose RFC 9207 support. Set `FALSE` to opt out explicitly.

- authorization_server_mode:

  Declares whether this client is part of an application that can
  interact with more than one authorization server, and which RFC 9700
  mix-up defense it uses. One of:

  - `"single"` (default): the application uses only one authorization
    server, so RFC 9700 does not require a mix-up defense.

  - `"multi_issuer"`: authorization responses identify their issuer.
    JARM response modes satisfy this requirement through their validated
    `iss` claim. Direct response modes require the provider to advertise
    `authorization_response_iss_parameter_supported = TRUE`; shinyOAuth
    then requires and validates the RFC 9207 `iss` response parameter.
    Missing support metadata is treated as absence of this defense.

  - `"multi_redirect_uri"`: each authorization server uses a distinct
    redirect URI. Supply the complete set through
    `authorization_server_redirect_uris`. This mode is supported by
    [`oauth_module_server()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_module_server.md),
    which compares the browser-visible canonical scheme, authority, and
    path before parsing callback values.

- authorization_server_redirect_uris:

  Complete character vector of redirect URIs used by the application for
  its authorization servers when
  `authorization_server_mode = "multi_redirect_uri"`. It must contain at
  least two canonically distinct scheme/authority/path routes and
  include this client's `redirect_uri`. Query and fragment components do
  not make routes distinct.

- scope_validation:

  Controls how scope discrepancies are handled when the authorization
  server grants fewer scopes than requested. RFC 6749 Section 3.3
  permits servers to issue tokens with reduced scope, and Section 5.1
  allows token responses to omit `scope` when it is unchanged from the
  requested scope.

  - `"warn"` (default): Emits a warning but continues authentication if
    scopes are missing.

  - `"strict"`: Throws an error if any requested scope is missing from
    the granted scopes. Omitted `scope` is treated as unchanged, not as
    an error.

  - `"none"`: Skips scope validation entirely.

- claims_validation:

  What to do if requested claims are missing or have unexpected values:
  `"warn"` continues with a warning, `"strict"` stops login, and
  `"none"` skips the check. When omitted,
  [`oauth_client()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_client.md)
  uses `"warn"` if `claims` includes `essential = TRUE`, `value`, or
  `values` requirements, and `"none"` otherwise. Checks on
  `claims$id_token` require ID token validation
  (`id_token_validation = TRUE` or `use_nonce = TRUE`).

- required_acr_values:

  Optional character vector of acceptable login requirements, such as a
  provider's multi-factor authentication (MFA) policy. Use the
  provider's Authentication Context Class Reference (ACR) identifiers.
  The validated ID token must contain a matching `acr` or login fails.
  The request also sends `acr_values` as a hint to the provider.
  Requires `id_token_validation = TRUE` and an `issuer`. Default
  `character(0)` imposes no requirement.

- userinfo_jwt_required_time_claims:

  Optional character vector of temporal JWT claims that must be present
  when the UserInfo response is a signed JWT (`application/jwt`).
  Allowed values are `"exp"`, `"iat"`, and `"nbf"`.

  Default is `character(0)`, which means these claims are validated only
  when present. Set, for example,
  `userinfo_jwt_required_time_claims = "exp"` to require an expiry on
  signed UserInfo JWTs, or pass multiple values to require additional
  temporal claims. For security-sensitive deployments that accept signed
  UserInfo JWTs, prefer requiring at least `"exp"`.

- introspect:

  If `TRUE`, ask the provider to confirm the access token is active
  before completing login and module refreshes. Requires
  `introspection_url`; an unsuccessful check or a response other than
  `active = TRUE` stops the operation. Default `FALSE`.

- introspect_elements:

  Optional character vector of additional requirements to enforce on the
  introspection response when `introspect = TRUE`. Supported values:

  - `"sub"`: require the introspected `sub` to match the session subject
    (from a validated ID token `sub` when available, else from userinfo
    `sub`).

  - `"client_id"`: require the introspected `client_id` to match your
    OAuth client id.

  - `"scope"`: validate introspected `scope` against requested scopes
    (respects the client's `scope_validation` mode).

  - `"token_type"`: require introspection to return `token_type`. This
    is useful for sender-constrained deployments such as DPoP, where
    introspection can authoritatively report `token_type = "DPoP"`.
    Default is `character(0)`. (Note that not all providers may return
    each of these fields in introspection responses.)

- state_store:

  Storage for pending logins. The default
  `cachem::cache_mem(max_age = 300)` is suitable for one R process. For
  multiple app processes, supply a shared
  [`custom_cache()`](https://lukakoning.github.io/shinyOAuth/reference/custom_cache.md)
  with atomic `$take()` and use the same `state_key` on every process.
  Plain
  [`cachem::cache_disk()`](https://cachem.r-lib.org/reference/cache_disk.html)
  is unsafe for shared login state because its separate read and delete
  operations do not prevent simultaneous reuse. See
  [`custom_cache()`](https://lukakoning.github.io/shinyOAuth/reference/custom_cache.md)
  for method and stored-value requirements.

- state_payload_max_age:

  Maximum age of a pending login's encrypted state, in seconds.
  Default 300. This is checked separately from the state store's entry
  lifetime; both must allow the returning login.

- state_entropy:

  Length in characters of the random state identifier, from 22 to 128.
  Default 64. Most apps should keep the default.

- state_key:

  Secret used to encrypt and protect pending login details. A random key
  is generated when omitted. This is separate from `client_secret` and
  is also used for public clients.

  For multiple R processes, supply the same key and shared `state_store`
  on every process. Accepts a character string or raw vector of at least
  32 bytes. Generate it from cryptographically random bytes; do not use
  a memorable password. State uses AES-GCM authenticated encryption.

- client_assertion_private_key:

  Optional private key for `private_key_jwt` client authentication at
  the token endpoint. Can be an `openssl::key` or a PEM string
  containing a private key. Required when the provider's
  `token_auth_style = 'private_key_jwt'`. Also used to sign JAR Request
  Objects, regardless of the token auth style. Current outbound
  private-key JWT signing supports RSA and EC private keys. For RSA
  keys, outbound signing is currently limited to `RS256`; `RS384`,
  `RS512`, and RSA-PSS (`PS256`, `PS384`, `PS512`) are not supported.
  Ed25519/Ed448 keys are also not currently supported.

- client_assertion_private_key_kid:

  Optional key identifier (kid) to include in the JWT header for
  `private_key_jwt` assertions and JAR Request Objects. Useful when the
  authorization server uses kid to select the correct verification key.

- client_assertion_alg:

  Optional JWT signing algorithm to use for client assertions. When
  omitted, defaults to `HS256` for `client_secret_jwt`. For
  `private_key_jwt`, a compatible default is selected based on the
  private key type/curve (e.g., `RS256` for RSA or
  `ES256`/`ES384`/`ES512` for EC P-256/384/521). If an explicit value is
  provided but incompatible with the key, validation fails early with a
  configuration error. When the provider advertises
  `token_endpoint_auth_signing_alg_values_supported`, both explicit
  values and inferred defaults must be included in that set. Supported
  values are `HS256`, `HS384`, `HS512` for client_secret_jwt and
  asymmetric algorithms supported for outbound signing (`RS256`,
  `ES256`, `ES384`, `ES512`) for private keys. `RS384`, `RS512`,
  `PS256`, `PS384`, `PS512`, and `EdDSA` are not currently supported for
  outbound client assertions.

- client_assertion_audience:

  Optional override for the `aud` claim used when building JWT client
  assertions (`client_secret_jwt` / `private_key_jwt`). By default,
  shinyOAuth uses the active token, introspection, or revocation request
  URL. PAR uses the issuer when configured, otherwise the canonical PAR
  URL, including when the request uses an mTLS alias. Set an explicit
  value when required by the provider's registration agreement.

- mtls_client_cert_file:

  Optional path to the PEM-encoded client certificate (or certificate
  chain) used for RFC 8705 mutual TLS (mTLS) client authentication and
  certificate-bound protected-resource requests. Required when
  `provider@token_auth_style` is `"tls_client_auth"` or
  `"self_signed_tls_client_auth"`.

- mtls_client_key_file:

  Optional path to the PEM-encoded private key used with
  `mtls_client_cert_file`. Must be supplied together with
  `mtls_client_cert_file`, and is required for RFC 8705 mTLS client
  authentication.

- mtls_client_key_password:

  Optional password used to decrypt an encrypted PEM private key
  referenced by `mtls_client_key_file`.

- mtls_client_ca_file:

  Optional path to a PEM CA bundle used to validate the remote HTTPS
  server certificate when making mTLS requests. This is mainly useful
  for local or test environments that use self-signed server
  certificates.

- mtls_certificate_bound_access_tokens:

  Logical. Whether this client intends to request RFC 8705
  certificate-bound access tokens when the provider advertises that
  capability. Default is `FALSE`.

  Set this to `TRUE` for clients that should prefer discovered
  `mtls_endpoint_aliases` on authorization-server requests even when
  `token_auth_style` itself is not an mTLS auth style, and present the
  certificate on token and protected-resource requests. Certificate/key
  configuration alone does not enable this mode.

  Requires `mtls_client_cert_file` and `mtls_client_key_file`, and the
  provider must be configured with
  `mtls_client_certificate_bound_access_tokens = TRUE`. By default,
  `mtls_require_observed_cnf = TRUE` also requires locally observable
  confirmation of the certificate binding. For opaque tokens whose
  binding is enforced only by the servers, keep
  `mtls_certificate_bound_access_tokens = TRUE` and set
  `mtls_require_observed_cnf = FALSE`.

- dpop_private_key:

  Private key for tying tokens to this app's requests using
  Demonstrating Proof of Possession (DPoP). Only needed when your
  provider/API supports DPoP. Accepts an `openssl::key` or PEM
  private-key string, using RSA or EC.
  [`oauth_client()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_client.md)
  then defaults `dpop_require_access_token` to `TRUE`. Supported signing
  algorithms are `RS256`, `ES256`, `ES384`, and `ES512`; RSA-PSS, other
  RSA signing algorithms, and EdDSA are not supported for outgoing
  proofs. See `dpop_signing_alg` and the [advanced security
  vignette](https://lukakoning.github.io/shinyOAuth/articles/advanced-security.html).

- dpop_private_key_kid:

  Optional key identifier (`kid`) to include in the JOSE header of DPoP
  proofs. Useful when the authorization or resource server expects a
  stable key identifier alongside the embedded public JWK.

- dpop_signing_alg:

  Optional JWT signing algorithm to use for DPoP proofs. When omitted, a
  compatible asymmetric default is selected based on the private key
  type/curve (for example `RS256`, `ES256`, `ES384`, or `ES512`).
  `RS384`, `RS512`, `PS256`, `PS384`, `PS512`, and `EdDSA` are not
  currently supported for outbound DPoP proofs. If an explicit value is
  provided but incompatible with the key, validation fails early with a
  configuration error. When the provider advertises
  `dpop_signing_alg_values_supported`, both explicit values and inferred
  defaults must be included in that set.

- dpop_require_access_token:

  Logical or `NULL`. When `TRUE` and `dpop_private_key` is configured,
  shinyOAuth requires the authorization server to return
  `token_type = "DPoP"` for access tokens and fails fast otherwise. When
  shinyOAuth can observe token binding data from a JWT access token or
  an introspection response, this strict mode also requires `cnf$jkt` to
  be present and match the configured `dpop_private_key`. Opaque access
  tokens that expose no `cnf` data still pass this check unless
  introspection later reveals the binding. In
  [`oauth_client()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_client.md),
  the default `NULL` resolves to `TRUE` when `dpop_private_key` is
  configured and to `FALSE` otherwise. Set `FALSE` explicitly only when
  you intentionally want to allow Bearer access tokens, such as
  deployments where DPoP is used only to bind refresh tokens.

- dpop_require_observed_cnf:

  Logical. When `TRUE`, shinyOAuth rejects `token_type = "DPoP"` access
  tokens unless it can observe `cnf$jkt` locally, either from the access
  token itself or from a token introspection response. Use this when
  high-assurance DPoP deployments must fail closed on opaque access
  tokens that provide no observable binding. Default is `FALSE`.

- request_object_mode:

  Controls how the authorization request is transported to the provider.

  - `"parameters"` (default): send OAuth parameters directly on the
    browser redirect URL.

  - `"request"`: send a signed JWT-secured authorization request (JAR;
    RFC 9101) via the `request` parameter.

  - `"request_uri"`: publish a signed Request Object by reference and
    send its URL via the `request_uri` parameter.

  If the provider has a `par_url`, `"parameters"` and `"request"` are
  sent to that endpoint first using Pushed Authorization Requests (PAR).
  The browser then receives the provider-issued `request_uri` handle.
  Caller-published `"request_uri"` mode is separate from PAR and cannot
  be used when the provider requires PAR.

  Use a signed Request Object when the provider requires JAR or when it
  must verify the integrity of the authorization parameters.
  `"request_uri"` lets the provider fetch the object from a published
  URL instead of carrying the JWT in the browser redirect. Both modes
  require signing material on the client. shinyOAuth prefers
  `client_assertion_private_key` when present; otherwise it falls back
  to HMAC signing with `client_secret`. When Request Object encryption
  is configured, shinyOAuth signs first and then wraps the signed
  Request Object in a JWE. Caller-managed `request_uri` publication
  requires HTTPS; HTTP URLs are rejected even when another configured
  host policy would otherwise allow them, as required by RFC 9101
  Section 5.2. If the provider advertises
  `request_uri_registration_required = TRUE`, caller-managed
  `request_uri` publication still depends on the provider having that
  URI or a matching wildcard prefix registered for the client;
  shinyOAuth cannot verify that server-side registration automatically.

- request_object_signing_alg:

  Optional JWS algorithm override for signed authorization requests when
  `request_object_mode` uses a Request Object (`"request"` or
  `"request_uri"`). When omitted, shinyOAuth chooses `HS256` for
  HMAC-based signing or a compatible asymmetric default based on
  `client_assertion_private_key` (for example `RS256`, `ES256`, `ES384`,
  or `ES512`). `RS384`, `RS512`, `PS256`, `PS384`, `PS512`, and `EdDSA`
  are not currently supported for outbound signed authorization
  requests.

- request_object_audience:

  Optional override for the `aud` claim used in signed authorization
  requests. By default, shinyOAuth uses the provider issuer when
  available. When `request_object_mode = "request"` or `"request_uri"`,
  the provider must have a configured issuer or you must supply an
  explicit override so the signed Request Object remains audience-bound
  to the intended authorization server.

- request_object_encryption_alg:

  Optional JWE key-management algorithm override for encrypted Request
  Objects. Current outbound support is limited to `RSA-OAEP`. When set,
  you must also set `request_object_encryption_enc`.

- request_object_encryption_enc:

  Optional JWE content-encryption algorithm override for encrypted
  Request Objects. Current outbound support is limited to the
  AES-CBC-HMAC family (`A128CBC-HS256`, `A192CBC-HS384`,
  `A256CBC-HS512`). When set, you must also set
  `request_object_encryption_alg`.

- request_object_encryption_kid:

  Optional key identifier (`kid`) used to select one provider encryption
  key and emit the outer JWE `kid` header. This is mainly useful when
  the provider publishes more than one Request Object encryption key.

- request_object_ttl:

  Positive number of seconds to keep signed authorization request
  objects (`request` JWTs) valid. When
  `request_object_mode = "request_uri"`, shinyOAuth also uses this value
  as the default publication window for the referenced Request Object
  URI. Default is `45`.

- request_object_nbf_skew:

  Optional non-negative number of seconds. When provided, shinyOAuth
  adds an `nbf` claim set to `iat - request_object_nbf_skew` so
  deployments can tolerate small clock skew while still emitting bounded
  request-object validity windows. Leave `NULL` (the default) to omit
  `nbf`. Request-object `nbf` is reserved by shinyOAuth and cannot be
  supplied through extra authorization parameters.

- jarm_signed_response_alg:

  Optional expected JWS algorithm for signed JWT Secured Authorization
  Responses (JARM). When omitted and the effective response mode is
  JARM, shinyOAuth defaults to `RS256`. This value is not sent
  dynamically on the authorization request; it must match the client
  metadata and provider behavior configured out-of-band for that client.
  Current inbound support accepts `HS256`, `HS384`, `HS512`, `RS256`,
  `RS384`, `RS512`, `ES256`, `ES384`, `ES512`, and `EdDSA`. RSA-PSS
  (`PS256`, `PS384`, `PS512`) and unsecured `none` are not accepted for
  inbound JARM.

- jarm_encrypted_response_alg:

  Optional expected JWE key-management algorithm for encrypted JARM
  responses. Current inbound support is limited to `RSA-OAEP`. Like
  `jarm_signed_response_alg`, this reflects out-of-band client metadata
  and expected provider behavior rather than an authorization request
  parameter emitted by shinyOAuth.

- jarm_encrypted_response_enc:

  Optional expected JWE content-encryption algorithm for encrypted JARM
  responses. Current inbound support is limited to the AES-CBC-HMAC
  family (`A128CBC-HS256`, `A192CBC-HS384`, `A256CBC-HS512`). When
  omitted while `jarm_encrypted_response_alg` is set, shinyOAuth
  defaults to `A128CBC-HS256`. This must also match the provider-side
  JARM client metadata when encrypted responses are enabled.

- jarm_decryption_private_key:

  Optional private key used to decrypt encrypted JARM responses. Can be
  an `openssl::key` or a PEM string containing a private key. Required
  when encrypted JARM is enabled.

- jarm_decryption_private_key_kid:

  Optional key identifier (`kid`) associated with
  `jarm_decryption_private_key`.

- jarm_max_lifetime:

  Positive number of seconds. Maximum accepted lifetime for a JARM
  response JWT. Default is 600 seconds, matching JARM's recommended
  10-minute upper bound for authorization response JWTs. When a JARM
  payload includes `iat`, shinyOAuth enforces
  `exp - iat <= jarm_max_lifetime`; otherwise it falls back to the
  remaining `exp` window at validation time. Applies only when
  `response_mode` uses JARM.

- mtls_require_observed_cnf:

  Logical, default `TRUE`. When
  `mtls_certificate_bound_access_tokens = TRUE`, require `cnf$x5t#S256`
  in the token response, JWT access token, or introspection and verify
  that it matches the configured certificate. The default preserves
  strict local assurance. Set `FALSE` for server-enforced opaque
  bindings that the client cannot observe; this does not disable
  certificate presentation or mTLS endpoint selection. Missing
  confirmation is then allowed, but any observed confirmation is still
  validated, including mismatches and conflicting claims. This flag does
  not independently enable mTLS.

## Details

Configure the app registration with `provider`, `client_id`,
`client_secret` (if issued), `redirect_uri`, and `scopes`. Create the
client outside your Shiny `server()` function, then pass it to
[`oauth_module_server()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_module_server.md).

Use the state-store settings for deployments where callbacks can reach
different R processes, and the validation settings to enforce required
scopes, claims, or authentication context. Certificate (mTLS),
key-binding (DPoP), and signed-request/response (JAR/JARM) settings
enable those protocol features when supported by your provider and
required by your deployment. See the [advanced security
vignette](https://lukakoning.github.io/shinyOAuth/articles/advanced-security.html)
for examples. The defaults described below refer to
[`oauth_client()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_client.md)
unless stated otherwise.

## Examples

``` r
# Register an app with GitHub and store its credentials in your environment.
# This creates the configuration; it does not start login or contact GitHub.
client <- oauth_client(
  provider = oauth_provider_github(),
  client_id = "your-client-id",
  client_secret = "your-client-secret",
  redirect_uri = "http://127.0.0.1:8100",
  scopes = c("read:user", "user:email")
)

# In a real app, read credentials with Sys.getenv() and create client
# outside server(). Inside server(), start login with:
# auth <- oauth_module_server("auth", client)
```
