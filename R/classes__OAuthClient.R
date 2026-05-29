# This file defines the OAuthClient object used across the login flow
# Used for keeping provider settings, client credentials, request options, and
# state-handling rules in one validated object

# 1 OAuth client class ---------------------------------------------------------

## 1.1 Class definition --------------------------------------------------------

#' OAuthClient S7 class
#'
#' @description
#' S7 class describing an OAuth 2.0 client configuration. It combines the
#' provider, client credentials, redirect URI, requested scopes, and the state
#' handling rules used during login and callback validation.
#'
#' This is a low-level constructor intended for advanced use. Most users should
#' prefer the helper constructor [oauth_client()].
#'
#' @param provider [OAuthProvider] object
#'
#' @param client_id OAuth client ID
#' @param client_secret OAuth client secret.
#'
#'   Validation rules:
#'   - Required (non-empty) when the provider authenticates the client with
#'     HTTP Basic auth at the token endpoint (`token_auth_style = "header"`,
#'     also known as `client_secret_basic`).
#'   - Optional when the provider uses form-body client authentication at the
#'     token endpoint (`token_auth_style = "body"`, also known as
#'     `client_secret_post`) and `use_pkce = TRUE`. In that configuration,
#'     the secret is omitted only when it is empty.
#'   - Ignored for token-endpoint authentication when the provider uses
#'     `token_auth_style = "public"` (or the alias `"none"`). Public auth
#'     sends `client_id` only and never sends `client_secret`, even if one is
#'     configured explicitly.
#'
#'   Note: If your provider issues HS256 ID tokens and `id_token_validation` is
#'   enabled, a non-empty `client_secret` is required for signature validation.
#'
#' @param redirect_uri Redirect URI registered with provider
#' @param scopes Vector of scopes to request. For OIDC providers (those with an
#'   `issuer`), shinyOAuth automatically prepends `openid` when it is missing;
#'   that effective scope set is what gets sent in the authorization request
#'   and used for later state and token-scope validation.
#'
#' @param response_mode Authorization response mode for authorization-code
#'   callbacks. Supported values are `"query"`, `"form_post"`, `"jwt"`,
#'   `"query.jwt"`, and `"form_post.jwt"`. The effective default is always
#'   `"query"`: omitting this argument keeps the normal query-parameter
#'   callback flow and shinyOAuth does not send a `response_mode` parameter.
#'   Pass `"query"` only if you need to explicitly request the query
#'   response mode from the provider. Set `"form_post"` only when the
#'   provider requires or explicitly recommends POSTing the authorization
#'   response to the redirect URI. Shiny apps using `"form_post"` must wrap
#'   their UI with [oauth_form_post_ui()]. Prefer this argument over setting
#'   `extra_auth_params$response_mode` on the provider. When the provider
#'   advertises `response_modes_supported`, the resolved mode must be included
#'   in that set. `"jwt"` requests the JARM-defined default callback
#'   transport for the response type; for the authorization-code flow that
#'   still means a query callback, but shinyOAuth preserves and sends `"jwt"`
#'   when you configure it explicitly. `"fragment.jwt"` is not currently
#'   supported because shinyOAuth does not implement fragment callback
#'   transport.
#'
#'   JARM callbacks are currently module-only. For `"jwt"`, `"query.jwt"`,
#'   and `"form_post.jwt"`, use [oauth_module_server()] and, for
#'   `"form_post.jwt"`, wrap the app UI with [oauth_form_post_ui()]. The
#'   exported [handle_callback()] helper still accepts only the classic
#'   direct `code` + sealed `state` callback shape and does not expose a
#'   public JARM validation/resume API.
#'
#' @param resource Optional RFC 8707 resource indicator(s). Supply a character
#'   vector of absolute URIs to request audience-restricted tokens for one or
#'   more protected resources. Each value is sent as a repeated `resource`
#'   parameter on the authorization request, initial token exchange, and token
#'   refresh requests. Default is `character(0)`.
#'
#' @param claims OIDC claims request parameter (OIDC Core §5.5). Allows
#'   requesting specific claims from the UserInfo Endpoint and/or in the ID
#'   Token. Can be:
#'   - `NULL` (default): no claims parameter is sent
#'   - A list: automatically JSON-encoded (via [jsonlite::toJSON()] with
#'     `auto_unbox = TRUE`) and URL-encoded into the authorization request.
#'     The list should have top-level members `userinfo` and/or `id_token`,
#'     each containing named lists of claims.
#'     Use `NULL` to request a claim without parameters (per spec).
#'     Example: `list(userinfo = list(email = NULL, given_name = list(essential = TRUE)), id_token = list(auth_time = list(essential = TRUE)))`
#'
#'     Note on single-element arrays: because `auto_unbox = TRUE` is used,
#'     single-element R vectors are serialized as JSON scalars, not arrays.
#'     The OIDC spec defines `values` as an array. To force array encoding
#'     for a single-element vector, wrap it in [I()], e.g.,
#'     `acr = list(values = I("urn:mace:incommon:iap:silver"))` produces
#'     `{"values":["urn:mace:incommon:iap:silver"]}`. Multi-element vectors
#'     are always encoded as arrays. shinyOAuth warns when it sees a
#'     single-element `values` entry that is not wrapped in [I()], because
#'     that common input pattern serializes incorrectly for OIDC.
#'   - A character string: pre-encoded JSON string (advanced use). Must
#'     be valid JSON. Use this when you need full control over JSON encoding.
#'   Note: The `claims` parameter is OPTIONAL per OIDC Core §5.5. Not all
#'   providers support it; consult your provider's documentation.
#'
#' @param enforce_callback_issuer Logical or `NULL`. When `TRUE`, enforce that
#'   authorization responses handled through this client include an RFC 9207
#'   `iss` parameter and reject callbacks unless it exactly matches
#'   `provider@issuer`. This is recommended when one callback URL can receive
#'   responses from more than one authorization server. Requires the provider
#'   to have a configured `issuer`.
#'
#'   When `NULL` (the [oauth_client()] helper default), shinyOAuth
#'   auto-enables this check for providers that advertise
#'   `authorization_response_iss_parameter_supported = TRUE` and have a
#'   configured `issuer`, such as OIDC discovery providers that expose RFC 9207
#'   support. Set `FALSE` to opt out explicitly.
#'
#' @param scope_validation Controls how scope discrepancies are handled when
#'   the authorization server grants fewer scopes than requested. RFC 6749
#'   Section 3.3 permits servers to issue tokens with reduced scope, and
#'   Section 5.1 allows token responses to omit `scope` when it is unchanged
#'   from the requested scope.
#'
#'   - `"warn"` (default): Emits a warning but continues authentication if
#'     scopes are missing.
#'   - `"strict"`: Throws an error if any requested scope is missing from the
#'     granted scopes. Omitted `scope` is treated as unchanged, not as an
#'     error.
#'   - `"none"`: Skips scope validation entirely.
#'
#' @param claims_validation Controls validation of requested claims supplied via
#'   the `claims` parameter (OIDC Core §5.5). When `claims` includes entries
#'   with `essential = TRUE` for `id_token` or `userinfo`, or explicit `value`
#'   / `values` constraints for individual claims, this setting determines what
#'   happens if the returned ID token or userinfo response does not satisfy
#'   those requests.
#'
#'   - `"none"`: Skips claims validation entirely. This remains the effective
#'     default when the supplied `claims` request has no enforceable
#'     `essential`, `value`, or `values` constraints, and when you explicitly
#'     set `claims_validation = "none"`.
#'   - `"warn"`: Emits a warning but continues authentication if requested
#'     essential claims are missing or requested claim values are not
#'     satisfied.
#'   - `"strict"`: Throws an error if any requested essential claims are
#'     missing or requested claim `value` / `values` constraints are not
#'     satisfied by the response.
#'
#'   If `claims_validation` is omitted and the supplied `claims` request does
#'   include enforceable `essential`, `value`, or `values` constraints,
#'   [oauth_client()] promotes the effective default to `"warn"` so those
#'   mismatches are surfaced by default.
#'
#'   Enforceable requests under `claims$id_token` require a validated ID token.
#'   Configure the provider with `id_token_validation = TRUE` or `use_nonce = TRUE`
#'   so shinyOAuth validates the ID token before checking those claims.
#'
#' @param required_acr_values Optional character vector of acceptable
#'   Authentication Context Class Reference values (OIDC Core §2, §3.1.2.1).
#'   When non-empty, the ID token returned by the provider must contain an
#'   `acr` claim whose value is one of the specified entries; otherwise the
#'   login fails with a `shinyOAuth_id_token_error`.
#'
#'   Additionally, when non-empty, the authorization request automatically
#'   includes an `acr_values` query parameter (space-separated) as a voluntary
#'   hint to the provider (OIDC Core §3.1.2.1).  Note that the provider is
#'   not required to honour this hint; the client-side validation is the
#'   authoritative enforcement.
#'
#'   Requires an OIDC-capable provider with `id_token_validation = TRUE` and
#'   an `issuer` configured.  Default is `character(0)` (no enforcement).
#'
#' @param userinfo_jwt_required_time_claims Optional character vector of
#'   temporal JWT claims that must be present when the UserInfo response is a
#'   signed JWT (`application/jwt`). Allowed values are `"exp"`, `"iat"`, and
#'   `"nbf"`.
#'
#'   Default is `character(0)`, which means these claims are validated only when
#'   present. Set, for example, `userinfo_jwt_required_time_claims = "exp"`
#'   to require an expiry on signed UserInfo JWTs, or pass multiple values to
#'   require additional temporal claims. For security-sensitive deployments that
#'   accept signed UserInfo JWTs, prefer requiring at least `"exp"`.
#'
#' @param introspect If TRUE, the login flow will call the provider's token
#'   introspection endpoint (RFC 7662) to validate the access token. The login
#'   is not considered complete unless introspection succeeds and returns
#'   `active = TRUE`; otherwise the login fails and `authenticated` remains
#'   FALSE. When [oauth_module_server()] later performs proactive refresh, it
#'   also forwards this setting so refreshed access tokens are introspected
#'   through the same client policy. Default is FALSE. Requires the provider to
#'   have an `introspection_url` configured.
#'
#' @param introspect_elements Optional character vector of additional
#'   requirements to enforce on the introspection response when
#'   `introspect = TRUE`. Supported values:
#'   - `"sub"`: require the introspected `sub` to match the session subject
#'     (from a validated ID token `sub` when available, else from userinfo
#'     `sub`).
#'   - `"client_id"`: require the introspected `client_id` to match your OAuth
#'     client id.
#'   - `"scope"`: validate introspected `scope` against requested scopes
#'     (respects the client's `scope_validation` mode).
#'   - `"token_type"`: require introspection to return `token_type`. This is
#'     useful for sender-constrained deployments such as DPoP, where
#'     introspection can authoritatively report `token_type = "DPoP"`.
#'   Default is `character(0)`.
#'   (Note that not all providers may return each of these fields in
#'   introspection responses.)
#'
#' @param state_store State storage backend. Defaults to `cachem::cache_mem(max_age = 300)`.
#'    Alternative backends should use [custom_cache()] with an atomic `$take()`
#'    method for replay-safe single-use state consumption. The backend
#'    must implement cachem-like methods `$get(key, missing)`, `$set(key, value)`,
#'    and `$remove(key)`; `$info()` is optional.
#'
#'    Stored values must round-trip `browser_token` as a non-empty string.
#'    `pkce_code_verifier` and `nonce` are required only when the provider
#'    enables PKCE or nonce validation; otherwise backends may keep those
#'    fields as `NULL` or omit them.
#'
#'    `cachem::cache_mem()` is a good default for a single Shiny process. For
#'    multi-process deployments, use [custom_cache()] with an atomic `$take()`
#'    backed by a shared store (for example Redis `GETDEL` or SQL
#'    `DELETE ... RETURNING`). Plain `cachem::cache_disk()` is **not safe** as
#'    a shared state store because its `$get()` + `$remove()` operations are not
#'    atomic.
#'
#'    The client automatically generates, persists (in `state_store`), and
#'    validates the OAuth `state` parameter (and OIDC `nonce` when applicable)
#'    during the authorization code flow.
#'
#' @param state_payload_max_age Positive number of seconds. Maximum allowed age
#'   for the decrypted state payload's `issued_at` timestamp during callback
#'   validation.
#'
#'   This is the freshness window for the sealed `state` payload itself. It is
#'   separate from the `state_store` TTL, which controls how long the one-time
#'   server-side state entry can exist.
#'
#'   Default is 300 seconds.
#'
#' @param state_entropy Integer. The length (in characters) of the randomly
#'   generated state parameter. Higher values provide more entropy and better
#'   security against CSRF attacks. Must be between 22 and 128 (to align with
#'   `validate_state()`'s default minimum which targets ~128 bits for base64url‑like
#'   strings). Default is 64.
#'
#' @param state_key Optional per-client secret used as the state sealing key
#'   for AES-GCM AEAD (authenticated encryption) of the state payload that
#'   travels via the `state` query parameter. This provides confidentiality
#'   and integrity (via authentication tag) for the embedded data used during
#'   callback verification. If you omit this argument, a random value is
#'   generated via `random_urlsafe(128)`. This key is distinct from the
#'   OAuth `client_secret` and may be used with public clients.
#'
#'   Type: character string (>= 32 bytes when encoded) or raw vector
#'   (>= 32 bytes). Raw keys enable direct use of high-entropy secrets from
#'   external stores. Both forms are normalized internally by cryptographic
#'   helpers.
#'
#'   Multi-process deployments: if your app runs with multiple R workers or
#'   behind a non-sticky load balancer, configure a shared `state_store` and
#'   the same `state_key` across all workers. Otherwise callbacks that land on
#'   a different worker will fail state validation.
#'
#' @param client_assertion_private_key Optional private key for `private_key_jwt` client authentication
#'   at the token endpoint. Can be an `openssl::key` or a PEM string containing a
#'   private key. Required when the provider's `token_auth_style = 'private_key_jwt'`.
#'   Ignored for other auth styles. Current outbound private-key JWT signing
#'   supports RSA and EC private keys. For RSA keys, outbound signing is currently
#'   limited to `RS256`; `RS384`, `RS512`, and RSA-PSS (`PS256`, `PS384`, `PS512`)
#'   are not supported. Ed25519/Ed448 keys are also not currently supported.
#'
#' @param client_assertion_private_key_kid Optional key identifier (kid) to include in the JWT header
#'   for `private_key_jwt` assertions. Useful when the authorization server uses kid to
#'   select the correct verification key.
#'
#' @param client_assertion_alg Optional JWT signing algorithm to use for client assertions.
#'   When omitted, defaults to `HS256` for `client_secret_jwt`. For `private_key_jwt`, a
#'   compatible default is selected based on the private key type/curve (e.g., `RS256` for RSA
#'   or `ES256`/`ES384`/`ES512` for EC P-256/384/521). If an explicit
#'   value is provided but incompatible with the key, validation fails early with a configuration
#'   error. When the provider advertises
#'   `token_endpoint_auth_signing_alg_values_supported`, both explicit values and
#'   inferred defaults must be included in that set.
#'   Supported values are `HS256`, `HS384`, `HS512` for client_secret_jwt and asymmetric algorithms
#'   supported for outbound signing (`RS256`, `ES256`, `ES384`, `ES512`) for
#'   private keys. `RS384`, `RS512`, `PS256`, `PS384`, `PS512`, and `EdDSA`
#'   are not currently supported for outbound client assertions.
#'
#' @param client_assertion_audience Optional override for the `aud` claim used when building
#'   JWT client assertions (`client_secret_jwt` / `private_key_jwt`). By default, shinyOAuth
#'   uses the exact token endpoint request URL. Some identity providers require a different
#'   audience value; set this to the exact value your IdP expects.
#' @param mtls_client_cert_file Optional path to the PEM-encoded client
#'   certificate (or certificate chain) used for RFC 8705 mutual TLS client
#'   authentication and certificate-bound protected-resource requests. Required
#'   when `provider@token_auth_style` is `"tls_client_auth"` or
#'   `"self_signed_tls_client_auth"`.
#' @param mtls_client_key_file Optional path to the PEM-encoded private key used
#'   with `mtls_client_cert_file`. Must be supplied together with
#'   `mtls_client_cert_file`, and is required for RFC 8705 mTLS client
#'   authentication.
#' @param mtls_client_key_password Optional password used to decrypt an encrypted
#'   PEM private key referenced by `mtls_client_key_file`.
#' @param mtls_client_ca_file Optional path to a PEM CA bundle used to validate
#'   the remote HTTPS server certificate when making mTLS requests. This is
#'   mainly useful for local or test environments that use self-signed server
#'   certificates.
#' @param mtls_certificate_bound_access_tokens Logical. Whether this
#'   client intends to request RFC 8705 certificate-bound access tokens when
#'   the provider advertises that capability. Default is `FALSE`.
#'
#'   Set this to `TRUE` for clients that should prefer discovered
#'   `mtls_endpoint_aliases` on authorization-server requests even when
#'   `token_auth_style` itself is not an mTLS auth style, and that should fail
#'   closed if the returned access token omits `cnf.x5t#S256`.
#'
#'   Requires `mtls_client_cert_file` and `mtls_client_key_file`, and the
#'   provider must be configured with
#'   `mtls_client_certificate_bound_access_tokens = TRUE`.
#'
#' @param dpop_private_key Optional private key used to generate DPoP proofs
#'   (RFC 9449). Can be an `openssl::key` or a PEM string containing an
#'   asymmetric private key. When provided, shinyOAuth can attach `DPoP`
#'   proofs to token endpoint requests and use DPoP-bound access tokens in
#'   downstream request helpers. In [oauth_client()], configuring this key also
#'   makes `dpop_require_access_token` default to `TRUE`, so access-token
#'   responses reject `token_type = "Bearer"` unless you explicitly set
#'   `dpop_require_access_token = FALSE`. Current outbound DPoP signing
#'   supports RSA and EC private keys. For RSA keys, outbound signing is
#'   currently limited to `RS256`; `RS384`, `RS512`, and RSA-PSS (`PS256`,
#'   `PS384`, `PS512`) are not supported. Ed25519/Ed448 keys are also not
#'   currently supported. This is an advanced setting; most clients do not need
#'   DPoP unless their provider or resource server asks for it.
#'
#' @param dpop_private_key_kid Optional key identifier (`kid`) to include in
#'   the JOSE header of DPoP proofs. Useful when the authorization or resource
#'   server expects a stable key identifier alongside the embedded public JWK.
#'
#' @param dpop_signing_alg Optional JWT signing algorithm to use for DPoP
#'   proofs. When omitted, a compatible asymmetric default is selected based on
#'   the private key type/curve (for example `RS256`, `ES256`, `ES384`, or
#'   `ES512`). `RS384`, `RS512`, `PS256`, `PS384`, `PS512`, and `EdDSA` are
#'   not currently supported for outbound DPoP proofs. If an explicit value is
#'   provided but incompatible with the key, validation fails early with a
#'   configuration error. When the provider advertises
#'   `dpop_signing_alg_values_supported`, both explicit values and inferred
#'   defaults must be included in that set.
#'
#' @param dpop_require_access_token Logical or `NULL`. When `TRUE` and
#'   `dpop_private_key` is configured, shinyOAuth requires the authorization
#'   server to return `token_type = "DPoP"` for access tokens and fails fast
#'   otherwise. When shinyOAuth can observe token binding data from a JWT
#'   access token or an introspection response, this strict mode also requires
#'   `cnf$jkt` to be present and match the configured `dpop_private_key`.
#'   Opaque access tokens that expose no `cnf` data still pass this check unless
#'   introspection later reveals the binding. In [oauth_client()], the default
#'   `NULL` resolves to `TRUE` when `dpop_private_key` is configured and to
#'   `FALSE` otherwise. Set `FALSE` explicitly only when you intentionally want
#'   to allow Bearer access tokens, such as deployments where DPoP is used only
#'   to bind refresh tokens.
#'
#' @param dpop_require_observed_cnf Logical. When `TRUE`, shinyOAuth rejects
#'   `token_type = "DPoP"` access tokens unless it can observe `cnf$jkt`
#'   locally, either from the access token itself or from a token
#'   introspection response. Use this when high-assurance DPoP deployments must
#'   fail closed on opaque access tokens that provide no observable binding.
#'   Default is `FALSE`.
#'
#' @param request_object_mode Controls how the authorization request is
#'   transported to the provider.
#'
#'   - `"parameters"` (default): send OAuth parameters directly on the browser
#'     redirect URL.
#'   - `"request"`: send a signed JWT-secured authorization request (JAR;
#'     RFC 9101) via the `request` parameter.
#'   - `"request_uri"`: publish a signed Request Object by reference and send
#'     its URL via the `request_uri` parameter.
#'
#'   Most users can keep the default. Request mode is an advanced option that
#'   requires signing material on the client. shinyOAuth prefers
#'   `client_assertion_private_key` when present; otherwise it falls back to HMAC signing
#'   with `client_secret`. When Request Object encryption is configured,
#'   shinyOAuth signs first and then wraps the signed Request Object in a JWE.
#'   If a caller-managed `request_uri` uses HTTP and the configured host policy
#'   explicitly allows it, shinyOAuth still publishes it but warns once per R
#'   session because RFC 9101 Section 5.2 expects client-provided
#'   `request_uri` values to use HTTPS.
#'   If the provider advertises `request_uri_registration_required = TRUE`,
#'   caller-managed `request_uri` publication still depends on the provider
#'   having that URI or a matching wildcard prefix registered for the client;
#'   shinyOAuth cannot verify that server-side registration automatically.
#' @param request_object_signing_alg Optional JWS algorithm override for
#'   signed authorization requests when `request_object_mode` uses a
#'   Request Object (`"request"` or `"request_uri"`).
#'   When omitted, shinyOAuth chooses `HS256` for HMAC-based signing or a
#'   compatible asymmetric default based on `client_assertion_private_key` (for example
#'   `RS256`, `ES256`, `ES384`, or `ES512`). `RS384`, `RS512`, `PS256`,
#'   `PS384`, `PS512`, and `EdDSA` are not currently supported for outbound
#'   signed authorization requests.
#'
#' @param request_object_audience Optional override for the `aud` claim
#'   used in signed authorization requests. By default, shinyOAuth uses the
#'   provider issuer when available. When
#'   `request_object_mode = "request"` or `"request_uri"`, the provider
#'   must have a configured issuer or you must supply an explicit override so
#'   the signed Request Object remains audience-bound to the intended
#'   authorization server.
#' @param request_object_encryption_alg Optional JWE key-management
#'   algorithm override for encrypted Request Objects. Current outbound support
#'   is limited to `RSA-OAEP`. When set, you must also set
#'   `request_object_encryption_enc`.
#' @param request_object_encryption_enc Optional JWE content-encryption
#'   algorithm override for encrypted Request Objects. Current outbound support
#'   is limited to the AES-CBC-HMAC family (`A128CBC-HS256`,
#'   `A192CBC-HS384`, `A256CBC-HS512`). When set, you must also set
#'   `request_object_encryption_alg`.
#' @param request_object_encryption_kid Optional key identifier (`kid`)
#'   used to select one provider encryption key and emit the outer JWE `kid`
#'   header. This is mainly useful when the provider publishes more than one
#'   Request Object encryption key.
#' @param request_object_ttl Positive number of seconds to keep signed
#'   authorization request objects (`request` JWTs) valid. When
#'   `request_object_mode = "request_uri"`, shinyOAuth also uses this
#'   value as the default publication window for the referenced Request Object
#'   URI. Default is `45`.
#' @param request_object_nbf_skew Optional non-negative number of
#'   seconds. When provided, shinyOAuth adds an `nbf` claim set to
#'   `iat - request_object_nbf_skew` so deployments can tolerate small
#'   clock skew while still emitting bounded request-object validity windows.
#'   Leave `NULL` (the default) to omit `nbf`. Request-object `nbf` is reserved
#'   by shinyOAuth and cannot be supplied through extra authorization
#'   parameters.
#'
#' @param jarm_signed_response_alg Optional expected JWS algorithm for
#'   signed JWT Secured Authorization Responses (JARM). When omitted and the
#'   effective response mode is JARM, shinyOAuth defaults to `RS256`. This
#'   value is not sent dynamically on the authorization request; it must match
#'   the client metadata and provider behavior configured out-of-band for that
#'   client. Current inbound support accepts `HS256`, `HS384`, `HS512`,
#'   `RS256`, `RS384`, `RS512`, `ES256`, `ES384`, `ES512`, and `EdDSA`.
#'   RSA-PSS (`PS256`, `PS384`, `PS512`) and unsecured `none` are not accepted
#'   for inbound JARM.
#' @param jarm_encrypted_response_alg Optional expected JWE
#'   key-management algorithm for encrypted JARM responses. Current inbound
#'   support is limited to `RSA-OAEP`. Like
#'   `jarm_signed_response_alg`, this reflects out-of-band client
#'   metadata and expected provider behavior rather than an authorization
#'   request parameter emitted by shinyOAuth.
#' @param jarm_encrypted_response_enc Optional expected JWE
#'   content-encryption algorithm for encrypted JARM responses. Current inbound
#'   support is limited to the AES-CBC-HMAC family (`A128CBC-HS256`,
#'   `A192CBC-HS384`, `A256CBC-HS512`). When omitted while
#'   `jarm_encrypted_response_alg` is set, shinyOAuth defaults to
#'   `A128CBC-HS256`. This must also match the provider-side JARM client
#'   metadata when encrypted responses are enabled.
#' @param jarm_decryption_private_key Optional private key
#'   used to decrypt encrypted JARM responses. Can be an `openssl::key` or a
#'   PEM string containing a private key. Required when encrypted JARM is
#'   enabled.
#' @param jarm_decryption_private_key_kid Optional key
#'   identifier (`kid`) associated with
#'   `jarm_decryption_private_key`.
#' @param jarm_max_lifetime Positive number of seconds. Maximum accepted
#'   lifetime for a JARM response JWT. Default is 600 seconds, matching JARM's
#'   recommended 10-minute upper bound for authorization response JWTs. When a
#'   JARM payload includes `iat`, shinyOAuth enforces
#'   `exp - iat <= jarm_max_lifetime`; otherwise it falls back to the
#'   remaining `exp` window at validation time. Applies only when
#'   `response_mode` uses JARM.
#'
#' @example inst/examples/oauth_module_server.R
#'
#' @export
OAuthClient <- S7::new_class(
  "OAuthClient",
  package = "shinyOAuth",
  properties = list(
    # Use class_any here to avoid load-order dependency on OAuthProvider symbol;
    # we validate it's actually an OAuthProvider in the validator below.
    provider = S7::class_any,
    client_id = S7::class_character,
    client_secret = S7::class_character,
    redirect_uri = S7::class_character,
    scopes = S7::class_character,
    # Authorization response mode for authorization-code callbacks.
    response_mode = S7::new_property(
      S7::class_character,
      default = NA_character_
    ),
    resource = S7::new_property(
      S7::class_character,
      default = character(0)
    ),
    # Optional OIDC claims request parameter (OIDC Core §5.5):
    # can be NULL (no claims), a list (auto JSON-encoded), or a character
    # string (pre-encoded JSON). When a list, it is JSON-encoded using
    # jsonlite::toJSON(auto_unbox = TRUE, null = "null") during auth URL
    # construction.
    claims = S7::new_property(
      S7::class_any,
      default = NULL
    ),
    enforce_callback_issuer = S7::new_property(
      S7::class_logical,
      default = FALSE
    ),
    scope_validation = S7::new_property(
      S7::class_character,
      default = "warn"
    ),
    claims_validation = S7::new_property(
      S7::class_character,
      default = "none"
    ),
    # OIDC acr enforcement (OIDC Core §2, §3.1.2.1): when non-empty, the ID
    # token's acr claim must match one of these values.
    required_acr_values = S7::new_property(
      S7::class_character,
      default = character(0)
    ),
    userinfo_jwt_required_time_claims = S7::new_property(
      S7::class_character,
      default = character(0)
    ),
    # Token introspection settings (RFC 7662): control whether login validates
    # the access token via the provider's introspection endpoint.
    introspect = S7::new_property(S7::class_logical, default = FALSE),
    introspect_elements = S7::new_property(
      S7::class_character,
      default = character(0)
    ),
    state_store = S7::new_property(
      S7::class_any,
      default = quote(cachem::cache_mem(max_age = 300))
    ),
    state_payload_max_age = S7::new_property(S7::class_numeric, default = 300),
    state_entropy = S7::new_property(S7::class_numeric, default = 64),
    state_key = S7::new_property(
      S7::class_any,
      default = quote(random_urlsafe(n = 128))
    ),
    # Optional client assertion private key (PEM string or openssl::key) for private_key_jwt.
    client_assertion_private_key = S7::new_property(
      S7::class_any,
      default = NULL
    ),
    # Optional kid header to include when using private_key_jwt.
    client_assertion_private_key_kid = S7::new_property(
      S7::class_character,
      default = NA_character_
    ),
    # Optional override for client assertion signing algorithm. If NULL, defaults
    # to HS256 for client_secret_jwt and RS256 for private_key_jwt.
    client_assertion_alg = S7::new_property(
      S7::class_character,
      default = NA_character_
    ),
    # Optional override for the client assertion audience claim.
    client_assertion_audience = S7::new_property(
      S7::class_character,
      default = NA_character_
    ),
    mtls_client_cert_file = S7::new_property(
      S7::class_character,
      default = NA_character_
    ),
    mtls_client_key_file = S7::new_property(
      S7::class_character,
      default = NA_character_
    ),
    mtls_client_key_password = S7::new_property(
      S7::class_character,
      default = NA_character_
    ),
    mtls_client_ca_file = S7::new_property(
      S7::class_character,
      default = NA_character_
    ),
    mtls_certificate_bound_access_tokens = S7::new_property(
      S7::class_logical,
      default = FALSE
    ),
    # Optional DPoP proof key (PEM string or openssl::key) used to
    # sender-constrain token and resource requests.
    dpop_private_key = S7::new_property(S7::class_any, default = NULL),
    # Optional kid header to include in DPoP proofs.
    dpop_private_key_kid = S7::new_property(
      S7::class_character,
      default = NA_character_
    ),
    # Optional override for the DPoP proof signing algorithm.
    dpop_signing_alg = S7::new_property(
      S7::class_character,
      default = NA_character_
    ),
    # Optional strict mode: require DPoP access tokens when DPoP is enabled.
    dpop_require_access_token = S7::new_property(
      S7::class_logical,
      default = FALSE
    ),
    # Optional high-assurance mode: require observable DPoP cnf.jkt binding.
    dpop_require_observed_cnf = S7::new_property(
      S7::class_logical,
      default = FALSE
    ),
    # Authorization request transport: direct parameters or signed JAR request.
    request_object_mode = S7::new_property(
      S7::class_character,
      default = "parameters"
    ),
    # Optional override for the signed authorization request alg.
    request_object_signing_alg = S7::new_property(
      S7::class_character,
      default = NA_character_
    ),
    # Optional override for the signed authorization request aud claim.
    request_object_audience = S7::new_property(
      S7::class_character,
      default = NA_character_
    ),
    # Optional override for the Request Object JWE alg.
    request_object_encryption_alg = S7::new_property(
      S7::class_character,
      default = NA_character_
    ),
    # Optional override for the Request Object JWE enc.
    request_object_encryption_enc = S7::new_property(
      S7::class_character,
      default = NA_character_
    ),
    # Optional recipient-key selection hint for Request Object JWE.
    request_object_encryption_kid = S7::new_property(
      S7::class_character,
      default = NA_character_
    ),
    # Signed authorization request lifetime in seconds.
    request_object_ttl = S7::new_property(
      S7::class_numeric,
      default = 45
    ),
    # Optional request-object nbf skew in seconds; NA means omit nbf.
    request_object_nbf_skew = S7::new_property(
      S7::class_numeric,
      default = NA_real_
    ),
    # Optional override for the signed JARM alg.
    jarm_signed_response_alg = S7::new_property(
      S7::class_character,
      default = NA_character_
    ),
    # Optional override for the encrypted JARM alg.
    jarm_encrypted_response_alg = S7::new_property(
      S7::class_character,
      default = NA_character_
    ),
    # Optional override for the encrypted JARM enc.
    jarm_encrypted_response_enc = S7::new_property(
      S7::class_character,
      default = NA_character_
    ),
    # Optional private key used to decrypt encrypted JARM.
    jarm_decryption_private_key = S7::new_property(
      S7::class_any,
      default = NULL
    ),
    # Optional kid associated with the encrypted JARM decryption key.
    jarm_decryption_private_key_kid = S7::new_property(
      S7::class_character,
      default = NA_character_
    ),
    # Maximum accepted JARM JWT lifetime in seconds.
    jarm_max_lifetime = S7::new_property(S7::class_numeric, default = 600)
  ),
  validator = function(self) oauth_client_validate(self)
)

# 2 Helper constructor ---------------------------------------------------------

#' Create generic [OAuthClient]
#'
#' Main helper for creating a validated [OAuthClient] configuration before
#' [oauth_module_server()] starts login or callback handling.
#'
#' @inheritParams OAuthClient
#' @param ... Deprecated renamed arguments accepted temporarily for backward
#'   compatibility.
#'
#' @return [OAuthClient] object
#'
#' @example inst/examples/oauth_module_server.R
#'
#' @export
oauth_client <- function(
  provider,
  client_id,
  client_secret = character(0),
  redirect_uri,
  scopes = character(0),
  response_mode = NULL,
  resource = character(0),
  claims = NULL,
  enforce_callback_issuer = NULL,
  scope_validation = c("warn", "strict", "none"),
  claims_validation = c("none", "warn", "strict"),
  required_acr_values = character(0),
  userinfo_jwt_required_time_claims = character(0),
  introspect = FALSE,
  introspect_elements = character(0),
  state_store = cachem::cache_mem(max_age = 300),
  state_payload_max_age = 300,
  state_entropy = 64,
  state_key = random_urlsafe(128),
  client_assertion_private_key = NULL,
  client_assertion_private_key_kid = NULL,
  client_assertion_alg = NULL,
  client_assertion_audience = NULL,
  mtls_client_cert_file = NULL,
  mtls_client_key_file = NULL,
  mtls_client_key_password = NULL,
  mtls_client_ca_file = NULL,
  mtls_certificate_bound_access_tokens = FALSE,
  dpop_private_key = NULL,
  dpop_private_key_kid = NULL,
  dpop_signing_alg = NULL,
  dpop_require_access_token = NULL,
  dpop_require_observed_cnf = FALSE,
  request_object_mode = c("parameters", "request", "request_uri"),
  request_object_signing_alg = NULL,
  request_object_audience = NULL,
  request_object_encryption_alg = NULL,
  request_object_encryption_enc = NULL,
  request_object_encryption_kid = NULL,
  request_object_ttl = 45,
  request_object_nbf_skew = NULL,
  jarm_signed_response_alg = NULL,
  jarm_encrypted_response_alg = NULL,
  jarm_encrypted_response_enc = NULL,
  jarm_decryption_private_key = NULL,
  jarm_decryption_private_key_kid = NULL,
  jarm_max_lifetime = 600,
  ...
) {
  compat_args <- resolve_deprecated_constructor_args(
    dots = list(...),
    arg_map = c(
      client_private_key = "client_assertion_private_key",
      client_private_key_kid = "client_assertion_private_key_kid",
      userinfo_jwt_required_temporal_claims = "userinfo_jwt_required_time_claims",
      mtls_request_certificate_bound_access_tokens = "mtls_certificate_bound_access_tokens",
      tls_client_cert_file = "mtls_client_cert_file",
      tls_client_key_file = "mtls_client_key_file",
      tls_client_key_password = "mtls_client_key_password",
      tls_client_ca_file = "mtls_client_ca_file",
      authorization_request_mode = "request_object_mode",
      authorization_request_signing_alg = "request_object_signing_alg",
      authorization_request_audience = "request_object_audience",
      authorization_request_encryption_alg = "request_object_encryption_alg",
      authorization_request_encryption_enc = "request_object_encryption_enc",
      authorization_request_encryption_kid = "request_object_encryption_kid",
      authorization_request_ttl = "request_object_ttl",
      authorization_request_nbf_skew = "request_object_nbf_skew",
      authorization_signed_response_alg = "jarm_signed_response_alg",
      authorization_encrypted_response_alg = "jarm_encrypted_response_alg",
      authorization_encrypted_response_enc = "jarm_encrypted_response_enc",
      authorization_response_decryption_private_key = "jarm_decryption_private_key",
      authorization_response_decryption_private_key_kid = "jarm_decryption_private_key_kid"
    ),
    fn_name = "oauth_client",
    provided_new = c(
      client_assertion_private_key = !missing(client_assertion_private_key),
      client_assertion_private_key_kid = !missing(
        client_assertion_private_key_kid
      ),
      userinfo_jwt_required_time_claims = !missing(
        userinfo_jwt_required_time_claims
      ),
      mtls_certificate_bound_access_tokens = !missing(
        mtls_certificate_bound_access_tokens
      ),
      mtls_client_cert_file = !missing(mtls_client_cert_file),
      mtls_client_key_file = !missing(mtls_client_key_file),
      mtls_client_key_password = !missing(mtls_client_key_password),
      mtls_client_ca_file = !missing(mtls_client_ca_file),
      request_object_mode = !missing(request_object_mode),
      request_object_signing_alg = !missing(request_object_signing_alg),
      request_object_audience = !missing(request_object_audience),
      request_object_encryption_alg = !missing(request_object_encryption_alg),
      request_object_encryption_enc = !missing(request_object_encryption_enc),
      request_object_encryption_kid = !missing(request_object_encryption_kid),
      request_object_ttl = !missing(request_object_ttl),
      request_object_nbf_skew = !missing(request_object_nbf_skew),
      jarm_signed_response_alg = !missing(jarm_signed_response_alg),
      jarm_encrypted_response_alg = !missing(jarm_encrypted_response_alg),
      jarm_encrypted_response_enc = !missing(jarm_encrypted_response_enc),
      jarm_decryption_private_key = !missing(jarm_decryption_private_key),
      jarm_decryption_private_key_kid = !missing(
        jarm_decryption_private_key_kid
      )
    )
  )
  if (length(compat_args) > 0) {
    list2env(compat_args, envir = environment())
  }

  dpop_require_access_token_missing <-
    missing(dpop_require_access_token) || is.null(dpop_require_access_token)
  claims_validation_missing <- missing(claims_validation)

  warn_about_oauth_client_created_in_shiny(
    state_key_missing = missing(state_key)
  )

  auto_enforce_callback_issuer <-
    missing(enforce_callback_issuer) || is.null(enforce_callback_issuer)
  if (
    !auto_enforce_callback_issuer &&
      !(is.logical(enforce_callback_issuer) &&
        length(enforce_callback_issuer) == 1 &&
        !is.na(enforce_callback_issuer))
  ) {
    err_input(
      "{.arg enforce_callback_issuer} must be NULL or a single non-NA logical."
    )
  }

  resolved_enforce_callback_issuer <- if (
    auto_enforce_callback_issuer &&
      S7::S7_inherits(provider, OAuthProvider)
  ) {
    isTRUE(provider@authorization_response_iss_parameter_supported) &&
      is_valid_string(provider@issuer %||% NA_character_)
  } else {
    isTRUE(enforce_callback_issuer)
  }
  if (
    isTRUE(resolved_enforce_callback_issuer) &&
      S7::S7_inherits(provider, OAuthProvider) &&
      !is_valid_string(provider@issuer %||% NA_character_)
  ) {
    provider_name <- provider@name %||% "(unnamed)"
    err_config(
      c(
        "{.arg enforce_callback_issuer} = {.val TRUE} requires the provider to have a configured {.arg issuer}.",
        "x" = paste0(
          "Provider {.val ",
          provider_name,
          "} does not expose a stable issuer identifier."
        ),
        "i" = "Disable {.arg enforce_callback_issuer} or use an issuer-configured OIDC/discovery provider."
      )
    )
  }

  scope_validation <- match.arg(scope_validation)
  if (
    isTRUE(claims_validation_missing) &&
      claims_request_has_enforceable_requirements(claims)
  ) {
    claims_validation <- "warn"
  }
  claims_validation <- match.arg(claims_validation)
  warn_about_scalar_claim_values(claims)
  request_object_mode <- match.arg(request_object_mode)
  response_mode_info <- resolve_auth_response_mode(
    response_mode,
    arg = "response_mode",
    context = "OAuthClient"
  )
  if (!is.null(response_mode_info[["error"]])) {
    err_input(response_mode_info[["error"]])
  }
  response_mode <- response_mode_info[["mode"]] %||%
    NA_character_
  jarm_encrypted_response_alg <- jarm_encrypted_response_alg %||%
    NA_character_
  jarm_encrypted_response_enc <-
    jarm_encrypted_response_enc %||% NA_character_
  if (
    is_valid_string(jarm_encrypted_response_alg %||% NA_character_) &&
      !is_valid_string(jarm_encrypted_response_enc %||% NA_character_)
  ) {
    jarm_encrypted_response_enc <- "A128CBC-HS256"
  }

  if (
    !isTRUE(dpop_require_access_token_missing) &&
      !(is.logical(dpop_require_access_token) &&
        length(dpop_require_access_token) == 1L &&
        !is.na(dpop_require_access_token))
  ) {
    err_input(
      "{.arg dpop_require_access_token} must be NULL or a single non-NA logical."
    )
  }
  if (
    !(is.logical(dpop_require_observed_cnf) &&
      length(dpop_require_observed_cnf) == 1L &&
      !is.na(dpop_require_observed_cnf))
  ) {
    err_input(
      "{.arg dpop_require_observed_cnf} must be a single non-NA logical."
    )
  }
  if (
    !(is.logical(mtls_certificate_bound_access_tokens) &&
      length(mtls_certificate_bound_access_tokens) == 1L &&
      !is.na(mtls_certificate_bound_access_tokens))
  ) {
    err_input(
      paste(
        "{.arg mtls_certificate_bound_access_tokens}",
        "must be a single non-NA logical."
      )
    )
  }

  # Normalize scopes early so callers can provide a single space-delimited
  # string (common in OAuth examples) while internal code consistently sees
  # a character vector of individual tokens.
  if (!is.null(scopes)) {
    scopes_for_validation <- if (is.list(scopes)) {
      unlist(scopes, recursive = TRUE, use.names = FALSE)
    } else {
      scopes
    }
    validate_scopes(as.character(scopes_for_validation))
  }
  scopes <- as_scope_tokens(scopes %||% NULL)
  resource <- resource %||% character(0)
  userinfo_jwt_required_time_claims <- unique(tolower(
    userinfo_jwt_required_time_claims %||% character(0)
  ))

  if (isTRUE(dpop_require_access_token_missing)) {
    dpop_require_access_token <- !is.null(dpop_private_key)
  }

  client <- OAuthClient(
    provider = provider,
    client_id = client_id,
    client_secret = client_secret,
    redirect_uri = redirect_uri,
    scopes = scopes,
    response_mode = response_mode,
    resource = resource,
    claims = claims,
    enforce_callback_issuer = isTRUE(resolved_enforce_callback_issuer),
    scope_validation = scope_validation,
    claims_validation = claims_validation,
    required_acr_values = required_acr_values,
    userinfo_jwt_required_time_claims = userinfo_jwt_required_time_claims,
    introspect = introspect,
    introspect_elements = introspect_elements,
    state_store = state_store,
    state_payload_max_age = state_payload_max_age,
    state_entropy = state_entropy,
    state_key = state_key,
    client_assertion_private_key = client_assertion_private_key,
    client_assertion_private_key_kid = client_assertion_private_key_kid %||%
      NA_character_,
    client_assertion_alg = client_assertion_alg %||% NA_character_,
    client_assertion_audience = client_assertion_audience %||% NA_character_,
    mtls_client_cert_file = mtls_client_cert_file %||% NA_character_,
    mtls_client_key_file = mtls_client_key_file %||% NA_character_,
    mtls_client_key_password = mtls_client_key_password %||% NA_character_,
    mtls_client_ca_file = mtls_client_ca_file %||% NA_character_,
    mtls_certificate_bound_access_tokens = isTRUE(
      mtls_certificate_bound_access_tokens
    ),
    dpop_private_key = dpop_private_key,
    dpop_private_key_kid = dpop_private_key_kid %||% NA_character_,
    dpop_signing_alg = dpop_signing_alg %||% NA_character_,
    dpop_require_access_token = isTRUE(dpop_require_access_token),
    dpop_require_observed_cnf = isTRUE(dpop_require_observed_cnf),
    request_object_mode = request_object_mode,
    request_object_signing_alg = request_object_signing_alg %||%
      NA_character_,
    request_object_audience = request_object_audience %||%
      NA_character_,
    request_object_encryption_alg = request_object_encryption_alg %||%
      NA_character_,
    request_object_encryption_enc = request_object_encryption_enc %||%
      NA_character_,
    request_object_encryption_kid = request_object_encryption_kid %||%
      NA_character_,
    request_object_ttl = request_object_ttl,
    request_object_nbf_skew = request_object_nbf_skew %||%
      NA_real_,
    jarm_signed_response_alg = jarm_signed_response_alg %||%
      NA_character_,
    jarm_encrypted_response_alg = jarm_encrypted_response_alg,
    jarm_encrypted_response_enc = jarm_encrypted_response_enc,
    jarm_decryption_private_key = jarm_decryption_private_key,
    jarm_decryption_private_key_kid = jarm_decryption_private_key_kid %||%
      NA_character_,
    jarm_max_lifetime = jarm_max_lifetime
  )

  client
}

# 3 Validation and constructor support helpers ---------------------------------

## 3.1 Client validation -------------------------------------------------------

#' Internal: validate one OAuthClient configuration
#'
#' Used by the [OAuthClient] S7 class before the rest of the package builds
#' authorization URLs, exchanges tokens, or processes callbacks.
#'
#' @param self [OAuthClient] instance under validation.
#' @return `NULL` for a valid client, otherwise a length-1 validation error
#'   string.
#' @keywords internal
#' @noRd
oauth_client_validate <- function(self) {
  if (!S7::S7_inherits(self@provider, OAuthProvider)) {
    return("OAuthClient: provider must be an OAuthProvider object")
  }

  # Require a non-empty client_id
  if (!is_valid_string(self@client_id)) {
    return("OAuthClient: client_id must be a non-empty string")
  }

  parsed <- try(httr2::url_parse(self@redirect_uri), silent = TRUE)
  if (
    inherits(parsed, "try-error") ||
      !nzchar((parsed[["scheme"]] %||% "")) ||
      !nzchar((parsed[["hostname"]] %||% ""))
  ) {
    return(
      "OAuthClient: redirect_uri must be an absolute URL (including scheme and hostname)"
    )
  }

  # RFC 6749 Section 3.1.2: redirect URI MUST NOT include a fragment
  if (nzchar(parsed[["fragment"]] %||% "")) {
    return(
      "OAuthClient: redirect_uri must not contain a URI fragment (RFC 6749 Section 3.1.2)"
    )
  }

  if (!is_ok_host(self@redirect_uri)) {
    return(paste0(
      "OAuthClient: redirect URI not accepted as a host ",
      "(see `?is_ok_host` for details)"
    ))
  }

  if (
    !(is.logical(self@enforce_callback_issuer) &&
      length(self@enforce_callback_issuer) == 1L &&
      !is.na(self@enforce_callback_issuer))
  ) {
    return(
      "OAuthClient: enforce_callback_issuer must be a single non-NA logical"
    )
  }
  if (
    isTRUE(self@enforce_callback_issuer) &&
      !is_valid_string(self@provider@issuer %||% NA_character_)
  ) {
    return(
      "OAuthClient: enforce_callback_issuer = TRUE requires the provider to have an issuer configured"
    )
  }

  # State payload freshness window (issued_at)
  spma <- suppressWarnings(as.numeric(self@state_payload_max_age))
  if (length(spma) != 1L || !is.finite(spma) || spma <= 0) {
    return(
      "OAuthClient: state_payload_max_age must be a finite positive number of seconds"
    )
  }

  # Validate client_secret presence based on provider auth style and PKCE
  tok_style <- normalize_token_auth_style(
    self@provider@token_auth_style %||% "header"
  )
  uses_pkce <- isTRUE(self@provider@use_pkce)
  if (identical(tok_style, "header")) {
    # For client_secret_basic (header) auth, a non-empty secret is required
    if (!is_valid_string(self@client_secret)) {
      return(
        "OAuthClient: client_secret is required when token_auth_style = 'header'"
      )
    }
  } else if (identical(tok_style, "body")) {
    # For client_secret_post (body) auth, allow secretless only with PKCE
    if (!uses_pkce && !is_valid_string(self@client_secret)) {
      return(
        "OAuthClient: client_secret is required unless using PKCE with token_auth_style = 'body'"
      )
    }
  } else if (identical(tok_style, "public")) {
    # Public clients send only client_id at the token endpoint.
  } else if (identical(tok_style, "client_secret_jwt")) {
    # JWT HMAC client assertion requires a non-empty client_secret
    if (!is_valid_string(self@client_secret)) {
      return(
        "OAuthClient: client_secret is required when token_auth_style = 'client_secret_jwt'"
      )
    }
  } else if (identical(tok_style, "private_key_jwt")) {
    # Asymmetric client assertion requires a private key
    if (is.null(self@client_assertion_private_key)) {
      return(
        "OAuthClient: client_assertion_private_key is required when token_auth_style = 'private_key_jwt'"
      )
    }
    # Basic sanity: if a character was supplied, must look like a PEM
    if (is.character(self@client_assertion_private_key)) {
      pem <- paste(self@client_assertion_private_key, collapse = "\n")
      # Accept PKCS#1 ("BEGIN RSA PRIVATE KEY" / "BEGIN EC PRIVATE KEY")
      # and PKCS#8 ("BEGIN PRIVATE KEY"). Make the RSA/EC prefix optional.
      if (
        !grepl(
          "BEGIN (?:RSA |EC )?PRIVATE KEY",
          pem,
          ignore.case = TRUE,
          perl = TRUE
        )
      ) {
        return(
          "OAuthClient: client_assertion_private_key must be a PEM string (BEGIN ... PRIVATE KEY) or an openssl::key"
        )
      }
    }
  }

  # Fail fast: HS* ID token verification requires a strong client_secret.
  #
  # For PKCE/public clients, client_secret may legitimately be empty for token
  # exchange (token_auth_style = 'body' with PKCE or token_auth_style =
  # 'public'), but if the provider allows HS* ID token algs and the flow may
  # validate ID tokens (id_token_validation or use_nonce), validate_id_token()
  # will later error when client_secret is missing/too short.
  aa <- toupper(as.character(self@provider@allowed_algs %||% character(0)))
  hs_algs <- c("HS256", "HS384", "HS512")
  hs_algs_enabled <- intersect(hs_algs, aa)
  should_validate_id_token <-
    isTRUE(self@provider@id_token_validation) ||
    isTRUE(self@provider@use_nonce)
  if (length(hs_algs_enabled) > 0 && isTRUE(should_validate_id_token)) {
    if (!is_valid_string(self@client_secret)) {
      return(
        "OAuthClient: client_secret is required for HS* ID token validation when id_token_validation or use_nonce is enabled"
      )
    }
    required_hs_bytes <- max(vapply(
      hs_algs_enabled,
      min_hmac_key_bytes,
      integer(1)
    ))
    if (nchar(self@client_secret, type = "bytes") < required_hs_bytes) {
      return(
        paste0(
          "OAuthClient: HS* ID token validation requires client_secret >= ",
          required_hs_bytes,
          " bytes for the configured allowed_algs"
        )
      )
    }
  }

  # If an explicit client_assertion_alg is provided, validate compatibility
  # with the configured token authentication style so we fail fast with a
  # clear input error rather than later inside JWT signing.
  client_assertion_alg <- NA_character_
  if (!is.null(self@client_assertion_alg)) {
    caa_raw <- self@client_assertion_alg
    if (!is.character(caa_raw) || length(caa_raw) != 1L) {
      return(
        "OAuthClient: client_assertion_alg must be a scalar character string (or NULL to omit)"
      )
    }
    alg_chr <- caa_raw
    if (!is.na(alg_chr) && nzchar(alg_chr)) {
      client_assertion_alg <- canonicalize_jws_alg(alg_chr)
      allowed_hmac <- c("HS256", "HS384", "HS512")
      allowed_asym <- c(
        "RS256",
        "ES256",
        "ES384",
        "ES512"
      )
      if (
        identical(tok_style, "client_secret_jwt") &&
          !(client_assertion_alg %in% allowed_hmac)
      ) {
        return(paste0(
          "OAuthClient: client_assertion_alg '",
          client_assertion_alg,
          "' is incompatible with token_auth_style = 'client_secret_jwt' (expected one of: ",
          paste(allowed_hmac, collapse = ", "),
          ")"
        ))
      }
      if (
        identical(tok_style, "private_key_jwt") &&
          !(client_assertion_alg %in% allowed_asym)
      ) {
        return(paste0(
          "OAuthClient: client_assertion_alg '",
          client_assertion_alg,
          "' is incompatible with token_auth_style = 'private_key_jwt' (expected one of: ",
          paste(allowed_asym, collapse = ", "),
          ")"
        ))
      }
      if (identical(tok_style, "private_key_jwt")) {
        key0 <- try(
          normalize_private_key_input(self@client_assertion_private_key),
          silent = TRUE
        )
        if (inherits(key0, "try-error")) {
          return(
            "OAuthClient: client_assertion_private_key could not be parsed for client_assertion_alg validation"
          )
        }
        if (
          !private_key_can_sign_jws_alg(
            key0,
            client_assertion_alg,
            typ = "JWT"
          )
        ) {
          return(paste0(
            "OAuthClient: client_assertion_alg '",
            client_assertion_alg,
            "' is incompatible with the provided private key"
          ))
        }
      }
    }
  }

  if (
    identical(tok_style, "private_key_jwt") &&
      (is.na(client_assertion_alg) || !nzchar(client_assertion_alg))
  ) {
    key0 <- try(
      normalize_private_key_input(self@client_assertion_private_key),
      silent = TRUE
    )
    if (inherits(key0, "try-error")) {
      return(
        "OAuthClient: client_assertion_private_key could not be parsed for client_assertion_alg validation"
      )
    }

    inferred_alg <- try(
      choose_default_alg_for_private_key(key0),
      silent = TRUE
    )
    if (inherits(inferred_alg, "try-error")) {
      return(paste(
        "OAuthClient: could not determine a compatible default",
        "client_assertion_alg from client_assertion_private_key",
        "(outbound private-key JWT signing currently supports RSA and ECDSA private keys only)"
      ))
    }
  }

  resolved_client_assertion_alg <- if (
    identical(tok_style, "client_secret_jwt")
  ) {
    if (!is.na(client_assertion_alg) && nzchar(client_assertion_alg)) {
      client_assertion_alg
    } else {
      "HS256"
    }
  } else {
    NA_character_
  }

  provider_client_assertion_algs <- toupper(as.character(
    self@provider@token_endpoint_auth_signing_alg_values_supported %||%
      character(0)
  ))
  if (
    length(provider_client_assertion_algs) > 0 &&
      (identical(tok_style, "client_secret_jwt") ||
        identical(tok_style, "private_key_jwt"))
  ) {
    resolved_client_assertion_alg <- if (
      !is.na(resolved_client_assertion_alg) &&
        nzchar(resolved_client_assertion_alg)
    ) {
      resolved_client_assertion_alg
    } else {
      inferred_alg <- try(
        {
          key0 <- normalize_private_key_input(self@client_assertion_private_key)
          choose_default_alg_for_private_key(key0)
        },
        silent = TRUE
      )
      if (inherits(inferred_alg, "try-error")) {
        return(
          paste(
            "OAuthClient: could not determine a compatible default",
            "client_assertion_alg from client_assertion_private_key"
          )
        )
      }
      toupper(as.character(inferred_alg))
    }

    if (
      !(toupper(resolved_client_assertion_alg) %in%
        provider_client_assertion_algs)
    ) {
      return(paste0(
        "OAuthClient: client_assertion_alg '",
        resolved_client_assertion_alg,
        "' is not supported by provider token_endpoint_auth_signing_alg_values_supported"
      ))
    }
  }

  if (identical(tok_style, "client_secret_jwt")) {
    min_secret_bytes <- min_hmac_key_bytes(resolved_client_assertion_alg)
    if (nchar(self@client_secret, type = "bytes") < min_secret_bytes) {
      return(paste0(
        "OAuthClient: client_secret_jwt with client_assertion_alg '",
        resolved_client_assertion_alg,
        "' requires client_secret >= ",
        min_secret_bytes,
        " bytes"
      ))
    }
  }

  # Validate client_assertion_audience when provided
  caa <- self@client_assertion_audience %||% NA_character_
  if (!is.character(caa) || length(caa) != 1L) {
    return(
      "OAuthClient: client_assertion_audience must be a scalar character string (or NULL/NA to omit)"
    )
  }
  if (!is.na(caa) && !nzchar(caa)) {
    return(
      "OAuthClient: client_assertion_audience must be non-empty when provided (use NULL or NA to omit)"
    )
  }

  arm <- self@request_object_mode %||% "parameters"
  if (!is.character(arm) || length(arm) != 1L || is.na(arm)) {
    return(
      "OAuthClient: request_object_mode must be a scalar character string"
    )
  }
  response_mode_info <- resolve_oauth_client_response_mode(self)
  if (!is.null(response_mode_info[["error"]])) {
    return(response_mode_info[["error"]])
  }
  effective_response_mode <- response_mode_info[["mode"]] %||%
    "query"
  jarm_response_mode <- effective_response_mode %in%
    c(
      "query.jwt",
      "form_post.jwt"
    )

  if (isTRUE(jarm_response_mode)) {
    jml <- suppressWarnings(as.numeric(self@jarm_max_lifetime))
    if (length(jml) != 1L || !is.finite(jml) || jml <= 0) {
      return(
        "OAuthClient: jarm_max_lifetime must be a finite positive number of seconds"
      )
    }
  }

  request_object_modes <- c("request", "request_uri")

  asra <- self@jarm_signed_response_alg %||% NA_character_
  if (!is.character(asra) || length(asra) != 1L) {
    return(
      paste(
        "OAuthClient: jarm_signed_response_alg must be a scalar",
        "character string (or NULL/NA to omit)"
      )
    )
  }
  if (!is.na(asra) && !nzchar(asra)) {
    return(
      paste(
        "OAuthClient: jarm_signed_response_alg must be non-empty",
        "when provided (use NULL or NA to omit)"
      )
    )
  }

  signed_response_alg <- if (!is.na(asra) && nzchar(asra)) {
    canonicalize_jws_alg(asra)
  } else if (isTRUE(jarm_response_mode)) {
    "RS256"
  } else {
    ""
  }
  if (!isTRUE(jarm_response_mode) && !is.na(asra) && nzchar(asra)) {
    return(
      paste(
        "OAuthClient: jarm_signed_response_alg requires",
        "response_mode = 'jwt', 'query.jwt', or 'form_post.jwt'"
      )
    )
  }
  if (identical(toupper(signed_response_alg), "NONE")) {
    return(
      "OAuthClient: jarm_signed_response_alg = 'none' is not supported"
    )
  }
  if (
    isTRUE(jarm_response_mode) &&
      !(signed_response_alg %in%
        c(
          "HS256",
          "HS384",
          "HS512",
          "RS256",
          "RS384",
          "RS512",
          "ES256",
          "ES384",
          "ES512",
          "EdDSA"
        ))
  ) {
    return(paste0(
      "OAuthClient: jarm_signed_response_alg '",
      signed_response_alg,
      "' is not supported for inbound JARM validation"
    ))
  }

  aera <- self@jarm_encrypted_response_alg %||% NA_character_
  if (!is.character(aera) || length(aera) != 1L) {
    return(
      paste(
        "OAuthClient: jarm_encrypted_response_alg must be a scalar",
        "character string (or NULL/NA to omit)"
      )
    )
  }
  if (!is.na(aera) && !nzchar(aera)) {
    return(
      paste(
        "OAuthClient: jarm_encrypted_response_alg must be non-empty",
        "when provided (use NULL or NA to omit)"
      )
    )
  }

  aere <- self@jarm_encrypted_response_enc %||% NA_character_
  if (!is.character(aere) || length(aere) != 1L) {
    return(
      paste(
        "OAuthClient: jarm_encrypted_response_enc must be a scalar",
        "character string (or NULL/NA to omit)"
      )
    )
  }
  if (!is.na(aere) && !nzchar(aere)) {
    return(
      paste(
        "OAuthClient: jarm_encrypted_response_enc must be non-empty",
        "when provided (use NULL or NA to omit)"
      )
    )
  }

  aerk <- self@jarm_decryption_private_key_kid %||%
    NA_character_
  if (!is.character(aerk) || length(aerk) != 1L) {
    return(
      paste(
        "OAuthClient: jarm_decryption_private_key_kid must be a scalar",
        "character string (or NULL/NA to omit)"
      )
    )
  }
  if (!is.na(aerk) && !nzchar(aerk)) {
    return(
      paste(
        "OAuthClient: jarm_decryption_private_key_kid must be non-empty",
        "when provided (use NULL or NA to omit)"
      )
    )
  }

  encrypted_response_alg <- canonicalize_jwe_alg(aera)
  encrypted_response_enc <- canonicalize_jwe_enc(aere)
  if (nzchar(encrypted_response_alg) && !nzchar(encrypted_response_enc)) {
    encrypted_response_enc <- "A128CBC-HS256"
  }
  encrypted_jarm_enabled <-
    nzchar(encrypted_response_alg) ||
    nzchar(encrypted_response_enc) ||
    !is.null(self@jarm_decryption_private_key)

  if (
    !isTRUE(jarm_response_mode) &&
      (!is.na(asra) && nzchar(asra) || encrypted_jarm_enabled)
  ) {
    return(
      paste(
        "OAuthClient: JARM authorization response settings require",
        "response_mode = 'jwt', 'query.jwt', or 'form_post.jwt'"
      )
    )
  }
  if (
    isTRUE(jarm_response_mode) &&
      !is_valid_string(self@provider@issuer %||% NA_character_)
  ) {
    return(
      "OAuthClient: JARM response modes require the provider to have an issuer configured"
    )
  }
  if (nzchar(encrypted_response_alg) != nzchar(encrypted_response_enc)) {
    return(
      paste(
        "OAuthClient: jarm_encrypted_response_alg and",
        "jarm_encrypted_response_enc must both be provided"
      )
    )
  }
  if (isTRUE(encrypted_jarm_enabled) && !nzchar(encrypted_response_alg)) {
    return(
      paste(
        "OAuthClient: encrypted JARM requires",
        "jarm_encrypted_response_alg"
      )
    )
  }
  if (isTRUE(encrypted_jarm_enabled)) {
    if (!(encrypted_response_alg %in% c("RSA-OAEP"))) {
      return(paste0(
        "OAuthClient: jarm_encrypted_response_alg '",
        encrypted_response_alg,
        "' is not supported for inbound encrypted JARM"
      ))
    }
    if (
      !(encrypted_response_enc %in%
        c(
          "A128CBC-HS256",
          "A192CBC-HS384",
          "A256CBC-HS512"
        ))
    ) {
      return(paste0(
        "OAuthClient: jarm_encrypted_response_enc '",
        encrypted_response_enc,
        "' is not supported for inbound encrypted JARM"
      ))
    }
    if (is.null(self@jarm_decryption_private_key)) {
      return(
        paste(
          "OAuthClient: encrypted JARM requires",
          "jarm_decryption_private_key"
        )
      )
    }

    response_decryption_key <- try(
      normalize_private_key_input(
        self@jarm_decryption_private_key,
        arg_name = "jarm_decryption_private_key"
      ),
      silent = TRUE
    )
    if (inherits(response_decryption_key, "try-error")) {
      return(
        paste(
          "OAuthClient: jarm_decryption_private_key must be a parseable",
          "PEM private key or openssl::key"
        )
      )
    }
    if (!inherits(response_decryption_key, "rsa")) {
      return(
        paste(
          "OAuthClient: encrypted JARM currently requires an RSA private key for",
          "jarm_decryption_private_key"
        )
      )
    }
  }

  provider_authorization_signing_algs <- as.character(
    self@provider@jarm_signing_alg_values_supported %||% character(0)
  )
  if (
    isTRUE(jarm_response_mode) &&
      length(provider_authorization_signing_algs) > 0 &&
      !(signed_response_alg %in% provider_authorization_signing_algs)
  ) {
    return(paste0(
      "OAuthClient: jarm_signed_response_alg '",
      signed_response_alg,
      "' is not supported by provider jarm_signing_alg_values_supported"
    ))
  }

  provider_authorization_encryption_algs <- as.character(
    self@provider@jarm_encryption_alg_values_supported %||%
      character(0)
  )
  if (
    isTRUE(encrypted_jarm_enabled) &&
      length(provider_authorization_encryption_algs) > 0 &&
      !(encrypted_response_alg %in%
        provider_authorization_encryption_algs)
  ) {
    return(paste0(
      "OAuthClient: jarm_encrypted_response_alg '",
      encrypted_response_alg,
      "' is not supported by provider jarm_encryption_alg_values_supported"
    ))
  }

  provider_authorization_encryption_encs <- as.character(
    self@provider@jarm_encryption_enc_values_supported %||%
      character(0)
  )
  if (
    isTRUE(encrypted_jarm_enabled) &&
      length(provider_authorization_encryption_encs) > 0 &&
      !(encrypted_response_enc %in%
        provider_authorization_encryption_encs)
  ) {
    return(paste0(
      "OAuthClient: jarm_encrypted_response_enc '",
      encrypted_response_enc,
      "' is not supported by provider jarm_encryption_enc_values_supported"
    ))
  }

  if (
    isTRUE(jarm_response_mode) &&
      signed_response_alg %in% c("HS256", "HS384", "HS512")
  ) {
    if (!is_valid_string(self@client_secret)) {
      return("OAuthClient: HS* JARM validation requires client_secret")
    }
    min_secret_bytes <- min_hmac_key_bytes(signed_response_alg)
    if (nchar(self@client_secret, type = "bytes") < min_secret_bytes) {
      return(paste0(
        "OAuthClient: jarm_signed_response_alg '",
        signed_response_alg,
        "' requires client_secret >= ",
        min_secret_bytes,
        " bytes"
      ))
    }
  }

  if (!(arm %in% c("parameters", request_object_modes))) {
    return(
      paste(
        "OAuthClient: request_object_mode must be one of 'parameters',",
        "'request', or 'request_uri'"
      )
    )
  }
  if (
    identical(arm, "request") &&
      identical(self@provider@request_parameter_supported, FALSE) &&
      !is_valid_string(self@provider@par_url %||% NA_character_)
  ) {
    return(
      paste(
        "OAuthClient: provider discovery metadata says request parameter transport is not supported;",
        paste(
          "request_object_mode = 'request' cannot be used unless",
          "PAR is configured"
        )
      )
    )
  }
  if (
    identical(arm, "request_uri") &&
      identical(self@provider@request_uri_parameter_supported, FALSE)
  ) {
    return(
      paste(
        "OAuthClient: provider discovery metadata says request_uri parameter",
        "transport is not supported; request_object_mode =",
        "'request_uri' cannot be used"
      )
    )
  }
  if (
    !(arm %in% request_object_modes) &&
      isTRUE(self@provider@signed_request_object_required)
  ) {
    return(
      paste(
        "OAuthClient: provider requires signed request objects;",
        "set request_object_mode = 'request' or 'request_uri'"
      )
    )
  }

  provider_has_issuer <- is_valid_string(
    self@provider@issuer %||% NA_character_
  )
  par_configured <- is_valid_string(self@provider@par_url %||% NA_character_)
  front_channel_mode <-
    self@provider@authorization_request_front_channel_mode %||% "compat"
  if (
    isTRUE(provider_has_issuer) &&
      identical(front_channel_mode, "minimal") &&
      (identical(arm, "request_uri") ||
        (identical(arm, "request") && !isTRUE(par_configured)))
  ) {
    return(
      paste(
        "OAuthClient: OpenID Connect request and caller-managed request_uri transports do not support",
        "authorization_request_front_channel_mode = 'minimal';",
        "use 'compat' or send the request through PAR"
      )
    )
  }

  arsa <- self@request_object_signing_alg %||% NA_character_
  if (!is.character(arsa) || length(arsa) != 1L) {
    return(
      "OAuthClient: request_object_signing_alg must be a scalar character string (or NULL/NA to omit)"
    )
  }
  if (!is.na(arsa) && !nzchar(arsa)) {
    return(
      "OAuthClient: request_object_signing_alg must be non-empty when provided (use NULL or NA to omit)"
    )
  }

  ara <- self@request_object_audience %||% NA_character_
  if (!is.character(ara) || length(ara) != 1L) {
    return(
      "OAuthClient: request_object_audience must be a scalar character string (or NULL/NA to omit)"
    )
  }
  if (!is.na(ara) && !nzchar(ara)) {
    return(
      "OAuthClient: request_object_audience must be non-empty when provided (use NULL or NA to omit)"
    )
  }
  if (
    arm %in%
      request_object_modes &&
      is.na(ara) &&
      !is_valid_string(self@provider@issuer %||% NA_character_)
  ) {
    return(
      paste(
        "OAuthClient: request_object_mode = 'request' or 'request_uri' requires either",
        "provider issuer or request_object_audience so Request Objects stay audience-bound"
      )
    )
  }

  area <- self@request_object_encryption_alg %||% NA_character_
  if (!is.character(area) || length(area) != 1L) {
    return(
      paste(
        "OAuthClient: request_object_encryption_alg must be a scalar",
        "character string (or NULL/NA to omit)"
      )
    )
  }
  if (!is.na(area) && !nzchar(area)) {
    return(
      paste(
        "OAuthClient: request_object_encryption_alg must be non-empty",
        "when provided (use NULL or NA to omit)"
      )
    )
  }

  arec <- self@request_object_encryption_enc %||% NA_character_
  if (!is.character(arec) || length(arec) != 1L) {
    return(
      paste(
        "OAuthClient: request_object_encryption_enc must be a scalar",
        "character string (or NULL/NA to omit)"
      )
    )
  }
  if (!is.na(arec) && !nzchar(arec)) {
    return(
      paste(
        "OAuthClient: request_object_encryption_enc must be non-empty",
        "when provided (use NULL or NA to omit)"
      )
    )
  }

  arek <- self@request_object_encryption_kid %||% NA_character_
  if (!is.character(arek) || length(arek) != 1L) {
    return(
      paste(
        "OAuthClient: request_object_encryption_kid must be a scalar",
        "character string (or NULL/NA to omit)"
      )
    )
  }
  if (!is.na(arek) && !nzchar(arek)) {
    return(
      paste(
        "OAuthClient: request_object_encryption_kid must be non-empty",
        "when provided (use NULL or NA to omit)"
      )
    )
  }

  arttl <- self@request_object_ttl %||% NA_real_
  if (!(is.numeric(arttl) && length(arttl) == 1L && is.finite(arttl))) {
    return(
      paste(
        "OAuthClient: request_object_ttl must be a single finite number",
        "of seconds"
      )
    )
  }
  if (arttl <= 0) {
    return(
      "OAuthClient: request_object_ttl must be greater than 0 seconds"
    )
  }

  arns <- self@request_object_nbf_skew %||% NA_real_
  if (
    !(is.numeric(arns) &&
      length(arns) == 1L &&
      (is.na(arns) || is.finite(arns)))
  ) {
    return(
      paste(
        "OAuthClient: request_object_nbf_skew must be NULL/NA or a",
        "single finite number of seconds"
      )
    )
  }
  if (!is.na(arns) && arns < 0) {
    return(
      paste(
        "OAuthClient: request_object_nbf_skew must be greater than or",
        "equal to 0 seconds"
      )
    )
  }

  if (arm %in% request_object_modes) {
    allowed_hmac <- c("HS256", "HS384", "HS512")
    allowed_asym <- c(
      "RS256",
      "ES256",
      "ES384",
      "ES512"
    )
    alg <- canonicalize_jws_alg(arsa)
    has_private_key <- !is.null(self@client_assertion_private_key)
    has_secret <- is_valid_string(self@client_secret)

    if (nzchar(alg) && identical(toupper(alg), "NONE")) {
      return(
        "OAuthClient: request_object_signing_alg = 'none' is not supported"
      )
    }

    if (!nzchar(alg)) {
      if (isTRUE(has_private_key)) {
        key0 <- try(
          normalize_private_key_input(self@client_assertion_private_key),
          silent = TRUE
        )
        if (inherits(key0, "try-error")) {
          return(
            "OAuthClient: client_assertion_private_key could not be parsed for request_object_signing_alg validation"
          )
        }

        inferred_alg <- try(
          choose_default_alg_for_private_key(key0),
          silent = TRUE
        )
        if (inherits(inferred_alg, "try-error")) {
          return(paste(
            "OAuthClient: could not determine a compatible default",
            "request_object_signing_alg from client_assertion_private_key",
            "(outbound signed authorization requests currently support RSA and ECDSA private keys only)"
          ))
        }
      }
      if (!isTRUE(has_private_key) && !isTRUE(has_secret)) {
        return(
          paste(
            "OAuthClient: request_object_mode = 'request' or",
            "'request_uri' requires client_assertion_private_key or client_secret"
          )
        )
      }
      if (
        !isTRUE(has_private_key) &&
          nchar(self@client_secret, type = "bytes") <
            min_hmac_key_bytes("HS256")
      ) {
        return(
          paste(
            "OAuthClient: request_object_mode = 'request' or",
            "'request_uri' requires client_secret >= 32 bytes when no",
            "client_assertion_private_key is configured"
          )
        )
      }
    } else if (alg %in% allowed_hmac) {
      if (!isTRUE(has_secret)) {
        return(
          "OAuthClient: HS* request_object_signing_alg requires client_secret"
        )
      }
      min_secret_bytes <- min_hmac_key_bytes(alg)
      if (nchar(self@client_secret, type = "bytes") < min_secret_bytes) {
        return(paste0(
          "OAuthClient: request_object_signing_alg '",
          alg,
          "' requires client_secret >= ",
          min_secret_bytes,
          " bytes"
        ))
      }
    } else if (alg %in% allowed_asym) {
      if (!isTRUE(has_private_key)) {
        return(
          "OAuthClient: asymmetric request_object_signing_alg requires client_assertion_private_key"
        )
      }

      key0 <- try(
        normalize_private_key_input(self@client_assertion_private_key),
        silent = TRUE
      )
      if (inherits(key0, "try-error")) {
        return(
          "OAuthClient: client_assertion_private_key could not be parsed for request_object_signing_alg validation"
        )
      }
      if (
        !private_key_can_sign_jws_alg(key0, alg, typ = "oauth-authz-req+jwt")
      ) {
        return(paste0(
          "OAuthClient: request_object_signing_alg '",
          alg,
          "' is incompatible with the provided private key"
        ))
      }
    } else {
      return(paste0(
        "OAuthClient: request_object_signing_alg '",
        alg,
        "' is incompatible with signed authorization requests"
      ))
    }

    provider_request_algs <- toupper(as.character(
      self@provider@request_object_signing_alg_values_supported %||%
        character(0)
    ))
    if (length(provider_request_algs) > 0) {
      resolved_alg <- if (!is.na(alg) && nzchar(alg)) {
        alg
      } else if (isTRUE(has_private_key)) {
        inferred_alg <- try(
          {
            key0 <- normalize_private_key_input(
              self@client_assertion_private_key
            )
            choose_default_alg_for_private_key(key0)
          },
          silent = TRUE
        )
        if (inherits(inferred_alg, "try-error")) {
          return(
            paste(
              "OAuthClient: could not determine a compatible default",
              "request_object_signing_alg from client_assertion_private_key"
            )
          )
        }
        as.character(inferred_alg)
      } else {
        "HS256"
      }

      if (!(toupper(resolved_alg) %in% provider_request_algs)) {
        return(paste0(
          "OAuthClient: request_object_signing_alg '",
          resolved_alg,
          "' is not supported by provider request_object_signing_alg_values_supported"
        ))
      }
    }
  }

  encryption_alg <- canonicalize_jwe_alg(area)
  encryption_enc <- canonicalize_jwe_enc(arec)
  encryption_enabled <- nzchar(encryption_alg) || nzchar(encryption_enc)

  if (isTRUE(encryption_enabled) && !(arm %in% request_object_modes)) {
    return(
      paste(
        "OAuthClient: Request Object encryption requires",
        "request_object_mode = 'request' or 'request_uri'"
      )
    )
  }
  if (nzchar(encryption_alg) != nzchar(encryption_enc)) {
    return(
      paste(
        "OAuthClient: request_object_encryption_alg and",
        "request_object_encryption_enc must both be provided"
      )
    )
  }
  if (isTRUE(encryption_enabled)) {
    supported_encryption_algs <- c("RSA-OAEP")
    supported_encryption_encs <- c(
      "A128CBC-HS256",
      "A192CBC-HS384",
      "A256CBC-HS512"
    )

    if (!(encryption_alg %in% supported_encryption_algs)) {
      return(paste0(
        "OAuthClient: request_object_encryption_alg '",
        encryption_alg,
        "' is not supported for outbound Request Object encryption"
      ))
    }
    if (!(encryption_enc %in% supported_encryption_encs)) {
      return(paste0(
        "OAuthClient: request_object_encryption_enc '",
        encryption_enc,
        "' is not supported for outbound Request Object encryption"
      ))
    }

    provider_encryption_algs <- toupper(as.character(
      self@provider@request_object_encryption_alg_values_supported %||%
        character(0)
    ))
    if (
      length(provider_encryption_algs) > 0 &&
        !(toupper(encryption_alg) %in% provider_encryption_algs)
    ) {
      return(paste0(
        "OAuthClient: request_object_encryption_alg '",
        encryption_alg,
        "' is not supported by provider request_object_encryption_alg_values_supported"
      ))
    }

    provider_encryption_encs <- toupper(as.character(
      self@provider@request_object_encryption_enc_values_supported %||%
        character(0)
    ))
    if (
      length(provider_encryption_encs) > 0 &&
        !(toupper(encryption_enc) %in% provider_encryption_encs)
    ) {
      return(paste0(
        "OAuthClient: request_object_encryption_enc '",
        encryption_enc,
        "' is not supported by provider request_object_encryption_enc_values_supported"
      ))
    }

    provider_request_object_encryption_key <-
      self@provider@request_object_encryption_jwk %||% NULL
    if (
      is.null(provider_request_object_encryption_key) &&
        !is_valid_string(self@provider@issuer %||% NA_character_)
    ) {
      return(
        paste(
          "OAuthClient: Request Object encryption requires provider issuer or",
          "provider request_object_encryption_jwk"
        )
      )
    }
  }

  # Validate DPoP configuration when provided.
  if (!is.null(self@dpop_private_key)) {
    if (is.character(self@dpop_private_key)) {
      pem <- paste(self@dpop_private_key, collapse = "\n")
      if (
        !grepl(
          "BEGIN (?:RSA |EC |ENCRYPTED )?PRIVATE KEY",
          pem,
          ignore.case = TRUE,
          perl = TRUE
        )
      ) {
        return(
          "OAuthClient: dpop_private_key must be a PEM string (BEGIN ... PRIVATE KEY) or an openssl::key"
        )
      }
    }
  }

  dpop_kid <- self@dpop_private_key_kid %||% NA_character_
  if (!is.character(dpop_kid) || length(dpop_kid) != 1L) {
    return(
      "OAuthClient: dpop_private_key_kid must be a scalar character string (or NULL/NA to omit)"
    )
  }
  if (!is.na(dpop_kid) && !nzchar(dpop_kid)) {
    return(
      "OAuthClient: dpop_private_key_kid must be non-empty when provided (use NULL or NA to omit)"
    )
  }

  dpop_alg_raw <- self@dpop_signing_alg %||% NA_character_
  resolved_dpop_alg <- NA_character_
  if (!is.character(dpop_alg_raw) || length(dpop_alg_raw) != 1L) {
    return(
      "OAuthClient: dpop_signing_alg must be a scalar character string (or NULL/NA to omit)"
    )
  }
  if (!is.na(dpop_alg_raw) && nzchar(dpop_alg_raw)) {
    if (is.null(self@dpop_private_key)) {
      return(
        "OAuthClient: dpop_signing_alg requires dpop_private_key to also be configured"
      )
    }
    dpop_alg <- canonicalize_jws_alg(dpop_alg_raw)
    resolved_dpop_alg <- dpop_alg
    allowed_dpop_algs <- c(
      "RS256",
      "ES256",
      "ES384",
      "ES512"
    )
    if (!(dpop_alg %in% allowed_dpop_algs)) {
      return(paste0(
        "OAuthClient: dpop_signing_alg '",
        dpop_alg,
        "' is incompatible with DPoP (expected one of: ",
        paste(allowed_dpop_algs, collapse = ", "),
        ")"
      ))
    }
    key0 <- try(
      normalize_private_key_input(
        self@dpop_private_key,
        arg_name = "dpop_private_key"
      ),
      silent = TRUE
    )
    if (inherits(key0, "try-error")) {
      return(
        "OAuthClient: dpop_private_key could not be parsed for dpop_signing_alg validation"
      )
    }
    if (!private_key_can_sign_jws_alg(key0, dpop_alg, typ = "dpop+jwt")) {
      return(paste0(
        "OAuthClient: dpop_signing_alg '",
        dpop_alg,
        "' is incompatible with the provided dpop_private_key"
      ))
    }
  }

  if (
    !is.null(self@dpop_private_key) &&
      (!nzchar(dpop_alg_raw) || is.na(dpop_alg_raw))
  ) {
    key0 <- try(
      normalize_private_key_input(
        self@dpop_private_key,
        arg_name = "dpop_private_key"
      ),
      silent = TRUE
    )
    if (inherits(key0, "try-error")) {
      return(
        "OAuthClient: dpop_private_key could not be parsed for dpop_signing_alg validation"
      )
    }

    inferred_alg <- try(
      choose_default_alg_for_private_key(key0),
      silent = TRUE
    )
    if (inherits(inferred_alg, "try-error")) {
      return(paste(
        "OAuthClient: could not determine a compatible default",
        "dpop_signing_alg from dpop_private_key",
        "(outbound DPoP proofs currently support RSA and ECDSA private keys only)"
      ))
    }
    resolved_dpop_alg <- toupper(as.character(inferred_alg))
  }

  provider_dpop_algs <- toupper(as.character(
    self@provider@dpop_signing_alg_values_supported %||% character(0)
  ))
  if (length(provider_dpop_algs) > 0 && !is.null(self@dpop_private_key)) {
    if (!(toupper(resolved_dpop_alg) %in% provider_dpop_algs)) {
      return(paste0(
        "OAuthClient: dpop_signing_alg '",
        resolved_dpop_alg,
        "' is not supported by provider dpop_signing_alg_values_supported"
      ))
    }
  }

  if (
    !(is.logical(self@dpop_require_access_token) &&
      length(self@dpop_require_access_token) == 1L &&
      !is.na(self@dpop_require_access_token))
  ) {
    return(
      "OAuthClient: dpop_require_access_token must be a single non-NA logical"
    )
  }
  if (
    isTRUE(self@dpop_require_access_token) && is.null(self@dpop_private_key)
  ) {
    return(
      "OAuthClient: dpop_require_access_token = TRUE requires dpop_private_key"
    )
  }
  if (
    !(is.logical(self@dpop_require_observed_cnf) &&
      length(self@dpop_require_observed_cnf) == 1L &&
      !is.na(self@dpop_require_observed_cnf))
  ) {
    return(
      paste(
        "OAuthClient: dpop_require_observed_cnf",
        "must be a single non-NA logical"
      )
    )
  }
  if (
    isTRUE(self@dpop_require_observed_cnf) && is.null(self@dpop_private_key)
  ) {
    return(
      paste(
        "OAuthClient: dpop_require_observed_cnf = TRUE",
        "requires dpop_private_key"
      )
    )
  }
  if (
    !(is.logical(self@mtls_certificate_bound_access_tokens) &&
      length(self@mtls_certificate_bound_access_tokens) == 1L &&
      !is.na(self@mtls_certificate_bound_access_tokens))
  ) {
    return(paste(
      "OAuthClient: mtls_certificate_bound_access_tokens",
      "must be a single non-NA logical"
    ))
  }

  mtls_client_cert_file <- self@mtls_client_cert_file %||% NA_character_
  mtls_client_key_file <- self@mtls_client_key_file %||% NA_character_
  mtls_client_ca_file <- self@mtls_client_ca_file %||% NA_character_
  mtls_client_key_password <- self@mtls_client_key_password %||% NA_character_

  has_mtls_client_cert <- is_valid_string(mtls_client_cert_file)
  has_mtls_client_key <- is_valid_string(mtls_client_key_file)
  requires_tls_client_cert <- tok_style %in%
    c(
      "tls_client_auth",
      "self_signed_tls_client_auth"
    )
  requests_certificate_bound_tokens <- isTRUE(
    self@mtls_certificate_bound_access_tokens
  )

  if (
    isTRUE(requests_certificate_bound_tokens) &&
      !(has_mtls_client_cert && has_mtls_client_key)
  ) {
    return(paste(
      "OAuthClient: mtls_certificate_bound_access_tokens = TRUE",
      "requires mtls_client_cert_file and mtls_client_key_file"
    ))
  }
  if (
    isTRUE(requests_certificate_bound_tokens) &&
      !isTRUE(self@provider@mtls_client_certificate_bound_access_tokens)
  ) {
    return(paste(
      "OAuthClient: mtls_certificate_bound_access_tokens = TRUE",
      "requires provider@mtls_client_certificate_bound_access_tokens = TRUE"
    ))
  }

  if (
    isTRUE(requires_tls_client_cert) &&
      !(has_mtls_client_cert && has_mtls_client_key)
  ) {
    return(paste0(
      "OAuthClient: mtls_client_cert_file and mtls_client_key_file are required when token_auth_style = '",
      tok_style,
      "'"
    ))
  }
  if (xor(has_mtls_client_cert, has_mtls_client_key)) {
    return(
      paste(
        "OAuthClient: mtls_client_cert_file and mtls_client_key_file",
        "must be supplied together"
      )
    )
  }

  for (field in list(
    list(name = "mtls_client_cert_file", value = mtls_client_cert_file),
    list(name = "mtls_client_key_file", value = mtls_client_key_file),
    list(name = "mtls_client_ca_file", value = mtls_client_ca_file)
  )) {
    if (
      is_valid_string(field[["value"]]) &&
        !file.exists(field[["value"]])
    ) {
      return(
        paste0(
          "OAuthClient: ",
          field[["name"]],
          " must point to an existing file"
        )
      )
    }
  }

  if (
    !is.character(mtls_client_key_password) ||
      length(mtls_client_key_password) != 1L
  ) {
    return(
      "OAuthClient: mtls_client_key_password must be a scalar character string (or NULL/NA to omit)"
    )
  }
  if (!is.na(mtls_client_key_password) && !nzchar(mtls_client_key_password)) {
    return(
      "OAuthClient: mtls_client_key_password must be non-empty when provided (use NULL or NA to omit)"
    )
  }

  # Validate state_entropy: must be a finite length-1 numeric integer in [22, 128]
  ent <- self@state_entropy
  if (is.null(ent) || length(ent) != 1L || is.na(ent)) {
    return(
      "OAuthClient: state_entropy must be a non-NA length-1 numeric value"
    )
  }
  if (!is.numeric(ent) || !is.finite(ent)) {
    return("OAuthClient: state_entropy must be a finite numeric value")
  }
  # Require integer-like (avoid fractional lengths causing truncation surprises)
  if (!isTRUE(all.equal(ent, as.integer(ent)))) {
    return(
      "OAuthClient: state_entropy must be an integer number of characters"
    )
  }
  ent <- as.integer(ent)
  if (ent < 22L || ent > 128L) {
    return("OAuthClient: state_entropy must be between 22 and 128")
  }

  # Validate state_key: allow character (>= 32 chars) OR raw (>= 32 bytes)
  sk <- self@state_key
  sk_valid <- (is.character(sk) && is_valid_string(sk, min_char = 32)) ||
    (is.raw(sk) && length(sk) >= 32L)
  if (!sk_valid) {
    return(
      "OAuthClient: state_key must be character (>= 32 chars) or raw (>= 32 bytes)"
    )
  }

  # Duck-type state_store: require $get, $set, and $remove; $info optional
  has_get <- !is.null(self@state_store$get) &&
    is.function(self@state_store$get)
  has_set <- !is.null(self@state_store$set) &&
    is.function(self@state_store$set)
  has_remove <- !is.null(self@state_store$remove) &&
    is.function(self@state_store$remove)
  if (!isTRUE(has_get && has_set && has_remove)) {
    return(paste(
      "OAuthClient: state_store must implement cachem methods:",
      "$get(key, missing)",
      "$set(key, value)",
      "$remove(key)",
      sep = " "
    ))
  }

  # Robustness: verify method signatures/compatibility.
  # - $get must accept a named `missing` argument (or `...`).
  #   Validated via formals inspection (no probe-call) to avoid triggering
  #   side-effects in stateful backends or test wrappers.
  get_formals <- try(formals(self@state_store$get), silent = TRUE)
  get_args <- if (!inherits(get_formals, "try-error")) {
    names(get_formals)
  } else {
    character()
  }
  if (!("..." %in% get_args || "missing" %in% get_args)) {
    return(
      "OAuthClient: state_store$get must accept argument 'missing' (expected signature get(key, missing = NULL))"
    )
  }

  # - $set must accept (key, value) either explicitly or via "..."
  #   (do not probe-call to avoid side-effects)
  set_formals <- try(formals(self@state_store$set), silent = TRUE)
  set_args <- if (!inherits(set_formals, "try-error")) {
    names(set_formals)
  } else {
    character()
  }
  if (
    !("..." %in% set_args || ("key" %in% set_args && "value" %in% set_args))
  ) {
    return("OAuthClient: state_store$set must accept (key, value)")
  }

  # - $remove must accept a key (explicitly or via "...")
  rm_formals <- try(formals(self@state_store$remove), silent = TRUE)
  rm_args <- if (!inherits(rm_formals, "try-error")) {
    names(rm_formals)
  } else {
    character()
  }
  # remove() is called positionally; require at least one parameter (any name) or allow ...
  if (!("..." %in% rm_args || length(rm_args) >= 1L)) {
    return("OAuthClient: state_store$remove must accept (key)")
  }

  # Optional $take for atomic state consumption (preferred for shared stores)
  # Validated via formals inspection (no probe-call) to avoid triggering
  # side-effects in stateful backends or test wrappers.
  if (
    !is.null(self@state_store$take) &&
      is.function(self@state_store$take)
  ) {
    take_formals <- try(formals(self@state_store$take), silent = TRUE)
    take_args <- if (!inherits(take_formals, "try-error")) {
      names(take_formals)
    } else {
      character()
    }
    if (!("..." %in% take_args || "missing" %in% take_args)) {
      return(
        "OAuthClient: state_store$take must accept argument 'missing' (expected signature take(key, missing = NULL))"
      )
    }
  }

  # Validate scopes
  scopes_valid <- try(validate_scopes(self@scopes), silent = TRUE)
  if (inherits(scopes_valid, "try-error")) {
    return(paste0("OAuthClient: scopes validation error: ", scopes_valid))
  }

  resource_problem <- resource_indicator_problem(self@resource)
  if (!is.null(resource_problem)) {
    return(paste0("OAuthClient: ", resource_problem))
  }

  # Validate claims
  if (!is.null(self@claims)) {
    # Must be either a list or a single non-empty character string
    if (is.list(self@claims)) {
      # Lists are valid; they will be JSON-encoded later
    } else if (is.character(self@claims)) {
      if (length(self@claims) != 1L || !nzchar(self@claims)) {
        return(
          "OAuthClient: claims must be a single non-empty character string when provided as character"
        )
      }
      # Try to validate it's valid JSON
      json_valid <- try(jsonlite::validate(self@claims), silent = TRUE)
      if (inherits(json_valid, "try-error") || !isTRUE(json_valid)) {
        return(
          "OAuthClient: claims provided as character must be valid JSON"
        )
      }
    } else {
      return(
        "OAuthClient: claims must be NULL, a list, or a character string"
      )
    }
  }

  # Validate scope_validation
  if (
    !is_valid_string(self@scope_validation) ||
      !self@scope_validation %in% c("strict", "warn", "none")
  ) {
    return(
      "OAuthClient: scope_validation must be one of 'strict', 'warn', or 'none'"
    )
  }

  # Validate claims_validation
  if (
    !is_valid_string(self@claims_validation) ||
      !self@claims_validation %in% c("strict", "warn", "none")
  ) {
    return(
      "OAuthClient: claims_validation must be one of 'strict', 'warn', or 'none'"
    )
  }

  if (
    !identical(self@claims_validation, "none") &&
      claims_request_target_has_enforceable_requirements(
        self@claims,
        "id_token"
      )
  ) {
    id_token_will_be_validated <-
      isTRUE(self@provider@id_token_validation) ||
      isTRUE(self@provider@use_nonce)
    if (!isTRUE(id_token_will_be_validated)) {
      return(
        paste(
          "OAuthClient: claims$id_token validation requires the provider to validate ID tokens;",
          "set id_token_validation = TRUE or use_nonce = TRUE"
        )
      )
    }
  }

  # Validate userinfo_jwt_required_time_claims
  ujrtc <- self@userinfo_jwt_required_time_claims
  if (!is.character(ujrtc)) {
    return(
      paste(
        "OAuthClient: userinfo_jwt_required_time_claims must be a character vector"
      )
    )
  }
  if (anyNA(ujrtc)) {
    return(
      paste(
        "OAuthClient: userinfo_jwt_required_time_claims must not contain NA"
      )
    )
  }
  if (length(ujrtc) > 0 && !all(nzchar(ujrtc))) {
    return(
      paste(
        "OAuthClient: userinfo_jwt_required_time_claims must not contain empty strings"
      )
    )
  }
  invalid_userinfo_temporal_claims <- setdiff(
    unique(tolower(ujrtc)),
    c("exp", "iat", "nbf")
  )
  if (length(invalid_userinfo_temporal_claims) > 0) {
    return(paste0(
      "OAuthClient: invalid userinfo_jwt_required_time_claims value(s): ",
      paste(invalid_userinfo_temporal_claims, collapse = ", "),
      "; allowed values are: exp, iat, nbf"
    ))
  }

  # Validate required_acr_values
  racr <- self@required_acr_values
  if (!is.character(racr)) {
    return("OAuthClient: required_acr_values must be a character vector")
  }
  if (anyNA(racr)) {
    return("OAuthClient: required_acr_values must not contain NA")
  }
  if (!all(nzchar(racr))) {
    return("OAuthClient: required_acr_values must not contain empty strings")
  }
  if (length(racr) > 0) {
    # acr enforcement requires an OIDC-capable provider (issuer + id_token_validation)
    if (!is_valid_string(self@provider@issuer)) {
      return(
        "OAuthClient: required_acr_values requires the provider to have an issuer configured"
      )
    }
    if (!isTRUE(self@provider@id_token_validation)) {
      return(
        "OAuthClient: required_acr_values requires id_token_validation = TRUE on the provider"
      )
    }
  }

  # Validate introspect
  if (
    !is.logical(self@introspect) ||
      length(self@introspect) != 1L ||
      is.na(self@introspect)
  ) {
    return("OAuthClient: introspect must be TRUE or FALSE (non-NA)")
  }

  # Validate introspect_elements
  ie <- self@introspect_elements
  if (!is.character(ie)) {
    return("OAuthClient: introspect_elements must be a character vector")
  }
  if (anyNA(ie)) {
    return("OAuthClient: introspect_elements must not contain NA")
  }
  if (!all(nzchar(ie))) {
    return("OAuthClient: introspect_elements must not contain empty strings")
  }
  ie <- unique(ie)
  if (!isTRUE(self@introspect) && length(ie) > 0) {
    return(
      "OAuthClient: introspect_elements was provided but introspect = FALSE; set introspect = TRUE or pass introspect_elements = character(0)"
    )
  }
  if (isTRUE(self@introspect) && length(ie) > 0) {
    allowed_ie <- c("sub", "client_id", "scope", "token_type")
    bad <- setdiff(ie, allowed_ie)
    if (length(bad) > 0) {
      return(
        paste0(
          "OAuthClient: invalid introspect_elements value(s): ",
          paste(bad, collapse = ", "),
          "; allowed: ",
          paste(allowed_ie, collapse = ", ")
        )
      )
    }
  }

  # Fail fast: introspect = TRUE requires introspection_url
  if (isTRUE(self@introspect)) {
    introspection_url <- self@provider@introspection_url %||% NA_character_
    if (!is_valid_string(introspection_url)) {
      return(
        "OAuthClient: introspect = TRUE requires the provider to have an introspection_url configured"
      )
    }
  }

  NULL
}

## 3.2 Constructor warnings ----------------------------------------------------

#' Warn when a client is created inside Shiny server code
#'
#' Emits a once-per-session warning when an [OAuthClient] is constructed while a
#' live Shiny session is active, because redirect-based OAuth flows typically
#' require stable client configuration across sessions. Used by
#' [oauth_client()] before the constructed client is returned.
#'
#' @param state_key_missing Whether `oauth_client()` auto-generated the state
#'   key for this client.
#' @return Invisibly returns `TRUE` when a warning is emitted; otherwise
#'   invisibly returns `NULL`.
#' @keywords internal
#' @noRd
warn_about_oauth_client_created_in_shiny <- function(state_key_missing = NA) {
  if (.is_test()) {
    return(invisible(NULL))
  }

  sess <- get_current_shiny_session()
  if (is.null(sess)) {
    return(invisible(NULL))
  }

  bullets <- c(
    "!" = paste0(
      "Detected OAuth client construction while a Shiny session is active. ",
      "This is usually a bug: the OAuth login flow involves a redirect which creates a new session."
    )
  )

  if (isTRUE(state_key_missing)) {
    bullets <- c(
      bullets,
      "x" = paste0(
        "Because you did not supply {.code state_key}, it will be auto-generated for this session ",
        "and callbacks in the post-redirect session will be unable to decrypt/validate state."
      )
    )
  } else {
    bullets <- c(
      bullets,
      "i" = paste0(
        "Construct your {.code OAuthClient} once outside server logic (e.g., in global scope) and reuse it.",
        " If you must create clients dynamically, ensure {.code state_key} is stable across sessions and (for multi-worker deployments) shared across workers."
      )
    )
  }

  warn_pkg(
    "OAuthClient created inside Shiny",
    bullets,
    .frequency = "once",
    .frequency_id = "oauth-client-created-in-shiny"
  )

  invisible(TRUE)
}

#' Warn when claims `values` entries will auto-unbox to scalars
#'
#' Detects list-based OIDC claims requests that use a single-element `values`
#' vector without wrapping it in [I()]. Used by [oauth_client()] so callers get
#' an early warning before `jsonlite::toJSON(auto_unbox = TRUE)` serializes that
#' value as a scalar instead of the OIDC-required array.
#'
#' @param claims Claims request passed to [oauth_client()].
#' @return Invisibly returns `TRUE` when a warning is emitted; otherwise
#'   invisibly returns `NULL`.
#' @keywords internal
#' @noRd
warn_about_scalar_claim_values <- function(claims) {
  if (!is.list(claims) || length(claims) == 0L) {
    return(invisible(NULL))
  }

  bad_paths <- character(0)

  walk_claims <- function(node, path) {
    if (!is.list(node) || length(node) == 0L) {
      return(invisible(NULL))
    }

    node_names <- names(node) %||% rep("", length(node))
    for (i in seq_along(node)) {
      node_name <- node_names[[i]] %||% ""
      child_path <- if (nzchar(node_name)) {
        paste0(path, "$", node_name)
      } else {
        paste0(path, "[[", i, "]]")
      }
      child <- node[[i]]

      if (
        identical(node_name, "values") &&
          !inherits(child, "AsIs") &&
          is.atomic(child) &&
          length(child) == 1L
      ) {
        bad_paths <<- c(bad_paths, child_path)
      }

      if (is.list(child)) {
        walk_claims(child, child_path)
      }
    }

    invisible(NULL)
  }

  walk_claims(claims, "claims")
  bad_paths <- unique(bad_paths)
  if (length(bad_paths) == 0L) {
    return(invisible(NULL))
  }

  warn_pkg(
    "OIDC claims `values` may serialize incorrectly",
    c(
      "!" = paste0(
        "Single-element `values` entries are serialized as JSON scalars under `jsonlite::toJSON(auto_unbox = TRUE)`: ",
        paste(bad_paths, collapse = ", ")
      ),
      "i" = paste0(
        "Wrap single-element `values` entries in `I(...)` to force array encoding, ",
        "for example `values = I(\"urn:example:acr\")`."
      )
    ),
    .frequency = "once",
    .frequency_id = "claims-values-singleton-scalar"
  )

  invisible(TRUE)
}
