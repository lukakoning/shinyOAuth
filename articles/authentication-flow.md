# Authentication flow

## Overview

This vignette walks through what happens when a user signs in through
[`oauth_module_server()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_module_server.md).
It explains the main OAuth 2.0 and OpenID Connect (OIDC) steps in
package terms, so you can follow the flow without needing deep protocol
knowledge.

For a concise quick-start (minimal and manual button examples, options,
and security checklist) see:
[`vignette("usage", package = "shinyOAuth")`](https://lukakoning.github.io/shinyOAuth/articles/usage.md).

For an explanation of logging key events during the flow, see:
[`vignette("audit-logging", package = "shinyOAuth")`](https://lukakoning.github.io/shinyOAuth/articles/audit-logging.md).

## What happens during the authentication flow?

‘shinyOAuth’ handles the OAuth 2.0 Authorization Code flow, plus
optional OIDC checks, from start to finish. Below is the sequence of
steps and why each one matters.

### 1. First page load: set a browser token

On the first load of your app, the module asks the browser to set a
small random cookie (SameSite=`Strict` by default; `Secure` when
required by HTTPS or `SameSite=None`).

This browser token is mirrored to Shiny as an input. Its purpose is to
ensure that the same browser that starts login is the one that comes
back after the redirect. If the browser cannot create or read this
cookie bridge (for example because cookies are blocked or Web Crypto is
unavailable), the module surfaces `browser_cookie_error` and stops
before login continues. If the mirrored token looks invalid,
‘shinyOAuth’ rejects it, records the event, and asks the browser to
generate a fresh token before login or callback processing continues.

### 2. Decide whether to start login

If `oauth_module_server(auto_redirect = TRUE)`, an unauthenticated
session triggers immediate redirection to the provider authorization
endpoint.

If `oauth_module_server(auto_redirect = FALSE)`, you manually call
`$request_login()` (e.g., when your user clicks a button).

### 3. Build the authorization URL (`prepare_call()`)

To redirect the user to the provider, the module builds an authorization
URL from the provider’s authorization endpoint. The URL includes a few
values that keep the flow linked to the right session and protect the
callback:

- State: a random value used to link the callback to this login attempt
  and help block forged callbacks; ‘shinyOAuth’ also seals extra context
  into it
- PKCE: a `code_verifier` and matching `code_challenge` that prove the
  same browser session finishes the flow
- Nonce (OIDC): a random value that is checked again when validating the
  ID token

‘shinyOAuth’ seals the state by storing extra context inside an
encrypted and authenticated payload. That payload contains:

- state, client_id, redirect_uri
- requested scopes
- provider fingerprint (issuer/auth/token URLs)
- client-policy fingerprint for callback-time policy binding
- issued_at timestamp
- observability metadata like an internal trace id

Sealing the state helps prevent tampering, stale callbacks, and mix-ups
with other providers or clients.

On the server side, the package also stores a few one-time callback
values in the state store (for example a `cachem` backend), under a
derived key based on the plain state value:

- browser token
- code_verifier
- nonce (OIDC)

These values are used later during callback validation.

If the client has `authorization_request_mode = "request"`, ‘shinyOAuth’
switches from plain query parameters to a JWT-based authorization
request. This is the JAR pattern (RFC 9101). In that mode, the package
builds a Request Object JWT containing the OAuth authorization
parameters that would otherwise appear directly on the browser URL. By
default, ‘shinyOAuth’ signs these Request Objects, which protects them
from tampering. When Request Object encryption is configured,
‘shinyOAuth’ signs first and then wraps the signed Request Object in a
JWE, as RFC 9101 requires for nested JWTs, so the request gains
confidentiality as well.

If the client has `authorization_request_mode = "request_uri"`,
‘shinyOAuth’ builds the same Request Object but publishes it by
reference and redirects the browser with a `request_uri` instead of an
inline `request` JWT. In
[`oauth_module_server()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_module_server.md),
the default publisher serves that Request Object from the current Shiny
app origin, and `request_uri_base_url` lets you override the public base
URL when the authorization server must fetch it through a different host
or proxy. This is the caller-managed Request Object URI path from RFC
9101, so the provider fetches the Request Object directly from the
published URL. Because Shiny data-object URLs include session-routing
path segments, that published `request_uri` can also appear in
authorization-server, reverse-proxy, or access logs.
`request_uri_base_url` changes the public origin but not the underlying
Shiny path layout, so prefer PAR when you need provider-facing opaque
handles.

If the provider has a `par_url` configured and the client is not using
caller-managed `authorization_request_mode = "request_uri"`, the module
uses Pushed Authorization Requests (PAR, RFC 9126) before redirecting
the browser. In that mode, the authorization request is first sent
server-to-server to the provider’s PAR endpoint as a form-encoded POST.
The browser is then redirected with a provider-issued `request_uri`
handle instead of the raw authorization parameters. By default, OIDC
providers keep outer `client_id`, `response_type=code`, and a `scope`
containing `openid` for compatibility, while the sealed `state`,
`redirect_uri`, and other request details stay behind the PAR handle.
Set
`oauth_provider(authorization_request_front_channel_mode = "minimal")`
for stricter authorization servers that expect only `client_id` plus
`request_uri`. Plain OAuth PAR flows already use that minimal shape. If
the provider requires PAR, `authorization_request_mode = "request_uri"`
is not allowed, because RFC 9126 assigns the `request_uri` handle to the
PAR response and the PAR request itself must not include a `request_uri`
parameter.

### 4. App redirects to the provider

If the client sets `response_mode = "form_post"`, ‘shinyOAuth’ also
sends `response_mode=form_post` on the authorization request so the
provider knows to return the authorization response as an HTTP POST. If
the client sets `response_mode = "jwt"`, ‘shinyOAuth’ sends that exact
shortcut value and still expects the authorization-code callback on the
normal query path because `jwt` selects the default transport for that
response type. If `response_mode` is left unset, ‘shinyOAuth’ stays on
the normal query callback flow and does not send a `response_mode`
parameter.

Without JAR and without PAR, the browser of the app user is redirected
to the provider’s authorization endpoint with the usual OAuth query
parameters: `response_type=code`, `client_id`, `redirect_uri`,
`state=<sealed state>`, PKCE parameters, `nonce` (OIDC), `scope`,
`claims` (OIDC, when configured via `oauth_client(claims = ...)`),
`acr_values` (OIDC, when `required_acr_values` is set on the client),
plus any configured extra parameters.

With JAR enabled but without PAR, the browser is still redirected to the
provider’s authorization endpoint, but the URL now carries the Request
Object instead of the raw authorization parameters. In practice, the
redirect contains `request=<Request Object JWT>` plus the outer
parameters that the active profile still requires. By default, OIDC
providers keep outer `client_id`, `response_type=code`, and an outer
`scope` containing `openid`. That outer OIDC shape is required by OpenID
Connect Core Section 6.1, so
`authorization_request_front_channel_mode = "minimal"` is rejected for
OIDC by-value `request` transport. Plain OAuth JAR flows can still use
the minimal `client_id` plus `request` shape. The Request Object itself
is signed by default, or signed first and then encrypted as a nested JWT
when Request Object encryption is configured.

With caller-managed `request_uri` mode, the browser is redirected with
`request_uri=<absolute URL>` plus any outer parameters still required by
the active profile. By default, OIDC providers keep outer `client_id`,
`response_type=code`, and an outer `scope` containing `openid`. That
outer OIDC shape is required by OpenID Connect Core Section 6.2, so
`authorization_request_front_channel_mode = "minimal"` is rejected for
caller-managed OIDC `request_uri` transport. Plain OAuth
request-by-reference flows can still use the minimal `client_id` plus
`request_uri` shape. The authorization server then fetches the Request
Object from that URL. This is different from PAR: the `request_uri`
points at a client-managed published Request Object, not a
provider-issued PAR handle. The published object still follows the same
JAR rules as above: signed by default, or signed first and then
encrypted when Request Object encryption is configured. In the default
Shiny-backed publisher used by ‘shinyOAuth’, that URL also embeds Shiny
session-routing path segments, so it is not as log-opaque as a
provider-issued PAR handle.

With PAR enabled and selected, the browser is still redirected to the
provider’s authorization endpoint, but the front-channel URL contains
only the PAR handle plus any profile-required outer parameters. By
default, OIDC providers keep outer `client_id`, `response_type=code`, an
outer `scope` containing `openid`, and `request_uri`. If your provider
accepts a smaller PAR redirect carrying only `client_id` plus the
provider-issued `request_uri`, set
`oauth_provider(authorization_request_front_channel_mode = "minimal")`.
Plain OAuth PAR flows already use that minimal shape. If JAR request
mode is also enabled, the Request Object pushed to the PAR endpoint
follows the same rule: signed by default, or signed first and then
encrypted when Request Object encryption is configured.

### 5. User authenticates and authorizes

Once at the provider’s authorization page, the user is prompted to log
in and authorize the app to access the requested scopes.

### 6. Provider redirects user back to the app

The provider returns the user’s browser to your Shiny app
(`redirect_uri`).

In the default query flow, the browser lands back on the app with `code`
and `state` in the query string, and optionally RFC 9207 `iss`, plus
`error`, `error_description`, and `error_uri` on failure.

If the client requested `response_mode = "jwt"` or
`response_mode = "query.jwt"`, the query callback instead carries a
compact JWT in the `response` parameter. For the authorization-code
flow, `jwt` is just the JARM shortcut for the default query transport,
so the callback still returns over the query string.
[`oauth_module_server()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_module_server.md)
validates that query JARM response before using any grant-specific
fields: it checks the compact JWT shape, enforces the expected issuer
and audience, checks expiry and any configured encryption, validates the
signature, and only then resumes the code or error callback path from
the normalized JARM claims.

#### What changes with `response_mode = "form_post"`?

If the client requested `response_mode = "form_post"`, the first hop
back is an HTTP POST to the `redirect_uri` instead of a query-string
callback. The plain form body carries the same callback fields (`code`,
`state`, optional `iss`, or provider error fields such as `error`,
`error_description`, and `error_uri`).

Because that POST reaches the app before a Shiny session exists, your UI
must be wrapped with
[`oauth_form_post_ui()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_form_post_ui.md).
That wrapper validates the POST boundary, decrypts the sealed state and
checks `iss` early enough to reject obviously invalid callbacks, stores
the accepted callback payload inside an authenticated short-lived
single-use handle, and replies with a `303 See Other` redirect back to
the app. The redirected URL no longer carries raw OAuth callback values;
instead, the OAuth-specific query parameters are only
`shinyOAuth_form_post=<handle>` and
`shinyOAuth_form_post_id=<module id>` so the normal Shiny module
callback path can resume on an ordinary GET request. Plain `form_post`
is supported; JWT Secured Authorization Response Mode (JARM) values such
as `form_post.jwt` use the same POST bridge, but the provider sends a
compact JWT `response` instead of direct OAuth fields.
[`oauth_form_post_ui()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_form_post_ui.md)
validates that JARM payload and the inner sealed state before
redirecting back to the app with the short-lived callback handle.

### 7. Callback processing & state verification (`oauth_module_server()`)

Once the browser lands back on the app, either directly with query
parameters or through the `form_post` bridge redirect, the module
processes the callback. In plain terms, it checks that the callback
belongs to the login attempt that started earlier and only then
continues to token exchange. For classic direct `code` + `state`
callbacks, the exported
[`handle_callback()`](https://lukakoning.github.io/shinyOAuth/reference/handle_callback.md)
helper performs the same state and token checks. JARM callback parsing
and resume stay internal to
[`oauth_module_server()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_module_server.md).
The main module checks are:

- Wait for a usable browser token input if it has not reached Shiny yet;
  when the cookie bridge fails, the module surfaces
  `browser_cookie_error` instead of attempting authentication without
  that binding
- If the URL carries a `form_post` bridge handle, resolve that handle to
  the stored callback payload and reject missing, expired, replayed, or
  misaddressed handles before continuing. The underlying login state is
  still consumed only after the Shiny session proves the browser-token
  binding
- If the URL carries a JARM `response` query parameter
  (`response_mode = "jwt"` or `"query.jwt"`), validate the callback JWT
  before reading any `code`, `error`, or `state` values from it.
  Query-based JARM callbacks are rejected if the `response` parameter is
  malformed, mixed with direct OAuth callback fields, or arrives on a
  client configured for the `form_post.jwt` transport
- Enforce callback query size caps before and after parsing, and when
  `form_post` is enabled also cap the incoming POST body, to protect
  against unusually large or abusive callback inputs on sensitive
  parameters such as `code`, `state`, `error`, `error_description`,
  `error_uri`, and `iss`
- Validate the callback `iss` value against the provider’s
  configured/discovered issuer so the callback must come from the
  expected provider (per RFC 9207). When
  `oauth_client(enforce_callback_issuer = TRUE)` is enabled, callbacks
  that omit `iss` are also rejected before token exchange. A mismatch
  produces an `issuer_mismatch` error; a missing required `iss` produces
  an `issuer_missing` error and corresponding audit event
- If the callback is an error response (`error=...`), still require a
  valid `state` parameter and browser-token binding before showing the
  provider error. That way, attacker-controlled error values are not
  trusted on their own. The provider’s `error_uri` is only surfaced when
  it is an absolute HTTPS URL
- Decrypt and verify the sealed state, making sure it is authentic and
  still fresh
- Check that embedded context matches the expected client and provider
- Fetch and immediately delete the one-time state entry from the
  configured state store
  - If the entry is missing, malformed, or deletion fails, the flow
    aborts with a `shinyOAuth_state_error`
  - Audit events are emitted on failures (e.g.,
    `state_store_lookup_failed`, `state_store_removal_failed`)
  - In multi-worker deployments, shared state stores are expected to
    provide an atomic `$take()` method for single-use semantics. Without
    that, ‘shinyOAuth’ rejects shared stores by default unless the
    operator explicitly opts into the weaker replay-risk fallback with
    `options(shinyOAuth.allow_non_atomic_state_store = TRUE)`
- Verify that user’s browser token matches the previously stored browser
  token
- Ensure PKCE components are available when required

Note: in asynchronous token exchange mode, the module may pre‑decrypt
the sealed state and prefetch plus remove the state store entry on the
main thread before handing work to the async worker, preserving the same
single‑use and strict failure behavior.

### 8. Exchange authorization code for tokens

Once the callback checks pass, the module sends the authorization code
to the token endpoint to obtain tokens.

A POST request is made to the token endpoint with
`grant_type=authorization_code`, the code, the `redirect_uri`, and the
`code_verifier` (PKCE). Client authentication depends on how the
provider expects the client to identify itself: public (`client_id`
only), HTTP Basic (`client_secret_basic`), body params
(`client_secret_post`), JWT-based assertions (`client_secret_jwt`,
`private_key_jwt`), or mTLS when configured. Most users only need to
configure the client correctly; ‘shinyOAuth’ builds the right request
from there.

When the client is configured with `dpop_private_key`, ‘shinyOAuth’ also
attaches a DPoP proof to the token request. For authorization-code
exchange and refresh, if the authorization server responds with a
`DPoP-Nonce` challenge, ‘shinyOAuth’ caches the supplied nonce and
retries the token request once with a fresh DPoP proof that includes it.
Generic transport and HTTP retries still stay disabled for these
non-idempotent token requests, so the package does not replay them
beyond that RFC 9449 nonce handshake. The response must include at least
`access_token`. Malformed or error responses abort the flow.

After a successful response, ‘shinyOAuth’ also checks two basic things:

- If the token response includes `scope`, ‘shinyOAuth’ can reconcile it
  against the requested scopes (defaults to warning on reduced grants;
  configurable via the client `scope_validation` setting)
- The token response must include `token_type`; if the provider was
  configured with a non-empty `allowed_token_types`, that value must
  also be one of the allowed types (case-insensitive, e.g., `Bearer`)

#### What changes when mTLS is enabled (RFC 8705)

When the provider uses mutual TLS
(`token_auth_style = "tls_client_auth"` or
`"self_signed_tls_client_auth"`), ‘shinyOAuth’ sends the configured
client certificate on authorization-server requests and prefers any
discovered `mtls_endpoint_aliases`.

Certificate-bound access tokens are a separate RFC 8705 policy. When the
provider advertises `tls_client_certificate_bound_access_tokens = TRUE`
and the client opts in with
`mtls_request_certificate_bound_access_tokens = TRUE`, ‘shinyOAuth’
prefers the mTLS endpoints for authorization-server requests even when
`token_auth_style` itself is not an mTLS auth style, and then treats the
resulting access tokens as sender-constrained when the binding is
observable:

- For authorization-server requests such as PAR, authorization-code
  exchange, refresh, introspection, and revocation, ‘shinyOAuth’ sends
  the configured client certificate on the TLS connection and prefers
  any discovered `mtls_endpoint_aliases`
- For protected-resource requests such as
  [`resource_req()`](https://lukakoning.github.io/shinyOAuth/reference/resource_req.md)
  calls to downstream APIs, and for userinfo when it is acting as a
  certificate-bound resource, ‘shinyOAuth’ checks that the token’s
  `cnf.x5t#S256` thumbprint matches the configured certificate before
  sending the request

If ‘shinyOAuth’ learns `cnf` by locally parsing a self-contained JWT
access token, it is only observing the token payload that the
authorization server returned; it is not independently verifying the
access-token signature. For strict assurance of sender-constrained
access tokens, prefer introspection or another provider-specific proof
surface.

#### What changes when DPoP is enabled (RFC 9449)

When the client is configured with `dpop_private_key`, ‘shinyOAuth’ adds
DPoP proofs to token requests and later protected-resource requests:

- Authorization-code exchange and refresh calls to the token endpoint
  carry a DPoP proof. If the authorization server responds with a
  `DPoP-Nonce` challenge, ‘shinyOAuth’ retries once with a fresh proof
  that includes the supplied nonce, then reuses the most recently
  learned authorization-server nonce on later token requests until the
  server rotates it
- Later
  [`get_userinfo()`](https://lukakoning.github.io/shinyOAuth/reference/get_userinfo.md)
  calls and downstream
  [`perform_resource_req()`](https://lukakoning.github.io/shinyOAuth/reference/perform_resource_req.md)
  requests also attach DPoP proofs when the effective access-token type
  is `DPoP` and the caller supplies the corresponding `OAuthClient`
  - [`perform_resource_req()`](https://lukakoning.github.io/shinyOAuth/reference/perform_resource_req.md)
    also retries one protected-resource `use_dpop_nonce` challenge with
    the supplied `DPoP-Nonce`; plain
    [`resource_req()`](https://lukakoning.github.io/shinyOAuth/reference/resource_req.md)
    only builds the request object
  - Resource-server nonces are cached per issuing server rather than per
    exact endpoint, so same-server protected-resource paths can reuse a
    nonce while token-endpoint and resource-server nonce state stay
    separate
  - If an idempotent DPoP request is retried after a transient transport
    or HTTP failure, ‘shinyOAuth’ mints a fresh proof for the retry
    instead of replaying the same proof JWT

### 9. Validate ID token (OIDC only)

When using `oauth_provider(id_token_validation = TRUE)`, the following
verifications are performed **before** any userinfo fetch. The list
below is intentionally a bit more detailed than a typical app needs day
to day; the main point is that ‘shinyOAuth’ does these checks for you
before making external calls:

- Signature: checked against the provider JWKS (with optional pinning)
  for supported asymmetric algorithms (`RS256`, `RS384`, `RS512`,
  `ES256`, `ES384`, `ES512`, `EdDSA`). HMAC algorithms
  (`HS256`/`HS384`/`HS512`) are only allowed with explicit opt-in
  (`options(shinyOAuth.allow_hs = TRUE)`) and a sufficiently strong
  server-held secret. RSA-PSS (`PS256`, `PS384`, `PS512`) is not
  currently supported
- Token format: ‘shinyOAuth’ accepts signed JWS ID tokens only.
  Encrypted ID tokens (JWE) are rejected because the package does not
  perform JWE decryption; configure the provider to return signed-only
  ID tokens
- Core claims: `iss` must match the expected issuer; `aud` must include
  `client_id`; `sub` must be present; `iat` must be a single finite
  numeric; time-based claims (`exp` is required, `nbf` optional) are
  evaluated with a small configurable leeway; tokens issued in the
  future are rejected
- JWT header type (`typ`, when present): must indicate a JWT (`JWT`,
  case-insensitive). Other values (e.g., `at+jwt`) are rejected for ID
  tokens
- Maximum ID token lifetime: `exp - iat` is checked against
  `options(shinyOAuth.max_id_token_lifetime)` (default 24 hours); tokens
  with unreasonably long lifetimes are rejected
- Authorized party (`azp`): when an ID token names multiple audiences,
  ‘shinyOAuth’ requires `azp = client_id` to keep the client binding
  explicit. If `azp` is present at all, it must equal `client_id`
- Nonce: must match the previously stored value (if configured)
- `auth_time` validation (OIDC Core §3.1.2.1): when `max_age` is present
  in `extra_auth_params`, the ID token’s `auth_time` claim must be
  present, must not be in the future beyond `leeway`, and must satisfy
  `now - auth_time <= max_age + leeway`
- `at_hash` (Access Token hash, OIDC Core §3.1.3.8): when the ID token
  contains an `at_hash` claim, the access token binding is verified.
  When `id_token_at_hash_required = TRUE` on the provider, the ID token
  must contain this claim or login fails
- Requested claims (OIDC Core §5.5): if the client requested specific
  claims via the `claims` parameter with `essential = TRUE`, `value`, or
  `values`, and `claims_validation` is `"warn"` or `"strict"`, the
  decoded ID token payload is checked for missing essential claims and
  unsatisfied requested claim values. These trigger a warning or error
  depending on the mode. For `claims$id_token`, this enforcement only
  runs after ‘shinyOAuth’ has validated the ID token; configure the
  provider with `id_token_validation = TRUE` or `use_nonce = TRUE` so
  those checks run on trusted token content. This is skipped when
  `claims_validation = "none"` (the default)
- ACR enforcement (OIDC Core §2, §3.1.2.1): if the client was created
  with `required_acr_values`, the ID token’s `acr` claim must be present
  and match one of the specified values. This ensures the provider
  performed the expected authentication context (e.g., MFA). If the
  `acr` claim is missing or not in the allowlist, login fails with a
  `shinyOAuth_id_token_error`. The authorization request also includes
  an `acr_values` parameter as a voluntary hint to the provider

### 10. Fetch userinfo (optional)

If userinfo is requested via `oauth_provider(userinfo_required = TRUE)`
(for which you should have a `userinfo_url` configured), the module
calls the userinfo endpoint with the access token and stores the
returned claims. This happens **after** ID token validation, so the
earlier token checks pass before another external call is made. If the
request fails, the flow aborts with an error.

When the access token is certificate-bound, ‘shinyOAuth’ treats the
userinfo call as protected-resource access: it uses the mTLS alias for
`userinfo_endpoint` when configured, sends the client certificate on the
TLS connection, and requires the token’s `cnf.x5t#S256` thumbprint to
match that certificate before making the request.

When a refresh response omits any new observable `cnf`, ‘shinyOAuth’
does not carry forward the previous `x5t#S256` thumbprint onto the
refreshed token. Refreshed access tokens keep mTLS sender-constrained
state only when the new token itself, or its introspection response,
supplies fresh `cnf` data.

The userinfo endpoint may return either a standard JSON response or,
less commonly, a JWT response (per OIDC Core section 5.3.2). When the
endpoint returns `Content-Type: application/jwt`, the body is verified
as a signed JWT against the provider JWKS. Only signed JWS userinfo
responses are supported. Encrypted UserInfo JWTs (JWE) are rejected;
configure the provider to return signed-only JWTs when using
`application/jwt` responses. When `userinfo_signed_jwt_required = TRUE`
on the provider, the endpoint must return `application/jwt` or the flow
is aborted. UserInfo JWT verification is limited to asymmetric
algorithms from the provider’s `allowed_algs` (`RS*`, `ES*`, or
`EdDSA`); `HS256`, `HS384`, and `HS512` are rejected on this surface
even if HS\* is otherwise enabled for ID tokens.

For security-sensitive deployments that rely on signed UserInfo JWTs,
consider requiring at least an expiry claim with
`oauth_client(userinfo_jwt_required_temporal_claims = "exp")`. OIDC Core
does not require `exp` on signed UserInfo responses, so ‘shinyOAuth’
leaves that policy opt-in and validates `exp`, `iat`, and `nbf` whenever
they are present.

- Subject match: whenever ‘shinyOAuth’ has both userinfo and a validated
  ID token baseline, it checks that `sub` in userinfo equals `sub` in
  the ID token. Setting `oauth_provider(userinfo_id_token_match = TRUE)`
  additionally makes the flow fail closed when userinfo is fetched but
  no validated ID token baseline is available
- Requested claims (OIDC Core §5.5): if the client requested specific
  userinfo claims via the `claims` parameter with `essential = TRUE`,
  `value`, or `values`, and `claims_validation` is `"warn"` or
  `"strict"`, the userinfo response is checked for missing essential
  claims and unsatisfied requested claim values. These trigger a warning
  or error depending on the mode

### 11. Build the `OAuthToken` object

Once the token response and any preceding verification steps have
succeeded, the module builds the `OAuthToken` object that your app will
work with. This happens before optional token introspection, but the
module still waits for any remaining checks before marking the session
as authenticated.

This is an S7 `OAuthToken` object which contains:

- `access_token` (string)
- `token_type` (string, e.g., `Bearer` or `DPoP`)
- `refresh_token` (optional string)
- `expires_at` (numeric timestamp, seconds since epoch; `Inf` for
  non-expiring tokens)
- `id_token` (optional string)
- `id_token_validated` (logical, indicating whether the ID token was
  cryptographically verified)
- `id_token_claims` (read-only named list exposing the decoded JWT
  payload, e.g., `sub`, `acr`, `amr`, `auth_time`)
- `cnf` (optional confirmation claim set, such as an mTLS certificate
  thumbprint)
- `granted_scopes` (normalized scope tokens currently associated with
  the access token)
- `granted_scopes_verified` (logical indicating whether the current
  token response explicitly proved those scopes)
- `userinfo` (optional list)

### 12. Token introspection (optional)

Some providers support RFC 7662 token introspection. This is an extra
server-to-server check where ‘shinyOAuth’ asks the provider whether a
token is currently active and receives related metadata.

If you enable `introspect = TRUE` when creating your
[`oauth_client()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_client.md),
the module calls the provider’s introspection endpoint after the token
object has been built and requires the response to indicate
`active = TRUE` before the session is treated as authenticated. If
introspection fails, or if the token is reported as inactive, login
stops and `$authenticated` is not set to `TRUE`.

You can optionally ask ‘shinyOAuth’ to check additional
provider-dependent fields via `oauth_client(introspect_elements = ...)`:

- `"sub"` – require introspection `sub` to match the session subject
- `"client_id"` – require introspection `client_id` to match your OAuth
  client id
- `"scope"` – validate introspection `scope` against requested scopes
  (respects the client’s `scope_validation` mode)

Note that not all providers may return each of these fields in
introspection responses.

### 13. Mark session as authenticated

The `$authenticated` value as returned by
[`oauth_module_server()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_module_server.md)
now becomes TRUE, meaning all requested verifications have passed.

### 14. Clean URL & tidy UI; clear browser token

The user’s browser was redirected to your app with OAuth 2.0 query
parameters (`code`, `state`, etc.). To keep the URL cleaner and avoid
leaving sensitive values in the address bar, these values are removed
with JavaScript. Optionally, the page title may also be adjusted (see
the `tab_title_` arguments in
[`oauth_module_server()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_module_server.md)).

The browser token cookie is also cleared and immediately re-issued with
a fresh value, so a future flow starts with a new per-session token.

### 15. Post-flow session management

Once login is complete, the module manages token lifetime during the
active session. Depending on your settings, that may include:

- Proactive refresh: if enabled via
  `oauth_module_server(refresh_proactively = TRUE)` and a refresh token
  exists, the access token is refreshed before expiry
- Expiration: expired tokens are cleared automatically, setting the
  `$authenticated` flag to FALSE
- Re-authentication: optionally,
  `oauth_module_server(reauth_after_seconds = ...)` can force periodic
  re-authentication

#### Refresh behavior (`refresh_token()`)

When the module refreshes a session, or when you call
[`refresh_token()`](https://lukakoning.github.io/shinyOAuth/reference/refresh_token.md)
directly, it performs an OAuth 2.0 refresh-token grant against the
provider’s token endpoint and updates the `OAuthToken` object. In short:

- A token request is sent with `grant_type=refresh_token` and the
  current `refresh_token`
- When DPoP is enabled and the token endpoint responds with
  `DPoP-Nonce`, ‘shinyOAuth’ retries the refresh request once with a
  fresh proof that includes that nonce
- The response must include a new `access_token`. `expires_at` is
  updated from `expires_in` when present; otherwise ‘shinyOAuth’
  synthesizes a finite fallback lifetime (default `3600` seconds,
  configurable via `options(shinyOAuth.default_expires_in = ...)`)
- If the provider rotates the refresh token (returns a new
  `refresh_token`), it is stored; otherwise the original is preserved
- If `oauth_provider(userinfo_required = TRUE)`, userinfo is re-fetched
  using the fresh access token
- If `oauth_client(introspect = TRUE)`, the refreshed access token is
  introspected through the same client policy before the session is
  updated

When the refresh response omits new observable `cnf`, ‘shinyOAuth’ does
not carry forward the previous certificate thumbprint onto the refreshed
token. Refreshed access tokens keep mTLS sender-constrained state only
when the new token itself, or its introspection response, supplies fresh
`cnf` data.

If you are running a security-sensitive app, set
`options(shinyOAuth.default_expires_in = ...)` to the provider’s
documented lifetime instead of relying on the package default, and
consider `oauth_module_server(reauth_after_seconds = ...)` when you need
a hard upper bound on session age.

Refresh can behave a little differently for OIDC ID tokens:

- Per OIDC Core Section 12.2, refresh responses may omit `id_token`.
  When that happens, ‘shinyOAuth’ keeps the original `id_token`, so
  refresh does not necessarily revalidate identity
- If the provider does return an `id_token` during refresh, ‘shinyOAuth’
  enforces OIDC 12.2 subject continuity: the refresh-returned `id_token`
  must have the same `sub` as the original `id_token` from login
  - If an original `id_token` did not exist in the session, and the
    refresh does return one, the refresh fails (cannot establish subject
    claim match with no baseline)
  - If `id_token_validation = TRUE`, the refresh-returned `id_token` is
    fully validated (signature + claims); the `sub` claim match is
    enforced as part of validation
  - If `id_token_validation = FALSE`, ‘shinyOAuth’ still enforces the
    `sub` match by parsing the JWT payload (ensuring that the `sub`
    claim still matches but without full validation)
  - In both validation paths, `iss` and `aud` claims in the refreshed ID
    token are compared against the original ID token’s values (not just
    the provider configuration) per OIDC Core Section 12.2, to cover
    edge cases with multi-tenant providers or rotating issuer URIs
  - ‘shinyOAuth’ also enforces continuity for `auth_time` when the
    original ID token had it, rejects a refreshed `nonce` when it
    changes, and requires `azp` to match when either token carries it

If refresh fails inside
[`oauth_module_server()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_module_server.md),
the module exposes the failure through its reactive state (for example,
`auth$error == "token_refresh_error"` plus `auth$error_description`). By
default it also clears the current session token; if
`oauth_module_server(indefinite_session = TRUE)`, the token is kept and
`auth$token_stale` becomes `TRUE`. In the default mode, `$authenticated`
becomes `FALSE` while the error is present. With
`indefinite_session = TRUE`, `$authenticated` stays `TRUE` even if a
refresh error is present.

### 16. Logout and token revocation

When `auth$logout()` is called, the module:

1.  Attempts to revoke both refresh and access tokens at the provider
    (RFC 7009) if a `revocation_url` is configured. This runs
    asynchronously only when `oauth_module_server(async = TRUE)`
2.  Clears the local session (`OAuthToken`, browser cookie)
3.  Emits a `"logout"` audit event
4.  Re-issues a fresh browser token for subsequent logins

You can also revoke tokens directly via
`revoke_token(client, token, which = "refresh")`.

To automatically attempt revocation when a Shiny session ends (for
example, a tab close or session timeout), set
`revoke_on_session_end = TRUE`:

This requires the provider to have a configured `revocation_url`;
otherwise
[`oauth_module_server()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_module_server.md)
rejects `revoke_on_session_end = TRUE` at startup.

``` r
auth <- oauth_module_server(
  "auth",
  client = client,
  revoke_on_session_end = TRUE
)
```

This is best-effort: the session may end while the provider is
unavailable, and revocation failures do not block local session cleanup.
