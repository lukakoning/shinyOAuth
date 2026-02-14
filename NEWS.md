# shinyOAuth 0.4.0

* 'mirai' & async backend improvements:
  - Warnings and messages emitted in async workers (e.g., missing `expires_in`
  from token response) are now captured and re-emitted on the main process so
  they appear in the R console. This includes conditions from user-supplied
  `trace_hook` / `audit_hook` functions: warnings, messages, and errors 
  (surfaced as warnings) all propagate back to the main thread. Replay can be
  disabled via `options(shinyOAuth.replay_async_conditions = FALSE)`.
  - Async callback flow no longer serializes the full client object (including
  potentially non-serializable custom `state_store` / JWKS cache backends)
  into the worker context. The `state_store` (already consumed on the main
  thread) is replaced with a lightweight serializable dummy before dispatch.
  If the client still fails serialization, the flow falls back to synchronous
  execution with an explicit warning instead of an opaque runtime error.
  - Further reduced serialization overhead towards async workers by using 
  certain functions from the package namespace directly.
  - Detect active daemons via `mirai::daemons_set()` instead of 
  `mirai::status()`. Falls back to `mirai::info()` on older 'mirai' versions
  that lack `mirai::daemons_set()` (< 2.3.0).
  - Configurable per-task timeout via `options(shinyOAuth.async_timeout)` 
  (milliseconds); timed-out 'mirai' tasks are automatically cancelled by the
  dispatcher. Default is `NULL` (no timeout).
  - Async audit events now include a `mirai_error_type` field. This classifies 
  mirai transport-level failures separately from application-level errors.
  - Prevent 'mirai' warning spam about 'stats' maybe not being available in 
  workers.

* ID token validation (`validate_id_token()`):
  - Now enforces RFC 7515 section 4.1.11 critical header
  parameter (`crit`) processing rules. Tokens containing unsupported critical 
  extensions are rejected with a `shinyOAuth_id_token_error`. The current
  implementation supports no critical extensions, so any `crit` presence 
  triggers rejection.
  - Now validates the `at_hash` (Access Token hash) claim
  when present in the ID token (per OIDC Core section 3.1.3.8 and 3.2.2.9). If 
  the claim exists, the access token binding is verified; a mismatch raises a 
  `shinyOAuth_id_token_error`. New `id_token_at_hash_required` property on 
  `OAuthProvider` (default `FALSE`) forces login to fail when the ID token does 
  not contain an `at_hash` claim.
  - Now validates, for refreshed ID tokens, per OIDC Core section 12.2, `iss`
  and `aud` claims against the original ID token's values (not just the provider
  configuration) to cover edge cases with multi-tenant providers or rotating
  issuer URIs. Enforced in both validated and non-validated code paths.
  - Now detects encrypted ID tokens (JWE compact serialization, 5 dot-separated 
  segments) early and raises a clear `shinyOAuth_id_token_error` instead of 
  letting a confusing alg/typ/parse failure propagate.
  - Now validates the `auth_time` claim when `max_age` is
  present in `extra_auth_params` (OIDC Core section 3.1.2.1).
  - Now enforces a maximum ID token lifetime (`exp - iat`) per OIDC Core
  section 3.1.3.7; tokens with unreasonably long lifetimes are rejected with a
  `shinyOAuth_id_token_error`. Configure via
  `options(shinyOAuth.max_id_token_lifetime = <seconds>)` (default of `86400`
  which is 24 hours). Set to `Inf` to disable the check.
  
* Stricter state store usage:
  - `custom_cache()` gains an optional `take` parameter for atomic get-and-delete.
  - `state_store_get_remove()` prefers `$take()` when available; falls back to
    `$get()` + `$remove()` with a mandatory post-removal absence check (instead
    of trusting `$remove()` return values).
  - Non-`cachem::cache_mem()` stores without `$take()` now error by default
    to prevent TOCTOU replay attacks in shared/multi-worker deployments. 
    To bypass this error, operators must explicitly acknowledge the risk by 
    setting `options(shinyOAuth.allow_non_atomic_state_store = TRUE)`, which
    downgrades the error to a warning.
  - `OAuthClient` validator now validates `$take()` signature when present.
  - The `$remove()` return value is no longer relied upon in the fallback path;
    the post-removal `$get()` absence check is authoritative.

* Stricter JWKS cache handling: JWKS cache key now includes host-policy fields
(`jwks_host_issuer_match`, `jwks_host_allow_only`). Previously, two provider
configs for the same issuer with different host policies shared the same cache
entry, allowing a relaxed-policy provider to populate the cache and a
strict-policy provider to skip host validation on cache hit. Cache entries now
also store the JWKS source host and re-validate it against the current
provider policy on read (defense-in-depth).

* Stricter URL validation: `OAuthClient` now rejects redirect URIs containing 
fragments (per RFC 6749, section 3.1.2); `OAuthProvider` now rejects issuer 
identifiers containing query or fragment components, covering both 
`oauth_provider_oidc_discover()` and manual construction of providers.

* Stricter state payload parsing: callback `state` now rejects embedded NUL
bytes before JSON decoding.

* Stricter response size validation: enforce max response body size on all 
outbound HTTP endpoints (token, introspection, userinfo, OIDC discovery, JWKS).
Curl aborts the transfer early when `Content-Length` exceeds the limit; a 
post-download guard catches chunked responses. Default 1 MiB, configurable via
`options(shinyOAuth.max_body_bytes)`.

* `OAuthProvider` (S7 class):
  - `leeway` validator now rejects non-finite values (`Inf`, 
  `-Inf`, `NaN`). Previously these passed validation but were silently coerced 
  to 0 at runtime, effectively disabling clock-skew tolerance.
  - Reserved OAuth parameter blocking in `extra_auth_params` and 
  `extra_token_params` is now case-insensitive and trims whitespace. 
  - Vector inputs for `pkce_method` and URL parameters (`auth_url`, `token_url`, 
  `userinfo_url`, `introspection_url`, `revocation_url`) now produce clear 
  scalar-input errors instead of cryptic coercion failures.

* `OAuthClient` (S7 class):
  - Gains a `claims_validation` property; when the client sends a structured 
  `claims` request parameter with `essential = TRUE` entries, this setting
  controls whether the returned ID token and/or userinfo response are checked 
  for those essential claims (similar to `scope_validation`).
  - Gains a `required_acr_values` property; enables client-side
  enforcement of the OIDC `acr` (Authentication Context Class Reference) claim.
  - `extra_token_headers` are now consistently applied to revoke
  and introspect requests, matching the existing behavior for token exchange and 
  refresh. Previously, provider integrations requiring custom headers across all
  token endpoints could partially fail on revocation/introspection.
  - Fixed incorrect warning about client being created in Shiny when this was
  not the case.
  - Malformed `client_assertion_alg` and `client_assertion_audience` values
  (e.g., `character(0)`, multi-element vectors) now produce clear validation 
  errors instead of crashing with base R subscript-out-of-bounds errors. Empty 
  string `""` for `client_assertion_audience` is now explicitly rejected instead 
  of being silently treated as "not provided".

* `OAuthToken` (S7 class):
  - Gains a read-only `id_token_claims` property that exposes the
  decoded ID token JWT payload as a named list, surfacing all OIDC claims
  (e.g., `acr`, `amr`, `auth_time`) without manual decoding.
  - Gains an `id_token_validated` property (logical) indicating whether the ID 
  token was cryptographically verified during the OAuth flow.

* `oauth_module_server()`: 
  - Now surfaces `error_uri` from provider error
  callbacks (RFC 6749, section 4.1.2.1). The new `$error_uri` reactive field
  contains the URI to a human-readable error page when the provider includes 
  one; `NULL` otherwise. The `error_uri` callback parameter is also validated
  against a configurable size limit
  (e.g., `options(shinyOAuth.callback_max_error_uri_bytes = 2048)`).
  - OAuth callback query cleanup is now also applied in early 
  return paths of internal function `.process_query()`, ensuring more consistent
  cleanup.
  * OAuth callback query size caps are now enforced even when the user is
  already authenticated. Previously, the "token already present" branch in
  `.process_query()` called `.query_has_oauth_callback_keys()` (which parses
  the query string) before any size validation, bypassing the intended DoS
  guardrails. The `validate_untrusted_query_string()` check now runs
  unconditionally at the top of `.process_query()`.
  - OAuth callback error responses (`?error=...`) now 
  require a valid `state` parameter. Missing/invalid/consumed state is then
  treated properly as an `invalid_state` error instead of surfacing the error 
  from `?error=...` (which could be set by an attacker).
  - OAuth callback including an `iss` query parameter now validate this against 
  the provider's configured/discovered issuer during callback processing 
  (complementing the existing ID token `iss` claim validation that occurs 
  post-exchange) (per RFC 9207). A mismatch produces an `issuer_mismatch` error 
  and audit event, defending against authorization-server mix-up attacks in
  multi-provider scenarios. When `iss` is absent, current behavior is retained 
  (no enforcement).

* `handle_callback()`: no longer accepts `decrypted_payload` and
`state_store_values` bypass parameters. These parameters were only intended for
internal use by `oauth_module_server()`'s async path. As they can be misused by
direct/custom callers to bypass important security checks, they have been
moved to an internal-only helper function (`handle_callback_internal()`).

* `handle_callback()`/`refresh_token()`: when a token response omits 
`expires_in`, a warning is now emitted once per phase (`exchange_code` / 
`refresh_token`) so operators know that proactive token refresh will not
trigger. Users can now also set a finite default lifetime for such tokens via
`options(shinyOAuth.default_expires_in = <seconds>)` (instead of the default of 
`Inf`).

* `get_userinfo()` now supports JWT-encoded userinfo responses per OIDC Core,
section 5.3.2. When the endpoint returns `Content-Type: application/jwt`, the 
body is decoded as a JWT. Verification is fail-closed: signature verification is
always performed against the provider JWKS using the provider's `allowed_algs`, 
`alg=none` is always rejected, and unparseable headers, non-asymmetric
algorithms, or missing issuer/JWKS infrastructure all raise errors. 
`options(shinyOAuth.allow_unsigned_userinfo_jwt = TRUE)` permits unsigned
JWTs. New `userinfo_signed_jwt_required` property on `OAuthProvider`
(default `FALSE`) mandates that the userinfo endpoint returns
`application/jwt` content-type which is then subject to the above verification.

* `client_bearer_req()` now validates the target URL against `is_ok_host()`
before attaching the Bearer token. Relative URLs, plain HTTP to non-loopback
hosts, and hosts outside `options(shinyOAuth.allowed_hosts)` are rejected by
default. A new `check_url` argument (default `TRUE`) allows opting out of
the check when the URL has already been validated.

* `err_http()` now extracts RFC 6749 section 5.2 structured error fields 
(`error`, `error_description`, `error_uri`) from JSON error response bodies. 
These fields are surfaced in the error message bullets, attached to the 
condition object (as `oauth_error`, `oauth_error_description`, 
`oauth_error_uri`), and included in trace/audit events. This improves debugging
of token endpoint failures (e.g. `invalid_grant`, `invalid_client`) without
changing existing control flow.

* OIDC `claims` parameter support (OIDC Core, section 5.5): `OAuthClient` and 
`oauth_client()` now accept a `claims` argument to request specific claims 
from the userinfo Endpoint and/or in the ID token. Pass a list structure 
(automatically JSON-encoded) or a pre-encoded JSON string.

* OIDC `openid` scope enforcement: when a provider has an `issuer` set
(indicating OIDC) and `openid` is missing from the client's scopes,
`build_auth_url()` now auto-prepends it and emits a one-time warning.

* OIDC discovery (`oauth_provider_oidc_discover()`) now prefers confidential
auth methods (`client_secret_basic`, `client_secret_post`) over `none` when
both are advertised in `token_endpoint_auth_methods_supported`. Previously,
mixed metadata (e.g. `none` + `client_secret_basic`) with PKCE enabled would
silently select the public-client posture (`"body"` without credentials).

* Scope validation now aligns with the RFC 6749, section 3.3 `scope-token` 
grammar (`NQSCHAR = %x21 / %x23-5B / %x5D-7E`). The previous regex rejected 
valid ASCII characters such as `!`, `#`, `$`, `=`, `@`, `~`, and others. All
printable ASCII except space, double-quote, and backslash is now accepted.

- JWT helpers (`build_client_assertion()`, 
`resolve_client_assertion_audience()`) now have defense-in-depth scalar guards 
so malformed property values cannot cause subscript errors at runtime.

* Audit events:
  - `audit_token_refresh`: replaced non-informative `had_refresh_token` field 
  (always `TRUE` post-mutation) with `refresh_token_rotated` (indicates whether 
  the provider returned a new refresh token).

# shinyOAuth 0.3.0

* Async backend: the default async backend is now 'mirai' (>= 2.0.0) for
simpler and more efficient asynchronous execution. Use `mirai::daemons()` to
configure async workers. A 'future' backend configured with `future::plan()`
is still supported, but 'mirai' takes precedence if both are configured.

* Test suite: fixed inconsistent results of several tests; tests not suitable
for CRAN now skip on CRAN. Silenced test output messages to avoid confusion.

# shinyOAuth 0.2.0

## New/improved

### Security

* Token revocation: tokens can now be revoked when Shiny session ends. Enable 
via `revoke_on_session_end = TRUE` in `oauth_module_server()`. The provider must
expose a `revocation_url` (auto-discovered for OIDC, or set manually via 
`oauth_provider()`). New exported function `revoke_token()`.

* Token introspection on login: validate tokens via the provider's introspection 
endpoint during login. Configure via `introspect` and `introspect_elements` 
properties on `OAuthClient`. The provider must expose an `introspection_url` 
(auto-discovered for OIDC, or set manually via `oauth_provider()`). 

* DoS protection: callback query parameters and state payload/browser token 
sizes are validated before expensive operations (e.g., hashing for audit logs).
Maximum size may be configured via `options()`; see section 'Size caps' in 
`vignette("usage", package = "shinyOAuth")`.

* DoS protection: rate-limited JWKS refresh: forced JWKS cache refreshes (triggered by unknown 
`kid`) are now rate-limited to prevent abuse.

* JWKS pinning: pinning is now enforced during signature verification: previously, 
`jwks_pins` with `jwks_pin_mode = "any"` only verified that at least one key 
in the JWKS matched a pin, but signature verification could still use any 
matching key (pinned or not). Now, signature verification is restricted to 
only use keys whose thumbprints appear in the pin list, ensuring true key 
pinning rather than presence-only checks.

* `use_shinyOAuth()` now injects `<meta name="referrer" content="no-referrer">` 
by default to reduce leaking ?code=...&state=... via the Referer header on the 
callback page. Can be disabled with
`use_shinyOAuth(inject_referrer_meta = FALSE)`.

* Sensitive outbound HTTP requests (token exchange/refresh, introspection,
revocation, userinfo, OIDC discovery, JWKS) now by default disable redirect 
following and reject 3xx responses to prevent bypassing host/HTTPS policies. 
Configurable via `options(shinyOAuth.allow_redirect = TRUE)`. `client_bearer_req()`
also gains `follow_redirect`, which defaults to `FALSE`, to similarly control redirect
behavior for requests using bearer tokens.

* State is now also consumed in login failure paths (when the provider
returns an error but also a state).

* Callback URL parameters are now also cleared in login failure paths.

* `OAuthProvider` now requires absolute URLs (scheme + hostname) for all 
endpoint URLs.

* Provider fingerprint now includes `userinfo_url` and `introspection_url`,
reducing risk of misconfiguration when multiple providers share endpoints.

* `state_payload_max_age` property on `OAuthClient` for independent freshness validation 
of the state payload's `issued_at` timestamp.

* Default client assertion JWT TTL reduced from 5 minutes to 120 seconds,
reducing the window for replay attacks while allowing for clock skew.

### Auditing

* New audit events: `session_ended` (logged on Shiny session close),
`authenticated_changed` (logged when authentication status changes),
`token_introspection` (when `introspect_token()` is used), `token_revocation`
(when `revoke_token()` is used), `error_state_consumed` and 
`error_state_consumption_failed` (called when provider returns an error during 
callback handling and the state is attempted to be consumed).

* All audit events now include `$process_id`, `$is_async`, and `$main_process_id`
(if called from an async worker); these fields help identify which process
generated the event and whether it was from an async worker. Async
workers now also properly propagate audit hooks from the main process (see 'Fixed').

* Audit event `login_success` now includes `sub_source` to indicate whether the
subject digest came from `userinfo`, `id_token` (verified), or `id_token_unverified`.

* Audit digest keying: audit/event digests (e.g., `sub_digest`, `browser_token_digest`)
now default to HMAC-SHA256 with an auto-generated per-process key to reduce
reidentification/correlation risk if logs leak. Configure a key with
`options(shinyOAuth.audit_digest_key = "...")`, or disable keying (legacy deterministic
SHA-256) with `options(shinyOAuth.audit_digest_key = FALSE)`.

* HTTP log sanitization: sensitive data in HTTP contexts (headers, cookies) is
now sanitized by default in audit logs. Can be disabled with 
`options(shinyOAuth.audit_redact_http = FALSE)`. Use 
`options(shinyOAuth.audit_include_http = FALSE)` to not include any HTTP data in
logs.

### UX

* Configurable scope validation: `validate_scopes` property on `OAuthClient` 
controls whether returned scopes are validated against requested scopes 
(`"strict"`, `"warn"`, or `"none"`). Scopes are now normalized (alphabetically 
sorted) before comparison.

* `OAuthProvider`: extra parameters are now blocked from overriding reserved keys
essential for the OAuth 2.0/OIDC flow. Reserved keys may be explicitly overridden via
`options(shinyOAuth.unblock_auth_params = c(...), shinyOAuth.unblock_token_params = c(...),
shinyOAuth.unblock_token_headers = c(...))`. It is also validated early that
all parameters are named, catching configuration errors sooner.

* Added warning about negative `expires_in` values in token responses.

* Added warning when `OAuthClient` is instantiated inside a Shiny session; may 
cause sealed state payload decryption to fail when random secret is generated
upon client creation.

* Added hints in error messages when sealed state payload decryption fails.

* Ensured a clearer error message when token response is in unexpected format.

* Ensured a clearer error when retrieved state store entry is in unexpected format.

* Ensured a clearer error message when retrieved userinfo cannot be parsed as JSON.

* Immediate error when `OAuthProvider` uses `HS*` algorithm but 
`options(shinyOAuth.allow_hs = TRUE)` is not enabled; also immediate error when `OAuthProvider`
uses `HS*` algorithm and ID token verification can happen but `client_secret` is
absent or too weak.

* `build_auth_url()` now uses package-typed errors (`err_invalid_state()`) 
instead of generic `stopifnot()` assertions, ensuring consistent error 
handling and audit logging.

### Other

* ID token signature/claims validation now occurs before fetching
userinfo. This ensures cryptographic validation passes before making external
calls to the userinfo endpoint.

* When fetching JWKS, if `key_ops` is present on keys, only keys with `key_ops` 
including `"verify"` are considered.

* `oauth_provider()` now defaults `allowed_token_types` to `c("Bearer")` for all
providers. This prevents accidentally misusing non-Bearer tokens (e.g., DPoP, 
MAC) as Bearer tokens. Set `allowed_token_types = character()` to opt out.
Token type is also now validated before calling the userinfo endpoint.

* `client_assertion_audience` property on `OAuthClient` allows overriding the 
JWT audience claim for client assertion authentication.

## Fixed

* Package now correctly requires `httr2` >= 1.1.0.

* `authenticated` now flips to `FALSE` promptly when a token expires or 
`reauth_after_seconds` elapses, even without other reactive changes. Previously, 
the value could remain `TRUE` past expiry until an unrelated reactive update 
triggered re-evaluation.

* HTTP error responses (4xx/5xx) are now correctly returned to the caller 
immediately instead of being misclassified as transport errors and retried.

* Async worker options propagation: all R options are now automatically 
propagated to async workers when using `async = TRUE`. Previously, options set 
in the main process (including `audit_hook`, `trace_hook`, HTTP settings, and 
any custom options) were not available in `future::multisession` workers.

* `oauth_provider_microsoft()`: fixed incorrect default which blocked 
multi-tenant configuration.

* `oauth_provider_oidc_discover()`: stricter host matching; `?` and `*` 
wildcards now correctly handled.

* Fixed potential auto-redirect loop after authentication error has surfaced.

* Fixed potential race condition between proactive refresh and expiry watcher: 
the expiry watcher now defers clearing the token and triggering reauthentication 
while a refresh is in progress.

* Token expiry handling during token refresh now aligns with how it is handled
during login.

* State payload `issued_at` validation now applies clock drift leeway (from 
`OAuthProvider@leeway` / `shinyOAuth.leeway` option), consistent with ID token 
`iat` check.

# shinyOAuth 0.1.4

* Added a console warning about needing to access Shiny apps with
`oauth_module_server()` in a regular browser; also updated examples and vignettes
to further clarify this.

* `oauth_module_server()`: improved formatting style of warning messages
(now consistent with error messages).

# shinyOAuth 0.1.3

* Rewrote `vignette("authentication-flow")` to improve clarity.

* Skip timing-sensitive tests on CRAN.

# shinyOAuth 0.1.1

* Initial CRAN submission.
