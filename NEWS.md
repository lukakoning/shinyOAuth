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
