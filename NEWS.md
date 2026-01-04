# shinyOAuth (development version)

## New

* Token revocation: tokens can now be revoked when Shiny session ends. Enable 
via `revoke_on_session_end = TRUE` in `oauth_module_server()`. The provider must
expose a `revocation_url` (auto-discovered for OIDC, or set manually via 
`oauth_provider()`). New exported function `revoke_token()`.

* Token introspection on login: validate tokens via the provider's introspection 
endpoint during login. Configure via `introspect` and `introspect_elements` 
properties on `OAuthClient`. The provider must expose an `introspection_url` 
(auto-discovered for OIDC, or set manually via `oauth_provider()`). 

* Configurable scope validation: `validate_scopes` property on `OAuthClient` 
controls whether returned scopes are validated against requested scopes 
(`"strict"`, `"warn"`, or `"none"`). Scopes are now normalized (alphabetically 
sorted) before comparison.

* Audit events: `session_ended` (logged on Shiny session close),
`authenticated_changed` (logged when authentication status changes),
`token_introspection` (when `introspect_token()` is used), `token_revocation`
(when `revoke_token()` is used), `error_state_consumed` and 
`error_state_consumption_failed` (called when provider returns an error during 
callback handling and the state is attempted to be consumed).

* `client_assertion_audience` property on `OAuthClient` allows overriding the 
JWT audience claim for client assertion authentication.

* `state_max_age` property on `OAuthClient` for independent freshness validation 
of the state payload's `issued_at` timestamp.

## Improved

### Security

* `OAuthProvider` now requires absolute URLs (scheme + hostname) for all 
endpoint URLs.

* DoS protection: callback query parameters and state payload/browser token 
sizes are validated before expensive operations (e.g., hashing for audit logs).

* HTTP log sanitization: sensitive data in HTTP contexts (headers, cookies) is
now sanitized by default in audit logs. Can be disabled with 
`options(shinyOAuth.audit_redact_http = FALSE)`. Use 
`options(shinyOAuth.audit_include_http = FALSE)` to not include any HTTP data in
logs.

* Rate-limited JWKS refresh: forced JWKS cache refreshes (triggered by unknown 
`kid`) are now rate-limited to prevent abuse.

* `use_shinyOAuth()` now injects `<meta name="referrer" content="no-referrer">` 
by default to reduce leaking ?code=...&state=... via the Referer header on the 
callback page. Can be disabled with
`use_shinyOAuth(inject_referrer_meta = FALSE)`.

* State is now also consumed on OAuth error responses, preventing re-use.

* Default client assertion JWT TTL reduced from 5 minutes to 60 seconds.

* Callback URL parameters are now also cleared in login failure paths (not just 
success).

* Extra authorization URL parameters are now blocked from overriding reserved 
OAuth keys.

* Provider fingerprint now includes `userinfo_url` and `introspection_url`.

* `oauth_provider()` now defaults `allowed_token_types` to `c("Bearer")` for all
providers. This prevents accidentally misusing non-Bearer tokens (e.g., DPoP, 
MAC) as Bearer tokens. Set `allowed_token_types = character()` to opt out.

### UX

* Added warning about negative `expires_in` values in token responses.

* Added warning when `OAuthClient` is instantiated inside a Shiny session; may 
cause sealed satte payload decryption to fail when random secret is generated
upon client creation.

* Added hints in error messages when sealed state payload decryption fails.

* Ensured a clearer error message when token response is in unexpected format.

* Ensured a clearer error message when retrieved userinfo cannot be parsed as JSON.

* Immediate error when `OAuthProvider` uses `HS*` algorithm but 
`allow_symmetric_alg` is not enabled; also immediate error when `OAuthProvider`
uses `HS*` algorithm and ID token verification can happen but `client_secret` is
absent or too weak.

### Other

* When fetching JWKS, if `key_ops` is present on keys, only keys with `key_ops` 
including `"verify"` are considered.

* Token type is now validated before making a call to the userinfo endpoint.

## Fixed

* Package now correctly requires `httr2` >= 1.1.0.

* HTTP error responses (4xx/5xx) are now correctly returned to the caller 
immediately instead of being misclassified as transport errors and retried.

* `oauth_provider_microsoft()`: fixed incorrect default which blocked 
multi-tenant configuration.

* `oauth_provider_oidc_discover()`: stricter host matching; `?` and `*` 
wildcards now correctly handled.

* Token expiry handling during token refresh now aligns with how it is handled
during login.

* Fixed potential auto-redirect loop after authentication error has surfaced.

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
