# Authentication flow

## Overview

This vignette provides a step-by-step description of what happens during
an authentication flow when using the
[`oauth_module_server()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_module_server.md)
Shiny module. It maps protocol concepts (OAuth 2.0 Authorization Code +
PKCE, OpenID Connect) to the concrete implementation details in the
package.

For a concise quick-start (minimal and manual button examples, options,
and security checklist) see:
[`vignette("usage", package = "shinyOAuth")`](https://lukakoning.github.io/shinyOAuth/articles/usage.md).

For an explanation of logging key events during the flow, see:
[`vignette("audit-logging", package = "shinyOAuth")`](https://lukakoning.github.io/shinyOAuth/articles/audit-logging.md).

## What happens during the authentication flow?

The package implements the OAuth 2.0 Authorization Code flow (with PKCE)
and optional OpenID Connect checks end‑to‑end. Below is the sequence of
operations and the rationale behind each step.

### 1. First page load: set a browser token

On the first load of your app, the module sets a small random cookie in
the user’s browser (SameSite=Strict; Secure when over HTTPS). This
*browser token* is mirrored to Shiny as an input. It helps bind the
start and end of the OAuth flow to the same browser (a “double-submit”
style CSRF defense) and prevents cross-tab confusion.

### 2. Decide whether to start login

If `oauth_module_server(auto_redirect = TRUE)`, an unauthenticated
session triggers immediate redirection. If
`oauth_module_server(auto_redirect = FALSE)`, you manually call
`$request_login()` (e.g., via a button) to begin the flow.

### 3. Build the authorization URL (`prepare_call()`)

The authorization request contains multiple high-entropy and contextual
elements:

- State: high-entropy random string to prevent CSRF; *sealed* before
  being sent
- PKCE: a `code_verifier` (random) and `code_challenge` (S256 hash)
  proving the same party finishes the flow
- Nonce (OIDC): random string echoed back in the ID token, mitigating
  replay attacks
- Server-side one-time state store: keyed by a cache-safe hash of the
  raw state (derived from the state to satisfy cache backends); stores:
  browser token, code_verifier, nonce. Purged after callback
- Sealed state payload: instead of sending raw state, the package seals
  (AES-GCM AEAD: encrypts + authenticates) a payload containing:
  - state, client_id, redirect_uri
  - requested scopes
  - provider fingerprint (issuer/auth/token URLs)
  - issued_at timestamp

This sealing prevents tampering, stale callbacks, and mix-ups with other
providers/clients.

### 4. App redirects to the provider

The browser of the app user will be redirected to the provider’s
authorization endpoint with the following parameters:
`response_type=code`, `client_id`, `redirect_uri`, `state=<sealed>`,
PKCE parameters, `nonce` (OIDC), `scope`, plus any configured extra
parameters.

### 5. User authenticates and authorizes

Once at the provider’s authorization page, the user is prompted to log
in and authorize the app to access the requested scopes.

### 6. Provider redirects back

The provider redirects the user’s browser back to your Shiny app (your
`redirect_uri`), including the `code` and `state` parameters (and
optionally `error` and `error_description` on failure).

### 7. Callback processing & state verification (`handle_callback()`)

- Wait for the browser token input if not yet visible (page load race)
  before proceeding
- Decrypt + verify sealed state: integrity (auth tag), authenticity, and
  freshness (issued_at window)
- Check embedded context matches expected client/provider (defends
  against misconfiguration / multi-tenant mix-ups)
- Fetch and immediately delete the one-time state entry from the
  configured state store
  - Strict semantics: if the entry is missing, malformed, or deletion
    fails, the flow aborts with a `shinyOAuth_state_error`
  - Audit events are emitted on failures (e.g.,
    `audit_state_store_lookup_failed`,
    `audit_state_store_removal_failed`) with redacted context
- Verify browser token equality with stored value
- Ensure PKCE components are available when required

Note: In asynchronous token exchange mode, the module may pre‑decrypt
the sealed state and prefetch+remove the state store entry on the main
thread before handing work to the async worker, preserving the same
single‑use and strict failure behavior.

### 8. Exchange authorization code for tokens

A POST request is made to the token endpoint with
`grant_type=authorization_code`, code, redirect_uri, and `code_verifier`
(PKCE). Client authentication method depends on provider style: HTTP
Basic header (`client_secret_basic`), body params
(`client_secret_post`), or JWT-based assertions (`client_secret_jwt`,
`private_key_jwt`) when configured. The response must include at least
`access_token`. Malformed or error responses abort the flow. When
successful, the package also applies two safety rails:

- If the token response includes `scope`, all scopes requested by the
  client must be present in the granted set; otherwise the flow fails
  fast to avoid downstream surprises.
- If the token response includes `token_type`, and the provider was
  configured with `allowed_token_types`, the `token_type` must be
  present in the response and be one of the allowed types (e.g.,
  `Bearer`). Failure aborts the flow.

### 9. (Optional) Fetch userinfo

If `oauth_provider(userinfo_required = TRUE)`, the module calls the
userinfo endpoint with the access token and stores returned claims.
Failure aborts the flow.

### 10. (OIDC) Validate ID token

When using `oauth_provider(id_token_validation = TRUE)`, the following
verifications are performed:

- Signature: verified against provider JWKS (with optional thumbprint
  pinning) for RS256/ES256; HS256 only with explicit opt-in and
  server-held secret
- Claims: `iss` matches expected issuer; `aud` vector contains
  `client_id`; `sub` present; `iat` is REQUIRED and must be a single
  finite numeric; time-based claims (`exp` REQUIRED, `nbf` optional) are
  evaluated with a small configurable leeway; tokens issued in the
  future are rejected
- Nonce: if used, matches stored value
- Subject match: If `oauth_provider(userinfo_id_token_match = TRUE)`,
  ensure `sub` in userinfo equals ID token `sub`

### 11. Materialize the `OAuthToken`

Constructs an S7 `OAuthToken` capturing `access_token`, optional
`refresh_token`, expiry time, `id_token`, `userinfo`, and verification
results. `$authenticated` becomes TRUE only after all requested
verifications pass.

### 12. Clean URL & tidy UI

Removes OAuth query parameters (`code`, `state`, etc.) from the
browser’s address bar and optionally adjusts the page title. Clears the
browser token cookie to allow a fresh future flow.

### 13. Keeping the session alive

- Proactive refresh: if enabled and a refresh token exists, refresh
  before expiry.
- Expiration & reauth: expired tokens are cleared. Optional
  `oauth_module_server(reauth_after_seconds = ...)` forces periodic
  re-authentication.

### 14. Errors, logging, and safety rails

- Structured errors surface short codes and (optionally) detailed
  descriptions (avoid exposing full descriptions to users)
- If the browser cannot set the session-binding cookie or the Web Crypto
  API is unavailable, the module surfaces `browser_cookie_error` with a
  concise description and halts login attempts until resolved
- Host and HTTPS constraints enforced early
- State is single‑use and time‑limited; sealed state + cookie binding
  mitigate CSRF/state injection
- State store access is strict: lookup or removal failures cause the
  flow to abort with a `shinyOAuth_state_error` to prevent replay/mix‑up
- Hooks (`trace_hook`, `audit_hook`) provide structured telemetry
  without exposing raw tokens
