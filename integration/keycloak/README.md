# Keycloak integration environment (Docker)

This folder provides a minimal Keycloak setup to run local integration tests against shinyOAuth.

- Image: `quay.io/keycloak/keycloak:26.6.1`
- Admin credentials: `admin` / `admin`
- Realm: `shinyoauth`
- Test user: `alice` / `alice`
- Clients:
  - `shiny-public` (public; PKCE S256; standard authorization-code flow)
  - `shiny-par-required` (public; PKCE S256; PAR required at authorization endpoint)
  - `shiny-confidential` (confidential; client secret `secret`; standard code flow; service accounts enabled for client_credentials)
  - `shiny-resource-confidential` (confidential; client secret `secret`; authorization-code flow with a fixed access-token audience mapper for `https://api.shinyoauth.test`)
  - `shiny-userinfo-jwt` (confidential; client secret `secret`; RS256-signed UserInfo responses)
  - `shiny-mtls-confidential` (confidential; X.509 client auth; certificate-bound authorization-code tokens)
  - `shiny-mtls-service` (confidential; X.509 client auth; certificate-bound client_credentials tokens)
  - `shiny-jar-hmac` (confidential; 32-byte client secret; HS256-signed Request Objects for JAR integration coverage)

## Run integration tests

```bash
# One-shot script (starts Keycloak, waits, runs tests, tears down):
# From repo root
bash integration/keycloak/run-integration.sh
```

## Start/stop Keycloak manually

```bash
# From integration/keycloak
docker compose up -d

# Tail logs (optional)
docker compose logs -f

# Stop and remove container
docker compose down -v
```

Key endpoints after startup:
- Issuer: http://localhost:8080/realms/shinyoauth
- Discovery: http://localhost:8080/realms/shinyoauth/.well-known/openid-configuration
- Admin console: http://localhost:8080/admin (login with admin/admin)

Note on PAR: this local Keycloak setup serves PAR metadata over plain HTTP.
'shinyOAuth' accepts that local PAR endpoint through the same non-HTTPS host policy used
for the other endpoints, so the PAR integration tests work through the regular localhost
allowlist behavior rather than a PAR-specific override.

To verify OIDC discovery quickly:
```bash
curl -fsSL http://localhost:8080/realms/shinyoauth/.well-known/openid-configuration | jq '.issuer, .authorization_endpoint, .token_endpoint'
```

## Overview of tests

Headless `testServer()` + `perform_login_form*()` tests are protocol
integrations. They intentionally bypass the browser cookie boundary, so they do
not prove SameSite cookie handling, callback cleanup, or live redirect
behavior. Those behaviors are covered by the `*_browser*.R` and `*_e2e.R`
files listed below.

- `test_integration_keycloak.R` — discovery and client_credentials + introspection
- `test_integration_module_shiny.R` — headless protocol integration for the full authorization-code flow against Keycloak, driving `oauth_module_server()` inside a Shiny test server and posting credentials directly to the Keycloak login form (requires the R packages `xml2` and `rvest`)
- `test_integration_module_shiny_browser.R` — end-to-end flow with a real headless browser (Chromium via {shinytest2}/{chromote}): clicks the Login button, completes the Keycloak login form, and verifies redirect back to the app and authenticated state.
- `test_integration_module_shiny_browser_request_uri.R` — end-to-end `request_uri` flow with a real Shiny app and headless browser, proving Keycloak can fetch the published Request Object through a public base-URL override while the browser still uses the local app URL.
 - `test_integration_keycloak_auth_styles.R` — parametric introspection using different token endpoint client auth styles: header (client_secret_basic), body (client_secret_post), client_secret_jwt and private_key_jwt (pre-provisioned in realm).
 - `test_integration_keycloak_auth_styles_unhappy.R` — negative-path coverage: wrong client_secret for CSJWT, mismatched algorithm, wrong private key for PJWT (server rejection), and incompatible alg for the provided key (local config error).
- `test_integration_keycloak_par.R` — PAR discovery and end-to-end code flow coverage, including the standard localhost HTTP host-policy path used by the local Keycloak setup.
- `test_integration_keycloak_par_unhappy.R` — PAR unhappy-path coverage for request-body validation plus live Keycloak rejection of bad JWT client-assertion audiences, consumed `request_uri` replays, and `request_uri` replay under a different client_id.
- `test_integration_keycloak_jar.R` — JAR happy-path coverage for private_key_jwt, HS256, and JAR+PAR end-to-end flows.
- `test_integration_keycloak_jar_unhappy.R` — JAR unhappy-path coverage against live Keycloak, exercising request-object signature rejection both at the authorization endpoint and through PAR.
- `test_integration_keycloak_mtls.R` — RFC 8705 mTLS coverage for authorization-code and client_credentials flows, including wrong/missing client certificate rejection, certificate-bound userinfo protection, and refresh/introspection/revocation regressions that must reach the AS even when token cnf data is mismatched locally.
 - `test_integration_keycloak_pkce.R` — PKCE enforcement for public client `shiny-public`:
   - Happy path: completes S256 PKCE code flow and authenticates
   - Unhappy path (missing verifier): deletes `code_verifier` from the state store before callback → module rejects with a PKCE/code_verifier error before token exchange
   - Unhappy path (wrong verifier): replaces `code_verifier` with a different valid value → server rejects the token exchange (invalid_grant), surfaced as a token/HTTP error
 - `test_integration_keycloak_revocation.R` — token revocation (RFC 7009) end-to-end: acquires a client_credentials token, verifies it is active via introspection, calls `revoke_token()`, and confirms the token is inactive; also exercises different auth styles for the revocation call
- `test_integration_keycloak_resource_indicators.R` — RFC 8707 coverage for both stock Keycloak compatibility and the dedicated audience-mapped fixture client, including local protected-resource rejection of tokens that lack the configured audience.
- `test_integration_attack_csrf_browser_token_e2e.R` — real browser cookie-boundary CSRF coverage: tampered browser token cookie causes callback rejection as `invalid_state` at the real callback boundary.
- `test_integration_attack_callback_swap_browser_e2e.R` — real browser callback-swap coverage: a foreign callback is rejected in the attacked session while the rightful callbacks still authenticate their original browser sessions.
- `test_integration_attack_dpop_resource.R` — DPoP protected-resource attack coverage: proof replay, wrong-key proof binding, bearer fallback rejection, and mirrored assertions against both package-backed and independent verification logic.

## Protocol validation tests

These tests exercise high-priority OAuth2/OIDC protocol behavior against the live Keycloak realm.

| Test file | Protocol surface | Coverage |
|-----------|------------------|----------|
| `test_integration_callback_issuer.R` | RFC 9207 authorization response `iss` | Accepts the real Keycloak callback issuer; rejects missing/mismatched issuer before state or code use |
| `test_integration_error_callback.R` | RFC 6749 authorization error callbacks | Surfaces provider errors only after issuer/state validation; consumes state; rejects replay and unsolicited errors |
| `test_integration_keycloak_claims_scope_acr.R` | OIDC claims, ACR, and OAuth scope validation | Essential userinfo happy path; missing ID token claim; ACR downgrade; reduced live token scope |
| `test_integration_keycloak_refresh_protection.R` | Refresh-token lifecycle | Refresh happy path; explicit refresh-token revocation; `revoke_on_session_end` invalidation |
| `test_integration_keycloak_protocol_hardening.R` | RFC 8707, OIDC `max_age`, RFC 7662, UserInfo subject binding | Resource policy binding; `auth_time`; introspection `sub`/`client_id`/`scope`; client-id mix-up; cross-user UserInfo substitution |
| `test_integration_keycloak_pkce_authorization_tamper.R` | RFC 7636 PKCE authorization request integrity | Missing challenge, `plain` downgrade, and malformed challenge rejected before code issuance |
| `test_integration_keycloak_jwt_auth_unhappy_code_flow.R` | JWT client authentication in full auth-code flow | Wrong secret, wrong audience, wrong alg, and wrong private key fail at token exchange and consume state |
| `test_integration_keycloak_dpop_nonce_retry.R` | RFC 9449 protected-resource nonce challenge | First DPoP proof receives `use_dpop_nonce`; retry uses fresh `jti`, nonce, `ath`, `htm`, and `htu` |
| `test_integration_keycloak_par_unhappy.R` | RFC 9126 PAR unhappy paths | Rejects caller-supplied `request_uri` in pushed params, bad JWT client-assertion audience at the PAR endpoint, consumed `request_uri` reuse, and outer `client_id` changes that violate `request_uri` client binding |
| `test_integration_keycloak_jar_par_confusion.R` | JAR/PAR outer-parameter behavior | PAR proves outer `redirect_uri`, `scope`, `state`, `nonce`, `resource`, and `code_challenge` do not override the pushed request; the JAR case records that this Keycloak fixture still reflects conflicting outer `redirect_uri` and `state` values in an `invalid_request` callback, so the suite does not overclaim JAR-alone protection |
| `test_integration_module_shiny_browser_callback_cleanup.R` | Browser callback leakage cleanup | Real browser login leaves no OAuth callback parameters in `window.location.href` or `document.title` |
| `test_integration_keycloak_resource_indicators.R` | RFC 8707 resource indicators | Proves stock Keycloak accepts `resource` parameters without projecting them into `aud`, then uses the dedicated `shiny-resource-confidential` fixture client plus a local protected resource to verify audience-checked token usability |
| `test_integration_keycloak_jwks_rotation.R` | OIDC JWKS refresh on key rotation | Rotates the disposable Keycloak realm signing key through the admin API; validates refresh-on-new-`kid` and rejects rogue signatures for old/new `kid` values |
| `test_integration_keycloak_userinfo_jwt.R` | OIDC signed UserInfo JWT | Live RS256 UserInfo JWT from Keycloak is verified, issuer/audience checked, and subject-bound to the validated ID token |

## Attack vector tests

These tests simulate real-world OAuth2/OIDC attack vectors against a live Keycloak server to verify the package's security defenses hold end-to-end. Shared helpers live in `helper-keycloak.R`.

Test users: `alice` / `alice` and `bob` / `bob` (for cross-user attacks).

| Test file | Attack vector | Defense mechanism verified |
|-----------|--------------|---------------------------|
| `test_integration_attack_code_replay.R` | **Authorization code replay** — replaying an already-exchanged code | Single-use state store; Keycloak server-side code single-use (invalid_grant) |
| `test_integration_attack_state_replay.R` | **State replay / CSRF** — reusing a consumed state parameter or injecting state from a different session | Single-use state store; per-session state isolation; AES-256-GCM key binding |
| `test_integration_attack_state_tamper.R` | **State parameter tampering** — bit-flip, truncation, random substitution, appending/prepending garbage, wrong encryption key | AES-256-GCM authenticated encryption (integrity tag); input validation |
| `test_integration_attack_code_injection.R` | **Cross-user flow substitution / login CSRF semantics** — Bob completes Alice's started flow, so the callback authenticates Bob, not Alice | Verified subject/claim surfaces remain app-visible for expected-user policy checks; independent state injection, wrong-verifier exchange, and cross-client swaps still fail closed |
| `test_integration_attack_nonce_mismatch.R` | **Nonce mismatch / replay** — tampered, missing, or replayed nonce in ID token validation | ID token nonce claim verification against state store |
| `test_integration_attack_csrf_browser_token.R` | **Browser token callback validation** — mismatched, missing, or malformed browser token values passed directly into callback handling | constant_time_compare(); browser token format validation; skip-guard |
| `test_integration_attack_csrf_browser_token_e2e.R` | **Browser token CSRF (double-submit cookie bypass)** — attacker tampers with the real app-origin browser token cookie before the callback returns | Cookie/header double-submit binding across the real browser boundary; invalid_state failure at the live callback origin |
| `test_integration_attack_callback_swap_browser_e2e.R` | **Real browser callback swap** — one live browser session receives another session's callback before both rightful callbacks arrive | Foreign callback rejected at the real callback origin; cookie/session isolation via distinct module instances; rightful callbacks still authenticate their original sessions |
| `test_integration_attack_dpop_resource.R` | **DPoP protected-resource substitution/replay** — bearer fallback, mismatched proof key, or proof replay against a DPoP-bound access token | DPoP `cnf.jkt` binding, `ath`/`htu`/`htm` proof checks, nonce/replay defenses, and parity between package-backed and independent verifiers |
| `test_integration_attack_expired_state.R` | **Expired state payload** — delayed callback after state max_age | issued_at freshness check in state_payload_decrypt_validate() |
| `test_integration_attack_cross_client.R` | **Cross-client code swap** — code issued for one client_id exchanged by another | Keycloak server-side client_id binding; state payload client_id binding |
| `test_integration_attack_redirect_uri.R` | **Redirect URI manipulation** — attacker changes redirect_uri to steal authorization code | Keycloak redirect URI allowlist; state payload redirect_uri binding |
| `test_integration_attack_concurrent_flows.R` | **Concurrent flow isolation** — multiple simultaneous flows and cross-session callback swaps | State store entry keying; per-session isolation; multi-user independence |

For the browser `request_uri` integration test, the Shiny app listens on all
interfaces but the browser uses `127.0.0.1` so redirect cookies stay on one
origin. Keycloak fetches the published Request Object through
`SHINYOAUTH_E2E_REQUEST_URI_BASE_URL`. When unset, the test defaults to
`http://host.docker.internal:${SHINYOAUTH_E2E_PORT}` and the compose file maps
`host.docker.internal` back to the host on Linux runners via `host-gateway`.
If you override that URL, the matching public `request_uri` prefix must also be
registered on the Keycloak client.
