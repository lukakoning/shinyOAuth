# Keycloak integration environment (Docker)

This folder provides a minimal Keycloak setup to run local integration tests against shinyOAuth.

- Image: `quay.io/keycloak/keycloak:24.0.5`
- Admin credentials: `admin` / `admin`
- Realm: `shinyoauth`
- Test user: `alice` / `alice`
- Clients:
  - `shiny-public` (public; PKCE S256; standard authorization-code flow)
  - `shiny-confidential` (confidential; client secret `secret`; standard code flow; service accounts enabled for client_credentials)

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

To verify OIDC discovery quickly:
```bash
curl -fsSL http://localhost:8080/realms/shinyoauth/.well-known/openid-configuration | jq '.issuer, .authorization_endpoint, .token_endpoint'
```

## Overview of tests

- `test_integration_keycloak.R` — discovery and client_credentials + introspection
- `test_integration_module_shiny.R` — full authorization code flow against Keycloak, driving `oauth_module_server()` inside a Shiny test server and posting credentials to the Keycloak login form (requires the R packages `xml2` and `rvest`)
- `test_integration_module_shiny_browser.R` — end-to-end flow with a real headless browser (Chromium via {shinytest2}/{chromote}): clicks the Login button, completes the Keycloak login form, and verifies redirect back to the app and authenticated state.
 - `test_integration_keycloak_auth_styles.R` — parametric introspection using different token endpoint client auth styles: header (client_secret_basic), body (client_secret_post), client_secret_jwt and private_key_jwt (pre-provisioned in realm).
 - `test_integration_keycloak_auth_styles_unhappy.R` — negative-path coverage: wrong client_secret for CSJWT, mismatched algorithm, wrong private key for PJWT (server rejection), and incompatible alg for the provided key (local config error).
 - `test_integration_keycloak_pkce.R` — PKCE enforcement for public client `shiny-public`:
   - Happy path: completes S256 PKCE code flow and authenticates
   - Unhappy path (missing verifier): deletes `code_verifier` from the state store before callback → module rejects with a PKCE/code_verifier error before token exchange
   - Unhappy path (wrong verifier): replaces `code_verifier` with a different valid value → server rejects the token exchange (invalid_grant), surfaced as a token/HTTP error
 - `test_integration_keycloak_revocation.R` — token revocation (RFC 7009) end-to-end: acquires a client_credentials token, verifies it is active via introspection, calls `revoke_token()`, and confirms the token is inactive; also exercises different auth styles for the revocation call

## Attack vector tests

These tests simulate real-world OAuth2/OIDC attack vectors against a live Keycloak server to verify the package's security defenses hold end-to-end. Shared helpers live in `helper-keycloak.R`.

Test users: `alice` / `alice` and `bob` / `bob` (for cross-user attacks).

| Test file | Attack vector | Defense mechanism verified |
|-----------|--------------|---------------------------|
| `test_integration_attack_code_replay.R` | **Authorization code replay** — replaying an already-exchanged code | Single-use state store; Keycloak server-side code single-use (invalid_grant) |
| `test_integration_attack_state_replay.R` | **State replay / CSRF** — reusing a consumed state parameter or injecting state from a different session | Single-use state store; per-session state isolation; AES-256-GCM key binding |
| `test_integration_attack_state_tamper.R` | **State parameter tampering** — bit-flip, truncation, random substitution, appending/prepending garbage, wrong encryption key | AES-256-GCM authenticated encryption (integrity tag); input validation |
| `test_integration_attack_code_injection.R` | **Cross-user code injection** — attacker (bob) injects their code into victim's (alice) session | Per-session state stores; PKCE challenge binding; Keycloak client_id binding |
| `test_integration_attack_nonce_mismatch.R` | **Nonce mismatch / replay** — tampered, missing, or replayed nonce in ID token validation | ID token nonce claim verification against state store |
| `test_integration_attack_csrf_browser_token.R` | **Browser token CSRF (double-submit cookie bypass)** — mismatched, missing, or malformed browser session cookie | constant_time_compare(); browser token format validation; skip-guard |
| `test_integration_attack_expired_state.R` | **Expired state payload** — delayed callback after state max_age | issued_at freshness check in state_payload_decrypt_validate() |
| `test_integration_attack_cross_client.R` | **Cross-client code swap** — code issued for one client_id exchanged by another | Keycloak server-side client_id binding; state payload client_id binding |
| `test_integration_attack_redirect_uri.R` | **Redirect URI manipulation** — attacker changes redirect_uri to steal authorization code | Keycloak redirect URI allowlist; state payload redirect_uri binding |
| `test_integration_attack_concurrent_flows.R` | **Concurrent flow isolation** — multiple simultaneous flows and cross-session callback swaps | State store entry keying; per-session isolation; multi-user independence |
