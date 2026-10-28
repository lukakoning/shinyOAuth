# Keycloak integration environment (Docker)

Test shinyOAuth against a local Keycloak provider. The runner starts a
disposable server, runs the integration tests, and stops it afterward.
Its preconfigured accounts are for local testing only.

For adding login to your own app, start with the
[usage guide](../../vignettes/usage.Rmd).

## Prerequisites

- Docker Engine with the Compose v2 plugin
- Bash, `curl`, and the OpenSSL command-line tools on `PATH`
- R 4.1 or newer with the package's development dependencies plus `rvest`;
  for example, run `remotes::install_deps(dependencies = TRUE)` and then
  `install.packages("rvest")` from the repository root
- A locally launchable Chrome or Chromium browser for the shinytest2/chromote
  tests. If chromote cannot find it automatically, set `CHROMOTE_CHROME` to the
  browser executable before running the script

The one-shot script installs the local shinyOAuth source package without
installing dependencies, so install these prerequisites first.

Client-hosted Request Objects use URLs at the app root with a
`shinyOAuth_request_object` query handle. The JAR clients' `request.uris`
registration therefore permits `https://host.docker.internal:18100/*`.
Keycloak's path-wildcard matching does not constrain query values. Recreate
the disposable container after changing the realm fixture; restarting an
existing realm does not replace its client registrations.

## Run integration tests

The shared test options keep `shinyOAuth.expose_error_body = FALSE`. Assertions
use condition classes, module error codes, and structured audit fields. Only
tests specifically inspecting provider diagnostics should enable detailed
errors locally. The release runner retains a zero-skip budget by default.

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
The integration runner explicitly enables the loopback-only development option
`shinyOAuth.allow_insecure_oidc_loopback`; the ordinary endpoint host allowlist
does not permit HTTP. No PAR-specific override is used.

To verify OIDC discovery quickly:
```bash
curl -fsSL http://localhost:8080/realms/shinyoauth/.well-known/openid-configuration | jq '.issuer, .authorization_endpoint, .token_endpoint'
```

## Test accounts and clients

- Image: `quay.io/keycloak/keycloak:26.6.1`
- Admin credentials: `admin` / `admin`
- Realm: `shinyoauth`
- Test user: `alice` / `alice`
- Clients:
  - `shiny-public` (public; PKCE S256; standard authorization-code flow)
  - `shiny-par-required` (public; PKCE S256; PAR required at authorization endpoint)
  - `shiny-confidential` (confidential; client secret `secret`; standard code flow; service accounts enabled for client_credentials)
  - `shiny-csjwt` (confidential; `client_secret_jwt`; service accounts enabled for client_credentials and JWT client-assertion replay coverage)
  - `shiny-pjwt` (confidential; `private_key_jwt`; service accounts enabled for client_credentials and JWT client-assertion replay coverage)
  - `shiny-resource-confidential` (confidential; client secret `secret`; authorization-code flow with a fixed access-token audience mapper for `https://api.shinyoauth.test`)
  - `shiny-userinfo-jwt` (confidential; client secret `secret`; RS256-signed UserInfo responses)
  - `shiny-mtls-confidential` (confidential; X.509 client auth; certificate-bound authorization-code tokens)
  - `shiny-mtls-service` (confidential; X.509 client auth; certificate-bound client_credentials tokens)
  - `shiny-jar-hmac` (confidential; 32-byte client secret; HS256-signed Request Objects for JAR integration coverage)
  - `shiny-jar-pjwt` (confidential; `private_key_jwt`; RS256-signed Request Objects and `request_uri` support)
  - `shiny-jar-pjwt-jwe` (confidential; `private_key_jwt`; signed-and-encrypted Request Objects and `request_uri` support)

## Overview of tests

Capability expectations are pinned to Keycloak 26.6.1, the Compose image.
DPoP+PAR must complete authorization, token issuance and protected UserInfo;
an error is a regression, not an alternative passing outcome.

The DPoP+JAR, mTLS+JAR and JAR+JARM rejection canaries record unsupported
combinations in this fixture. The JAR-claims tests record known server
noncompliance: wrong audience/issuer, expired Request Objects and repeated
Request Objects are accepted. Local callback-state consumption does not prove
server-side replay prevention. These tests must not be counted as successful
interoperability or AS conformance.

The [independent strict AS fixture](../conformance/README.md) tests successful
JAR+DPoP and JAR+mTLS flows, both with and without PAR, and JAR+signed-JARM.
It independently rejects unsigned requests, wrong issuer/audience, expiry and
Request Object replay. CI runs it separately from the Keycloak capability tests.

Headless `testServer()` + `perform_login_form*()` tests are protocol
integrations. They intentionally bypass the browser cookie boundary, so they do
not prove SameSite cookie handling, callback cleanup, or live redirect
behavior. Those behaviors are covered by the `*_browser*.R` and `*_e2e.R`
files listed below.

Core login and token tests include:

- `test_integration_keycloak.R`: discovery, client-credentials tokens and
  introspection.
- `test_integration_module_shiny.R`: authorization-code login inside a Shiny
  test server, posting directly to Keycloak's login form. Requires `xml2` and
  `rvest`.
- `test_integration_module_shiny_browser.R`: Chromium clicks Login, completes
  the Keycloak form, and checks the return to an authenticated app.
- `test_integration_module_shiny_browser_request_uri.R`: Keycloak fetches the
  hosted Request Object through a public base-URL override while the browser
  uses the local app URL. Tampered browser markers and swapped callbacks must
  fail without consuming the legitimate callbacks.
- `test_integration_keycloak_auth_styles.R`: introspection with
  `client_secret_basic`, `client_secret_post`, `client_secret_jwt` and
  `private_key_jwt`.
- `test_integration_keycloak_auth_styles_unhappy.R`: wrong secrets and
  mismatched algorithms; Keycloak rejection of a wrong private key; local
  rejection of a key incompatible with the chosen algorithm.
- `test_integration_keycloak_par.R`: PAR discovery and authorization-code login
  using the fixture's localhost HTTP exception.
- `test_integration_keycloak_jar.R`: JAR login with `private_key_jwt` client
  authentication, HS256-signed Request Objects, and JAR combined with PAR.
- `test_integration_keycloak_jar_unhappy.R`: Request Object signature rejection
  at the authorization endpoint and through PAR.
- `test_integration_keycloak_pkce.R`: successful S256 login with `shiny-public`;
  a missing verifier fails before token exchange, and a wrong verifier produces
  `invalid_grant` at the token endpoint.
- `test_integration_keycloak_revocation.R`: a client-credentials token is active
  before `revoke_token()` and inactive afterward, across supported endpoint
  authentication methods.

## Protocol test reference

| Test file | Feature | Coverage |
|-----------|------------------|----------|
| `test_integration_callback_issuer.R` | RFC 9207 authorization response `iss` | Accepts the real Keycloak callback issuer; rejects missing/mismatched issuer before state or code use across plain, PAR, JAR, JAR+PAR, and mTLS+PAR flows; includes a true multi-issuer mix-up rejection using a disposable second Keycloak realm |
| `test_integration_error_callback.R` | RFC 6749 authorization error callbacks | Surfaces provider errors only after issuer/state validation; consumes state; rejects replay and unsolicited errors |
| `test_integration_error_callback_browser_e2e.R` | RFC 6749 authorization error callbacks at the real browser boundary | Browser cookie metadata inspection; issuer mismatch before state consumption; valid provider-error surfacing only after issuer, state, and browser-token validation; replay blocking; URL/title cleanup after error callbacks |
| `test_integration_keycloak_claims_scope_acr.R` | OIDC claims, ACR, and OAuth scope validation | Essential userinfo happy path; missing ID token claim; ACR downgrade; reduced live token scope |
| `test_integration_keycloak_refresh_protection.R` | Refresh-token lifecycle | Refresh happy path; explicit refresh-token revocation; `revoke_on_session_end` invalidation |
| `test_integration_keycloak_protocol_hardening.R` | RFC 8707, OIDC `max_age`, RFC 7662, UserInfo subject binding | Resource policy binding; `auth_time`; introspection `sub`/`client_id`/`scope`; client-id mix-up; cross-user UserInfo substitution |
| `test_integration_keycloak_pkce_authorization_tamper.R` | RFC 7636 PKCE authorization request integrity | Missing challenge, `plain` downgrade, and malformed challenge rejected before code issuance |
| `test_integration_keycloak_jwt_auth_unhappy_code_flow.R` | JWT client authentication in full auth-code flow | Wrong secret, wrong audience, wrong alg, and wrong private key fail at token exchange and consume state for both plain authorization-code callbacks and signed JARM `response_mode=query.jwt` callbacks |
| `test_integration_keycloak_dpop.R` | RFC 9449 DPoP auth-code flow | DPoP token issuance, UserInfo enforcement, rejection of Bearer fallback, refresh key binding, and a successful DPoP+PAR flow |
| `test_integration_keycloak_dpop_nonce_retry.R` | RFC 9449 protected-resource nonce challenge | First DPoP proof receives `use_dpop_nonce`; retry uses fresh `jti`, nonce, `ath`, `htm`, and `htu` |
| `test_integration_keycloak_par_unhappy.R` | RFC 9126 PAR unhappy paths | Rejects caller-supplied `request_uri` in pushed params, bad JWT client-assertion audience at the PAR endpoint, expired and consumed `request_uri` reuse, and outer `client_id` changes that violate `request_uri` client binding, including module-level assertions for whether failed `request_uri` callbacks consume or preserve pending state |
| `test_integration_keycloak_jwt_client_assertion_replay.R` | JWT client assertion replay at PAR and token endpoints | Proves live Keycloak rejects replayed `client_secret_jwt` and `private_key_jwt` assertions at both endpoints, and that shinyOAuth emits fresh `jti` values across repeated assertion builds |
| `test_integration_keycloak_jar_par_confusion.R` | JAR/PAR outer-parameter behavior | PAR proves outer `redirect_uri`, `scope`, `state`, `nonce`, `resource`, and `code_challenge` do not override the pushed request; direct JAR proves the same for `redirect_uri`, `state`, `nonce`, and `code_challenge` once the OIDC-required outer `response_type` and `scope` are preserved on the browser URL; direct JAR and JAR+PAR also cover outer `client_id` confusion so no code is accepted and the legitimate flow state remains usable |
| `test_integration_keycloak_jar_claims.R` | Signed Request Object claim validation | Records current Keycloak behavior for wrong `aud`, wrong `iss`, expired `exp`, and replayed signed Request Objects, and verifies shinyOAuth still rejects the second callback after state consumption |
| `test_integration_keycloak_jarm.R` | JARM signed and encrypted authorization responses | Completes live signed and encrypted `response_mode=query.jwt` logins against Keycloak, verifies replay rejection after state consumption, exercises PKCE verifier tampering and PAR compatibility under JARM, confirms the callback arrives as a JWT/JWE response rather than plain `code/state` parameters, proves the live Keycloak callback still needs the duplicate-`iss` interoperability workaround, and records that this fixture currently rejects signed Request Object + `query.jwt` combinations before login. |
| `test_integration_keycloak_mtls.R` | RFC 8705 mTLS sender constraints | Authorization-code and client-credentials flows; certificate-bound tokens without `tls_client_auth`; PAR over the mTLS alias with `client_secret_jwt`; missing or wrong certificates; wrong-certificate refresh rejection; certificate-bound UserInfo; and AS calls that must proceed when local `cnf` metadata is tampered |
| `test_integration_keycloak_mtls_jar.R` | RFC 8705 + JAR interoperability | Records that this Keycloak fixture rejects signed and encrypted mTLS+JAR combinations both directly and through PAR |
| `test_integration_keycloak_dpop_jar.R` | RFC 9449 + JAR interoperability | Verifies `dpop_jkt` is embedded inside signed Request Objects and records that this Keycloak fixture rejects DPoP+JAR and DPoP+JAR+PAR combinations |
| `test_integration_module_shiny_browser_callback_cleanup.R` | Browser callback leakage cleanup | Real browser login leaves no OAuth callback parameters in `window.location.href` or `document.title` |
| `test_integration_module_shiny_browser_form_post.R` | OIDC `response_mode=form_post` and `form_post.jwt` at the real browser boundary | Verifies Keycloak discovery advertises `form_post` and `form_post.jwt`, the built authorization URL requests the configured POST response mode, the live callback succeeds through `oauth_form_post_ui()`, and the transient `shinyOAuth_form_post*` handle parameters are cleaned from the browser URL/title |
| `test_integration_module_shiny_browser_form_post_unhappy.R` | OIDC `form_post` and `form_post.jwt` browser unhappy paths | Covers real-browser provider-error handling, issuer mismatch rejection before state use, tampered browser-token cookie rejection, wrong-app callback swaps, JARM `aud` rejection for stolen `form_post.jwt` callbacks, and cleanup of transient callback parameters after unhappy flows |
| `test_integration_keycloak_resource_indicators.R` | RFC 8707 resource indicators | Proves stock Keycloak accepts `resource` parameters without projecting them into `aud`, then uses the dedicated `shiny-resource-confidential` fixture client plus a local protected resource to verify audience-checked token usability |
| `test_integration_keycloak_jwks_rotation.R` | OIDC JWKS refresh on key rotation | Rotates the disposable Keycloak realm signing key through the admin API; validates refresh-on-new-`kid` and rejects rogue signatures for old/new `kid` values |
| `test_integration_keycloak_userinfo_jwt.R` | OIDC signed UserInfo JWT | Live RS256 UserInfo JWT from Keycloak is verified, issuer/audience checked, and subject-bound to the validated ID token |

Additional integration suites:

| Test file | Coverage |
|-----------|----------|
| `test_integration_browser_proactive_refresh.R` | Short-lived browser tokens refresh proactively and remain usable at UserInfo. |
| `test_integration_helper_strict_mode.R` | Strict integration mode turns missing infrastructure into failures. |
| `test_integration_keycloak_code_jwt_auth.R` | Authorization-code flows using `client_secret_jwt` and `private_key_jwt`. |
| `test_integration_module_shiny_async_audit.R` | File audit events from the main process and a real mirai worker. |
| `test_integration_module_shiny_browser_expiry.R` | Browser authentication state clears when tokens expire. |
| `test_integration_module_shiny_browser_introspection.R` | Browser login with live Keycloak token introspection. |
| `test_integration_module_shiny_future_multisession.R` | Shiny module login using a future multisession worker. |

## Security test reference

These tests submit altered, reused, or mismatched login requests and check
how the package and Keycloak respond. Shared helpers live in `helper-keycloak.R`.
Browser tests exercise actual redirects and cookies; other tests focus on
protocol handling without a browser.

Test users: `alice` / `alice` and `bob` / `bob` (for cross-user attacks).

| Test file | Attack vector | Defense mechanism verified |
|-----------|--------------|---------------------------|
| `test_integration_attack_code_replay.R` | Exchange an authorization code twice | Single-use state and Keycloak's rejection of a reused code with `invalid_grant` |
| `test_integration_attack_state_replay.R` | Reuse consumed state or inject state from another session | Single-use state, session isolation and AES-256-GCM key binding |
| `test_integration_attack_state_tamper.R` | Bit-flip, truncate or substitute state; prepend or append garbage; use the wrong encryption key | AES-256-GCM integrity checking and input validation |
| `test_integration_attack_code_injection.R` | Bob completes a login started by Alice; the callback identifies Bob | The app receives verified claims for its expected-account checks. Independent state injection and a wrong PKCE verifier are rejected. |
| `test_integration_attack_login_csrf_browser_e2e.R` | Complete the browser login with a different provider account than the app expected | The app receives the verified subject and UserInfo so it can reject an unexpected account. |
| `test_integration_attack_nonce_mismatch.R` | Submit a tampered, missing or replayed ID-token nonce | Compare the nonce with the pending login's stored value |
| `test_integration_attack_csrf_browser_token.R` | Pass mismatched, missing or malformed browser tokens directly to callback handling | `constant_time_compare()`, browser-token format validation and the skip guard |
| `test_integration_attack_csrf_browser_token_e2e.R` | Browser marker tampering before the callback returns | The cookie marker must match the origin- and tab-scoped storage record; a mismatch raises `invalid_state` at the callback origin. See [browser attack coverage](browser-attack-coverage.md). |
| `test_integration_attack_callback_swap_browser_e2e.R` | Send each deployment the other app's callback | Distinct redirect URIs and state stores reject the swapped callbacks; each original callback still authenticates its own session. |
| [`test_integration_cross_client_pkce.R`](test_integration_cross_client_pkce.R) | Redeem a code with a different client ID but the correct verifier and redirect URI | Both registrations first redeem their own codes successfully. Changing only `client_id` then produces HTTP 400 `invalid_grant` without an access token. |
| `test_integration_attack_dpop_resource.R` | Use a DPoP-bound token as Bearer, with the wrong proof key, or with a replayed proof | `cnf.jkt`, `ath`, `htu`, `htm`, nonce and replay checks; matching results from package-backed and independent verifiers |
| `test_integration_attack_expired_state.R` | Return a callback after the state's maximum age | The `issued_at` freshness check in `state_payload_decrypt_validate()` |
| `test_integration_attack_redirect_uri.R` | Change `redirect_uri` to divert an authorization code | Keycloak's redirect allowlist and the redirect URI bound into state |
| `test_integration_attack_concurrent_flows.R` | Start simultaneous logins and swap callbacks across sessions | State-store keys and session isolation keep users' logins separate. |

Negative PKCE authorization assertions require a callback at the configured URI,
the matching state, no code, and `invalid_request` identifying PKCE. Transport
and login-driver failures fail the test.

Earlier cross-client exchange cases had missing or incorrect PKCE verifiers;
their generic rejections did not establish client-ID binding. The dedicated
[`test_integration_cross_client_pkce.R`](test_integration_cross_client_pkce.R)
fixture now isolates server-side client-ID binding: both registrations redeem
their own codes successfully, then a fresh code is submitted with only
`client_id` changed, preserving its correct verifier and redirect URI. It
requires HTTP 400 `invalid_grant` and no access token.
The module case with independent encryption keys was removed from the evidence
suite. `tests/testthat/test-login-callback.R` isolates local client-ID binding
with a valid baseline and a specific mismatch assertion. The separate-app
browser fixture above does not establish session binding within a single
deployed client configuration.

For the browser `request_uri` integration test, the Shiny app listens on all
interfaces but the browser uses `127.0.0.1` so redirect cookies stay on one
origin. Keycloak fetches the published Request Object through
`SHINYOAUTH_E2E_REQUEST_URI_BASE_URL`. When unset, the test defaults to
`https://host.docker.internal:<app_port + 10000>`, served by the test's TLS
proxy. For example, Shiny port `8100` uses public Request Object port `18100`.
The compose file maps `host.docker.internal` back to the host on Linux runners
via `host-gateway`.
If you override that URL, the matching public `request_uri` prefix must also be
registered on the Keycloak client.
