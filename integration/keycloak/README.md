# Keycloak integration environment (Docker)

This folder provides a minimal Keycloak setup to run local integration tests against shinyOAuth.

- Image: `quay.io/keycloak/keycloak:24.0.5`
- Admin credentials: `admin` / `admin`
- Realm: `shinyoauth`
- Test user: `alice` / `alice`
- Clients:
  - `shiny-public` (public; PKCE S256; standard authorization-code flow)
  - `shiny-confidential` (confidential; client secret `secret`; standard code flow; service accounts enabled for client_credentials)

## Start/stop

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

## Verify discovery quickly

```bash
curl -fsSL http://localhost:8080/realms/shinyoauth/.well-known/openid-configuration | jq '.issuer, .authorization_endpoint, .token_endpoint'
```

## Run integration tests

```bash
# One-shot script (starts Keycloak, waits, runs tests, tears down):
# From repo root
bash integration/keycloak/run-integration.sh

# Or run manually from repo root (both tests in this folder):
Rscript -e "testthat::test_dir('integration/keycloak')"
```

Included tests:
- `test_integration_keycloak.R` — discovery and client_credentials + introspection
- `test_integration_module_shiny.R` — full authorization code flow against Keycloak, driving `oauth_module_server()` inside a Shiny test server and posting credentials to the Keycloak login form (requires the R packages `xml2` and `rvest`)
- `test_integration_module_shiny_browser.R` — end-to-end flow with a real headless browser (Chromium via {shinytest2}/{chromote}): clicks the Login button, completes the Keycloak login form, and verifies redirect back to the app and authenticated state.
 - `test_integration_keycloak_auth_styles.R` — parametric introspection using different token endpoint client auth styles: header (client_secret_basic), body (client_secret_post), and optional JWT styles when configured.
 - `test_integration_keycloak_auth_styles.R` — parametric introspection using different token endpoint client auth styles: header (client_secret_basic), body (client_secret_post), client_secret_jwt and private_key_jwt (pre-provisioned in realm).
 - `test_integration_keycloak_auth_styles_unhappy.R` — negative-path coverage: wrong client_secret for CSJWT, mismatched algorithm, wrong private key for PJWT (server rejection), and incompatible alg for the provided key (local config error).

Notes:
- If you don't have `xml2`/`rvest` installed, `test_integration_module_shiny.R` will be skipped automatically.
- If you don't have `{shinytest2}` and `{chromote}` (and a local Chrome/Chromium) installed, `test_integration_module_shiny_browser.R` will be skipped automatically.
```

### Enable JWT client assertion tests (optional)

Keycloak can accept JWT-based client authentication at the token/introspection endpoint, but individual clients must be configured accordingly. The included realm defaults to `client-secret` for `shiny-confidential`, so JWT styles are skipped by default. To enable them:

- client_secret_jwt (HMAC): either switch your `shiny-confidential` client to "Signed JWT" using the client secret in the Keycloak admin UI, or provision a new client for this purpose. Then set:

```bash
export SHINYOAUTH_TEST_CSJWT=1
# Optional overrides (defaults shown)
export SHINYOAUTH_CSJWT_CLIENT_ID=shiny-confidential
export SHINYOAUTH_CSJWT_SECRET=secret
export SHINYOAUTH_CSJWT_ALG=HS256
```

- private_key_jwt (asymmetric): create a client in Keycloak with "Signed JWT" and register the corresponding public key or JWKS. Provide the private key to the tests via env var:

```bash
export SHINYOAUTH_PJWT_CLIENT_ID=<your-client-id>
# Either embed the PEM directly or point to a file
export SHINYOAUTH_PJWT_KEY="-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----"
# or
export SHINYOAUTH_PJWT_KEY_FILE=/absolute/path/to/private.pem

# Optional: specify kid/alg if needed
export SHINYOAUTH_PJWT_KID=<kid>
export SHINYOAUTH_PJWT_ALG=RS256
```

With these set, `test_integration_keycloak_auth_styles.R` will include the JWT cases. If Keycloak rejects the configuration for a JWT style, the test reports the status and skips the strict assertion rather than failing unrelated suites.

## Run the demo Shiny app

This example uses the `shiny-public` client (PKCE) and listens on port 3000.

```bash
Rscript playground/example-keycloak-docker.R
```

If you prefer the existing example using the master realm, see `playground/example-keycloak.R`.

## Notes
- Redirect URIs registered in the realm allow http://localhost:3000/* and 8100 for local testing.
- For client credentials (service account) tests, use `shiny-confidential` with secret `secret`.
 - The Shiny module flow test disables the module's browser-token requirement via `options(shinyOAuth.skip_browser_token = TRUE)` so it can run headlessly.
