**Coverage scope**

Current stage: all fourteen modules in the pinned Basic RP plan execute in a
real browser with matching app evidence. The variant uses static registration,
code flow and `client_secret_basic`, synchronous transport and query callbacks.
Thirteen modules finish `PASSED`. The unsigned-token module finishes `SKIPPED`
after the app rejects `alg=none`, as its documented optional behavior permits.
For this exact plan/variant, `basic` reports `coverage_complete = true`; the
three-module `smoke` selection keeps it false. This establishes local Basic RP
test coverage; OpenID certification and other profiles remain separate.

Preflight's `required_plans_present` proves suite capability. The separate
synthetic-metadata fixture checks prove authorization-request plumbing. The API
check and app-stop control create interrupted modules for harness validation;
neither interruption counts as a client test pass.

| Target | Existing local evidence | Planned independent gate |
| --- | --- | --- |
| OIDC Core code flow, ID token and UserInfo validation | Unit tests, Keycloak browser/code flows, complete pinned Basic RP module selection (C05) | Basic implemented for the variant above; further profiles below |
| Discovery, exact issuer and signing-key changes | Discovery/JWKS tests and Keycloak rotation | Configuration RP; C06 |
| Form POST callback and browser binding | Real browser and retained-connection tests | Form Post Basic RP; C07 |
| Refresh identity continuity | Refresh validation and retained-connection tests | OIDC client refresh plan; C08 |
| Public clients, other auth methods and async transport | Keycloak and worker tests | Applicable extended-plan variants; C09 |
| PAR, DPoP and mTLS | Keycloak and independent Python exchanges | FAPI 2.0 Security Profile; C10-C11 |
| JAR/JARM combinations | Independent Python fixture and Keycloak capability tests | FAPI Message Signing; C12; second full provider C13-C14 |
| SMART App Launch | SMART browser fixtures and corrected Inferno simulator | Existing Inferno gate remains separate |

The `basic` selection follows the module order in the pinned
[Basic plan](https://gitlab.com/openid/conformance-suite/-/blob/410812ef6bc72a84723c1685725edce3558e31e3/src/main/java/net/openid/conformance/openid/client/OIDCCClientBasicTestPlan.java).
All cases use the normal discovery, login and callback APIs. Successful cases
require validated ID tokens and fetched UserInfo; rejections require no retained
identity or token and zero successful logins. The suite checks the code request
and HTTP Basic authentication, while C02's fixture checks separately establish
that the client sends PKCE S256 and a nonce.

| Module suffix (`oidcc-client-test` prefix) | Requirement or policy | Required app evidence | Suite verdict |
| --- | --- | --- | --- |
| (none) | Core 3.1.3.7, 5.3 | Authenticated, validated ID token and UserInfo | `PASSED` |
| `-invalid-iss` | Core 3.1.3.7 step 2 | ID-token rejection naming `iss`; no UserInfo | `PASSED` |
| `-missing-sub` | Core 2 | ID-token rejection naming `sub`; no UserInfo | `PASSED` |
| `-invalid-aud` | Core 3.1.3.7 step 3 | ID-token rejection naming `aud`; no UserInfo | `PASSED` |
| `-missing-iat` | Core 2 | ID-token rejection naming `iat`; no UserInfo | `PASSED` |
| `-kid-absent-single-jwks` | Core 10.1 | Successful signature verification without a key ID | `PASSED` |
| `-kid-absent-multiple-jwks` | Core 10.1; upstream permits rejection or trying eligible keys | Successful signature verification using an eligible key | `PASSED` |
| `-idtoken-sig-rs256` | Core 3.1.3.7 step 7 | Authenticated with validated ID token and UserInfo | `PASSED` |
| `-idtoken-sig-none` | Optional unsigned-token support; package requires signatures | `disallowed_algorithm` ID-token error; no UserInfo | `SKIPPED` |
| `-invalid-sig-rs256` | Package requires signature validation even over TLS | `invalid_signature` ID-token error; no UserInfo | `PASSED` |
| `-userinfo-invalid-sub` | Core 5.3.2 | Typed `shinyOAuth_userinfo_mismatch` after a UserInfo request | `PASSED` |
| `-nonce-invalid` | Core 3.1.3.7 step 11 | ID-token rejection naming `nonce`; no UserInfo | `PASSED` |
| `-scope-userinfo-claims` | Core 5.4 | Authenticated with requested `email` claim present in UserInfo; only its name recorded | `PASSED` |
| `-client-secret-basic` | Core 9; RFC 6749 2.3.1 | Successful code exchange and login | `PASSED` |

The unsigned-token exception follows the pinned
[module implementation](https://gitlab.com/openid/conformance-suite/-/blob/410812ef6bc72a84723c1685725edce3558e31e3/src/main/java/net/openid/conformance/openid/client/OIDCCClientTestIdTokenSigAlgNone.java),
which calls `fireTestSkipped()` if no UserInfo request follows the unsigned
token. Its comments mention a warning, but the executable implementation yields
`SKIPPED`; the gate requires that exact verdict and the app's matching reason.
This exception applies only to that module and never converts its verdict to
`PASSED`. Every module must reach `FINISHED`, with verified browser callback
cleanup, the expected app package/run identity, and owned-resource cleanup.

Baseline references: [OIDC Core](https://openid.net/specs/openid-connect-core-1_0.html),
[Discovery](https://openid.net/specs/openid-connect-discovery-1_0.html),
[RFC 6749](https://www.rfc-editor.org/rfc/rfc6749.html),
[RFC 6750](https://www.rfc-editor.org/rfc/rfc6750.html),
[RFC 7636](https://www.rfc-editor.org/rfc/rfc7636.html),
[RFC 9207](https://www.rfc-editor.org/rfc/rfc9207.html),
[RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html) and
[RFC 8725](https://www.rfc-editor.org/rfc/rfc8725.html).
Map each future scenario to its applicable requirement or stricter package
policy. Server enforcement, public deployment TLS and credential custody need
their own evidence. Keep the OAuth 2.1 configuration assessment's draft pin.

The initial claim excludes implicit/hybrid flows, WebFinger, dynamic client
registration, OIDC logout protocols and national FAPI ecosystem profiles.
Unexpected skips, manual-review results and unfinished modules cannot establish
a pass. Both Config RP rotation modules need explicit execution despite their
default exclusion from the upstream runner.
