**Coverage scope**

Current stage: environment preflight, suite API/evidence validation and Shiny fixture plumbing. No client
conformance profile has run yet. `required_plans_present` proves suite capability.
The separate fixture checks prove a browser authorization request using local
synthetic metadata, with no token issuance or external conformance verdict.
The API check creates and cancels a waiting suite module; it does not count
that interrupted run as a client test pass.

| Target | Existing local evidence | Planned independent gate |
| --- | --- | --- |
| OIDC Core code flow, ID token and UserInfo validation | Unit tests and Keycloak browser/code flows | Basic RP; C04-C05 |
| Discovery, exact issuer and signing-key changes | Discovery/JWKS tests and Keycloak rotation | Configuration RP; C06 |
| Form POST callback and browser binding | Real browser and retained-connection tests | Form Post Basic RP; C07 |
| Refresh identity continuity | Refresh validation and retained-connection tests | OIDC client refresh plan; C08 |
| Public clients, other auth methods and async transport | Keycloak and worker tests | Applicable extended-plan variants; C09 |
| PAR, DPoP and mTLS | Keycloak and independent Python exchanges | FAPI 2.0 Security Profile; C10-C11 |
| JAR/JARM combinations | Independent Python fixture and Keycloak capability tests | FAPI Message Signing; C12; second full provider C13-C14 |
| SMART App Launch | SMART browser fixtures and corrected Inferno simulator | Existing Inferno gate remains separate |

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
