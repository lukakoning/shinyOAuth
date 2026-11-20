# OAuth security requirements and evidence

This SA04 map accounts for the protocol/security clauses in sections 2–4 of
[RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html), including the section 3
assumptions. Accounting includes unsupported features, external duties and
unresolved work; a row does not mean its requirement is met. The initial
2.1–2.2/4.2–4.8 review used `f9056d9b12fd8f11e24eacfcb2c1317ac9b8261b`;
the remaining-clause review used `5f218e22f8156c65efaf9cf204a12d6fdff0d9b5`.
This document adds threat and role
accounting to the existing [OAuth map](requirements-oauth.md), rather than
repeating its parameter, metadata and transport audit. The
[OIDC map](requirements-oidc.md), [PAR/authentication map](requirements-par-auth.md),
[sender-constraint map](requirements-sender-constraints.md) and
[JWT map](requirements-jwt-signing.md) retain their detailed extension rules.

Rows below identify code and concrete regression definitions. Writing the map
adds no test execution, provider verdict, certification or source-qualified
release result. The [scope](scope.md), [release review](release-review.md) and
[source identity](source-identity.md) describe the separate retained evidence.
This accounting does not close the listed gaps or establish blanket compliance.
SA04's overall status belongs to the implementation plan; SA08 still owns the
combined release evidence set.

## Configuration and roles

The reviewed client uses the code flow, S256 PKCE, authenticated pending state
and browser binding. OIDC configurations additionally select ID-token validation
and `use_nonce = TRUE`; OAuth-only configurations retain state without an OIDC
nonce. Direct multi-issuer callbacks need the corresponding issuer policy, or
the separately configured JARM/distinct-route defense. These properties are
conditional: explicit plain/disabled PKCE, issuer opt-outs, signature/browser
test bypasses and arbitrary application HTTP handling earn no equivalent claim.

The package builds requests, checks responses and preserves transaction/key
context. The authorization server (AS) issues codes/tokens, enforces their
binding and controls registration. The resource server (RS) decides whether to
accept credentials and proofs. Operators select trusted issuer/endpoint tuples,
callbacks, keys, resource targets and browser/proxy deployment. Client checks
cannot establish these external properties. The topic column is a short clause
index; the linked RFC supplies the normative conditions and requirement levels.

## Evidence index

| ID | Independently inspected implementation and assertions |
| --- | --- |
| S1 | [methods__login.R](../../R/methods__login.R), `prepare_call_internal()` / `build_authorization_params()`, generates fresh state, a 64-character verifier and a 32-character OIDC nonce when enabled; the request fixes `response_type = "code"`. [utils__random.R](../../R/utils__random.R) uses OpenSSL randomness. OAuth PK01–PK03 index generator bounds, the independent S256 vector and request/exchange pairing. [test-par-transaction-freshness.R](../../tests/testthat/test-par-transaction-freshness.R) repeats public-client preparation for encrypted/reference state, independently hashes both verifiers, checks distinct state/nonce/reference values and preserves the first pending record. Its only HTTP boundary is stubbed; it does not assess AS entropy or reference reuse. |
| S2 | [utils__state.R](../../R/utils__state.R), callback processing in S1 and [oauth_module_server.R](../../R/oauth_module_server.R) validate client/provider/callback/policy, browser marker, deadlines and one-use pending records. [test-login-callback.R](../../tests/testthat/test-login-callback.R) rejects wrong browser markers, missing/malformed verifiers and replay. [test-state-reference.R](../../tests/testthat/test-state-reference.R), `wrong-browser reference callbacks cannot consume or exchange, and replays fail`, also checks that the rightful callback remains usable. [Browser attack coverage](../keycloak/browser-attack-coverage.md) identifies separate wrapper/browser cases; a `testServer()` assertion alone does not exercise cookies or cross-site navigation. |
| S3 | [OAuth IS01–IS03](requirements-oauth.md) index `enforce_callback_issuer()` and [test-callback-iss-validation.R](../../tests/testthat/test-callback-iss-validation.R): exact present-issuer comparison, required presence, error callbacks and multi-issuer configuration. [test-callback-route-validation.R](../../tests/testthat/test-callback-route-validation.R), `distinct redirect routes stop a public-client provider mix-up`, exercises two module routes and an exchange sentinel. [Keycloak issuer cases](../keycloak/test_integration_callback_issuer.R) include a real second-realm issuer swap with legitimate-state recovery. [utils__jwt_jarm.R](../../R/utils__jwt_jarm.R) checks the signed response's expected issuer before code exchange; its JWT rules remain in the JWT map. |
| S4 | In S1, `verify_token_set()` validates the token-endpoint ID token before constructing an accepted `OAuthToken` or fetching UserInfo. [test-jwt-purpose-separation.R](../../tests/testthat/test-jwt-purpose-separation.R), `nonce-bound ID-token callbacks reject timed UserInfo and another transaction's ID token`, uses real signatures and HTTP stubs: native responses authenticate, while missing/wrong nonce yields one required token request, zero UserInfo requests, no installed token and no authentication. [test-userinfo-after-id-token-validation.R](../../tests/testthat/test-userinfo-after-id-token-validation.R) separately checks ordering and subject binding. The JWT map's G2 records nonce-free ID-token/UserInfo overlap; these controls are not unconditional JWT-purpose separation. |
| S5 | [oauth_ui.R](../../R/oauth_ui.R), [oauth_connections_ui.R](../../R/oauth_connections_ui.R) and [oauth_form_post_ui.R](../../R/oauth_form_post_ui.R) provide HTTP callback handling and privacy headers. [test-get-callback-bridge.R](../../tests/testthat/test-get-callback-bridge.R), `GET code, error and JARM callbacks redirect before application rendering`, checks accepted 303 continuations, no application rendering, no-store/no-referrer and the URL available to application scripts. [utils__callback_rejection.R](../../R/utils__callback_rejection.R), `oauth_callback_rejection_wrap()`, now supplies a separate bounded error continuation for marked package-owned validation failures. [test-callback-rejection-cleanup.R](../../tests/testthat/test-callback-rejection-cleanup.R) covers that lifecycle, safe diagnoses and pending-state/accepted-handle preservation; [test-browser-callback-rejection-cleanup.R](../../tests/testthat/test-browser-callback-rejection-cleanup.R) exercises Chrome query/fragment cleanup using precomputed wrapper responses. [test-oauth-ui.R](../../tests/testthat/test-oauth-ui.R) retains header/asset-referrer checks; [test-form-post-response-mode.R](../../tests/testthat/test-form-post-response-mode.R) covers POST handling. [Keycloak callback cleanup](../keycloak/test_integration_module_shiny_browser_callback_cleanup.R) inspects the final login URL/title. The [selected rejection evidence and limits](#selected-rejected-callback-cleanup) distinguish these checks from a browser-history or application-wide audit. |
| S6 | [OAuth A6/BE01–BE03](requirements-oauth.md) index header-only resource transport, competing query/form token rejection, destination binding, redirect rejection and verified backend TLS. [test-resource-token-transport.R](../../tests/testthat/test-resource-token-transport.R) inspects shaped requests, including encoded query collisions. [test-jwt-at-hash.R](../../tests/testthat/test-jwt-at-hash.R) checks valid/mismatched hashes, omission policy and selected algorithm mappings. The code-flow ID-token default permits an absent `at_hash`; enabling its requirement is an explicit policy, not implicit-flow support. |
| S7 | [Sender-constraint evidence](requirements-sender-constraints.md) separates configured DPoP/mTLS request construction from AS/RS enforcement. It indexes actual-signature proofs, bound public-client refresh, wrong-key/wrong-certificate denials, independent RS scenarios and the OIDF mTLS simulator's non-denial limitation. [OAuth A5/OA10–OA11](requirements-oauth.md) index adoption of rotated refresh credentials, omitted-token retention, single-flight dispatch and no generic retry after a possibly consumed refresh. These do not establish every AS's rotation/replay policy. |
| S8 | [Keycloak PKCE](../keycloak/test_integration_keycloak_pkce.R) defines public-client success, local missing-verifier rejection before exchange and actual AS wrong-verifier denial. [Authorization tampering](../keycloak/test_integration_keycloak_pkce_authorization_tamper.R) removes the challenge, substitutes plain and supplies a malformed challenge; the configured enforcing AS must issue no code. [Cross-client PKCE](../keycloak/test_integration_cross_client_pkce.R) tests client/code binding independently. Local preparation failures, provider rejection and the pinned Basic RP fixture's verifier limitation remain separate. |
| S9 | [utils__resource_binding.R](../../R/utils__resource_binding.R), `resolve_bound_resource()`, limits connection requests to a configured scheme/host/port and path base before credentials are attached. [test-resource-binding.R](../../tests/testthat/test-resource-binding.R) rejects origin changes, ambiguous paths and attempts to widen this policy with generic URL options. [test-refresh-scope-narrowing.R](../../tests/testthat/test-refresh-scope-narrowing.R) checks reduced grants; [resource indicators](../../tests/testthat/test-resource-indicators.R) and [connection targets](../../tests/testthat/test-connection-targets.R) inspect separately declared token targets. The sender-constraint map's R1–R2/RI rows retain actual provider/audience observations and their limits. [SMART authorization details](../../tests/testthat/test-smart-authorization-details.R) check location-specific context, refresh and ambiguous data; this is not general RFC 9396 authorization-details support. |
| S10 | [utils__connection_credentials.R](../../R/utils__connection_credentials.R) defines retained credential encryption and deployment-controlled key requirements. [test-connection-credentials.R](../../tests/testthat/test-connection-credentials.R), `encrypted credential schemas retain token continuity without live objects`, checks ciphertext/tag/IV tampering, wrong owner/connection/key and changed client policy. [test-refresh-credential-outcome.R](../../tests/testthat/test-refresh-credential-outcome.R) distinguishes consumed, rejected, possibly consumed and unchanged renewal outcomes. The module/connection lifecycle uses those outcomes; [test-refresh-rejected-cleanup.R](../../tests/testthat/test-refresh-rejected-cleanup.R) also distinguishes public errors from owner-only cleanup credentials. Raw token objects, custom caches and exported credentials do not acquire retained-connection encryption automatically. |
| S11 | [utils__tls.R](../../R/utils__tls.R), `resolve_effective_tls_policy()`, applies a TLS 1.2 floor while preserving stronger constraints and rejects disabled certificate/hostname verification under that policy; [test-tls-policy.R](../../tests/testthat/test-tls-policy.R) exercises these options. OAuth A7/MD01–MD04 index discovery and exact metadata handling; A3 and the PAR/authentication map index configured Basic, body-secret, JWT and mTLS authentication. [check_oauth21.R](../../R/check_oauth21.R) separately reports asymmetric-authentication advice and unresolved deployment properties; [test-check-oauth21.R](../../tests/testthat/test-check-oauth21.R) checks selected HTTP endpoints, effective mTLS paths, custody/server unknowns and side-effect-free assessment. Its draft-specific configuration verdict is not this RFC audit or an observation of deployed TLS/AS behavior. |
| S12 | [shinyOAuth.js](../../inst/www/shinyOAuth.js) supplies local browser binding and Shiny input handling; the package has no OAuth authorization/token response mode based on `postMessage`. Its GET/POST/JARM receiving paths are S3/S5. [oauth_connections_ui.R](../../R/oauth_connections_ui.R) applies `frame-ancestors 'none'` and restrictive CSP to its owner-recovery pages; [test-connection-strict-callbacks.R](../../tests/testthat/test-connection-strict-callbacks.R) checks CSP on Strict-cookie callback transition documents, including valid OAuth error callbacks. These selected pages are not AS login/consent pages and do not establish a framing policy for an application's full UI. |

## Redirect and replay recommendations

| ID / exact clause | Topic | Configured behavior and evidence | Role or remaining limit |
| --- | --- | --- | --- |
| SC01 / [2.1](https://www.rfc-editor.org/rfc/rfc9700.html#section-2.1) | Redirect integrity | S1 uses the configured redirect in both requests; S2 binds it to pending state. [test-redirect-uri-open-redirect.R](../../tests/testthat/test-redirect-uri-open-redirect.R) rejects a changed redirect inside the state payload. S3 and SC08–SC09 account for response/route handling. | AS registration matching and credential-preserving redirects are external. An application/reverse-proxy redirect-route inventory remains necessary; state tamper rejection does not prove there are no deployed open redirectors. SC20/SC23 retain these gaps. |
| SC02 / [2.1.1](https://www.rfc-editor.org/rfc/rfc9700.html#section-2.1.1) | Public/confidential PKCE; transaction binding | S1–S2 generate/store S256 inputs per transaction and bind them to the initiating browser context. S8 distinguishes client behavior from actual AS verifier enforcement. S4 records the additional OIDC nonce check. | Public/shared-secret/private-key authentication does not enable PKCE by itself. Select S256 explicitly or retain its enabled default; plain/disabled settings do not supply this evidence. The nonce-only path is not a substitute for public-client PKCE. |
| SC03 / [2.1.2](https://www.rfc-editor.org/rfc/rfc9700.html#section-2.1.2) | Code rather than implicit | S1 constructs code requests; credentials enter through the back-channel token response. The package implements neither implicit nor hybrid response types. | No implicit-flow leakage/injection mitigation or hybrid front-channel ID-token validation is claimed. Application handling of exported tokens remains separate. |
| SC04 / [2.2.1](https://www.rfc-editor.org/rfc/rfc9700.html#section-2.2.1) | Access-token replay | S7 provides selectable DPoP or certificate-bound requests and selected enforcing-provider/resource scenarios. | Ordinary Bearer configuration remains supported. AS issuance/binding and RS proof/replay enforcement are server properties; a proof header or decoded confirmation claim alone establishes neither. |
| SC05 / [2.2.2](https://www.rfc-editor.org/rfc/rfc9700.html#section-2.2.2) | Public-client refresh replay | S7 preserves the configured binding key/certificate and adopts rotated credentials; its separate public DPoP refresh cases require the original key. | An unbound public refresh configuration does not acquire rotation/reuse detection from the client library. Confirm the AS policy and retained enforcement evidence. Confidential-client authentication and public-client replay defenses are separate; SC26 records custody/lifecycle gaps. |

## Threat-specific accounting

| ID / exact clause | Topic | Configured behavior and concrete evidence | Role or remaining limit |
| --- | --- | --- | --- |
| SC06 / [4.2.1](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.2.1), [4.2.2](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.2.2), [4.2.3](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.2.3), [4.2.4](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.2.4) | Referrer leakage | S5 applies no-referrer and moves accepted callbacks and marked package-owned GET/POST validation failures to separate opaque continuations before application rendering. Current [helper-fapi.R](helper-fapi.R), `openid_http_callback_matches()`, requires schema-2 `opaque_error_v1` proof: browser-observed 303-to-400 cleanup, both-hop privacy, a marker-only final URL, final-request Referer absence, no reflected long credentials, matching audit, preserved pending state and no callback module. S2 and S1/S8 separately cover local state and code/PKCE. | The [historical query-retention finding and current selected evidence](#selected-rejected-callback-cleanup) have different source/policy boundaries. Cleanup does not erase the original request from history or operator/proxy logs. Custom HTTP handlers, external resources/links and AS pages still require review; client code cannot establish AS code invalidation. |
| SC07 / [4.3.1](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.3.1), [4.3.2](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.3.2) | Browser history | S5 checks clean continuation/final URLs, POST response handling and removal of an inherited callback fragment. The selected malformed-callback cases require `callback_cleaned = true` with schema-2 proof. The separate [HTTPS cross-site Form Post selection](cross-site-form-post.md) verifies final query cleanup after success and a valid provider denial. S6 rejects resource-token query transport; S2 prevents reuse of locally consumed state, and S8 separately tests AS code/verifier behavior. | A clean terminal address bar does not prove the initial callback never entered browser history, logs or synchronized history. The historical `5f218e22` query-retention result remains unchanged. Other browser, proxy and cookie-policy deployments need their own evidence; exported tokens and application-created navigation remain outside resource-builder checks. |
| SC08 / [4.4.2](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.4.2), [4.4.2.1](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.4.2.1) | Multi-AS response binding | S2 binds the selected client/provider context; S3 checks direct `iss` or signed JARM before sending a code to the token endpoint. Exact issuer and missing-issuer rejection are configuration-tested, including success/error branches. The second-realm scenario verifies rejection and legitimate-state recovery. | A later token-endpoint ID-token issuer check alone is not the credited mix-up defense. Direct multi-issuer mode requires advertised RFC 9207 support; JARM is a separate route. Trusted issuer-to-endpoint configuration and browser binding remain necessary. Relaxed single-AS/issuer opt-out settings earn no general multi-AS claim. |
| SC09 / [4.4.2.2](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.4.2.2) | Distinct redirect routes | S3's `multi_redirect_uri` configuration requires a complete distinct callback set; route tests keep a code on its own route before dispatch. The low-level callback API rejects this mode because it lacks the receiving browser route. | Registration and deployment must preserve the per-issuer assignment. Query-only distinctions are rejected by constructor tests. Module route/exchange-sentinel evidence is not a production registration audit or browser proof; prefer the issuer-based configuration where available. |
| SC10 / [4.5](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.5), [4.5.3.1](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.5.3.1) | Code injection / PKCE | S1–S2 retain the original verifier for exchange; S8 separates local missing-verifier failure from AS wrong-verifier denial. The PAR freshness regression independently recomputes each challenge and keeps both transactions intact. | A state check or confidential-client authentication alone does not prove that a substituted code matches this transaction. The AS owns code/challenge enforcement; a complete same-client two-session browser code-injection result is not inferred from the separate pair and wrong-verifier tests. |
| SC11 / [4.5.3.2](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.5.3.2) | Nonce before token use | With `use_nonce = TRUE`, S4 verifies the actual token-endpoint ID token against the pending nonce before UserInfo or accepted token construction. Its signed positive and missing/wrong-nonce controls assert the relevant downstream side effects. | These HTTP-stub/module cases bypass the real browser-marker boundary, which S2 covers separately. They do not introduce hybrid support or prove every possible token consumer. Public-client PKCE remains required for the reviewed public configuration. |
| SC12 / [4.5.3.3](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.5.3.3), [4.5.4](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.5.4) | Alternatives and limits | The implemented transaction checks are S1–S4. Optional PAR/JAR request construction and signed-response validation have separate extension maps and configured evidence. | No additional cryptographic code-binding alternative is claimed here. Request integrity, response confidentiality and deployment custody remain separate: passing a verifier/nonce assertion does not close disclosure or altered-authorization-request threats. |
| SC13 / [4.6](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.6), [4.6.1](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.6.1) | Access-token injection | S1's code flow obtains access tokens from the configured backend endpoint. S4 verifies the ID token before token use; S6 supplies `at_hash` checks when present or explicitly required. S7 separately covers sender-constrained resource use. | No pure-OAuth implicit response is accepted as a supported flow. Optional `at_hash` checks in a code-flow client do not prove an implicit-flow defense. The package does not generally authenticate arbitrary exported access tokens; trusted endpoint/TLS and AS/RS behavior remain essential. |
| SC14 / [4.7](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.7), [4.7.1](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.7.1) | Redirection-endpoint CSRF | S2 protects pending state against tampering/swapping and binds it to the browser; wrong-browser/replay cases assert rejection, with separate real wrapper/browser definitions. S1/S4 add enabled PKCE/nonce context. The client retains state rather than relying solely on presumed AS PKCE support. The [selected HTTPS cross-site cases](cross-site-form-post.md) additionally observe Strict-cookie absence on the POST and successful browser-bound state consumption for login and valid denial. | PKCE capability metadata is checked as indexed in OAuth MD04/PK03, but metadata is not AS enforcement proof. Authorization-initiation consent remains separate application/FAPI work. The selected HTTPS loopback cases do not establish every browser, cookie policy, public-domain deployment or proxy configuration; HTTP loopback attack fixtures retain their own scope. |
| SC15 / [4.8](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.8), [4.8.2](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.8.2) | PKCE downgrade | S1 never retries S256 as plain; discovery rejects a plain-only capability unless explicitly selected. S2 keeps state/browser correlation. S8's configured enforcing AS rejects removed or downgraded challenges at authorization. | Rejecting a verifier when the issued code had no challenge is an AS rule. Authorization-stage rejection under a mandatory-PKCE fixture does not independently exercise that token-endpoint branch. Preserve this distinction when collecting release evidence; explicit plain/disabled client modes earn no S256 credit. |

## Additional protocol and deployment accounting

These rows complete the section index begun above. They distinguish assessed
client behavior from obligations of services and deployments that the package
does not implement. Unsupported grants/transports remain explicit rather than
becoming implicit requirements to add features.

| ID / exact clause | Topic | Observed package behavior and concrete evidence | Role or remaining limit |
| --- | --- | --- | --- |
| SC16 / [2.3](https://www.rfc-editor.org/rfc/rfc9700.html#section-2.3) | Privilege | S9 validates scopes, resource indicators and separately configured connection targets; reduced refresh grants stay reduced. Scope/resource/SMART assertions inspect the selected request and accepted context. | Operators decide which permissions/actions/resources are necessary. AS grant/audience issuance and RS scope/action/audience enforcement remain external; sending a resource string does not prove any of them. General RFC 9396 requests or a business least-privilege decision are not supplied by the SMART response-context checks. |
| SC17 / [2.4](https://www.rfc-editor.org/rfc/rfc9700.html#section-2.4) | Password grant | S1 and [methods__token.R](../../R/methods__token.R) implement authorization-code/refresh requests; no resource-owner password grant API is implemented. The login UI sends the browser to the provider rather than collecting an owner's password. | No password-grant compatibility mode or tests are credited. Applications that separately collect owner credentials or build raw grant requests are outside these client paths. |
| SC18 / [2.5](https://www.rfc-editor.org/rfc/rfc9700.html#section-2.5) | Authentication | S11's endpoint policy supports private-key JWT and both mTLS authentication styles, while retaining valid public/shared-secret configurations. The PAR/authentication and sender-constraint maps identify real signing, certificate and selected AS-denial evidence. `check_oauth21()` reports asymmetric-method advice separately from its mandatory configuration verdict. | Client registration, AS method enforcement and secret/private-key confidentiality require separate evidence. DPoP token binding is not client authentication; a confidential credential cannot be assumed safe because its path/value exists. |
| SC19a / [2.6](https://www.rfc-editor.org/rfc/rfc9700.html#section-2.6) | Metadata / TLS | S11 indexes exported OAuth/OIDC discovery, backend verification and configured TLS minima; S5 supplies selected HTTPS browser callback fixtures through the OIDF harness. The FAPI map's network rows retain cipher/backend and production-deployment limits. | Manual providers and endpoint overrides remain supported and require review. Backend TLS options do not attest the browser, proxy or internal hops, or complete current BCP195. HTTP loopback Shiny/web fixtures provide development evidence; they do not establish the native-app exception. Production authorization-response HTTPS remains a deployment/AS check. |
| SC19b / [2.6](https://www.rfc-editor.org/rfc/rfc9700.html#section-2.6) | CORS / identity / messaging | Client identity/account handling and browser response transport are SC27/SC29. The package is not an OAuth authorization server and supplies no AS endpoint CORS implementation. | AS authorization-endpoint CORS and optional CORS on other browser-accessed OAuth endpoints need operator evidence. Ordinary Shiny resource or fetch behavior does not establish either policy. |
| SC20 / [4.1](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.1), [4.1.3](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.1.3) | Redirect matching | S1 constructs code requests; S2 binds the configured callback; S3 checks receiving routes. OAuth OA05 and the PAR/JWT maps index unchanged redirect values through code exchange and signed/pushed requests. | AS registration comparison, native loopback variable-port handling and any AS decision to trust an authenticated PAR/JAR redirect are AS properties. Runtime canonical-route comparison is not AS exact-string registration evidence. The implicit/fragment examples in 4.1.1–4.1.2 do not add supported flows. SC23 retains the application redirect inventory; no fragment-rewriting mitigation is claimed. |
| SC21 / [4.9.1](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.9.1), [4.9.2](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.9.2), [4.9.3](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.9.3) | RS leakage | S6/S9 limit package-built credential destinations and transport. S7 indexes chosen sender constraints and selected enforcing RSs; S10 covers retained client credentials. | An approved base can still be the wrong operator-chosen server. Production RS compromise, token storage/logging and secret transport are not assessed by these client tests. Ordinary Bearer tokens have no sender-bound replay property; stolen key plus token is outside the protection supplied by a proof header. |
| SC22 / [4.10](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.10), [4.10.1](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.10.1), [4.10.2](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.10.2), [4.10.3](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.10.3) | Stolen tokens | S7 covers proof generation, observed binding policy and separate enforcing-server scenarios. S9 requests target-specific grants; the sender-constraint map separates actual audience observations from stock providers accepting `resource` without issuing a matching audience. Connection/resource bases come from application configuration, not the nonstandard `resource_servers`/`access_token_resource_server` fields discussed in 4.10.3. | AS issuance, RS audience/proof/replay checks and key custody remain essential. Local destination checks supplement those services and do not replace them. No general access-token JWT signature/audience verifier, hardware-keystore guarantee or certificate-fingerprint audience option is claimed. |
| SC23 / [4.11.1](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.11.1), [4.11.2](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.11.2) | Open redirects | S5's callback bridges use configured application routes and opaque local continuation handles; rejected callbacks use a query-only package-generated Location without a caller-controlled destination. S2 rejects changed sealed callback data. These are selected managed paths. | Inventory all application/proxy navigation and return-URL handlers; neither state checks nor a passing login prove that every deployed route is safe. AS invalid-client/redirect error handling, URI trust assessment, authentication/consent and silent-redirect policy are not implemented or certified by the client. Custom error routes still need their own confidentiality review. |
| SC24 / [4.12](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.12) | POST redirects | S5's own GET/POST callback continuation uses 303, with tests of the returned status and clean Location. S6/backend redirect tests separately stop credential forwarding by package-owned HTTP clients under their default policy. | These are not evidence about an AS redirecting a password-bearing authentication POST. The AS's 307 avoidance/303 choice and any intervening proxy behavior need their own review; package callback support does not prevent an upstream server from disclosing credentials. |
| SC25 / [4.13](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.13) | TLS proxies | S3 validates the configured callback route; S11 validates selected outbound connections. The suite's local HTTPS proxies and independent mTLS fixtures have explicitly bounded roles in the FAPI/sender-constraint maps. | Operators must establish trusted peer/header provenance and the confidentiality, integrity and replay protection of proxy-to-app links. No production inbound-header sanitization, certificate-forwarding trust or private-network protection is established here. Outbound peer verification and a local CA fixture do not cover those hops. |
| SC26 / [4.14.1](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.14.1), [4.14.2](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.14.2) | Refresh protection | S7/S10 provide protected transport, optional retained-credential encryption, configured authentication/binding, adoption of replacement tokens and lifecycle outcomes. Scope/resource-target tests limit client requests; bound public DPoP refresh and confidential mTLS cases have separate evidence. [Keycloak refresh protection](../keycloak/test_integration_keycloak_refresh_protection.R) defines successful identity continuity, explicit revocation and selected session-end revocation cases. | AS issuance risk, consented scope/resource binding, client binding, public replay detection, token integrity, grant-family invalidation, security-event revocation and inactivity expiry are AS policies, not consequences of local replacement. No general rotation-family replay/expiry assurance is credited. Applications own exported copies, direct refresh callers, cross-process coordination, storage permissions and encryption-key custody; selected revocation tests do not establish every AS logout/password-change policy. |
| SC27 / [4.15](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.15), [4.15.1](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.15.1) | Identity namespaces | The implemented grants are S1/S7 code/refresh; there is no client-credentials grant API. OIDC subject/audience checks and UserInfo subject binding have S4 evidence and the OIDC map. | AS registration controls the client identifier/claim namespace and issues any distinction needed by an RS; application resource authorization must preserve it. ID-token identity checks do not prove separation of user/client identities in arbitrary access tokens. No RFC 9068 issuer/RS conformance claim is made. |
| SC28 / [4.16](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.16) | Framing | S12 supplies CSP on selected local documents. The ordinary Shiny application remains operator-authored and the browser leaves it for provider authentication. | AS authorization/login/consent/error framing defenses, CSP, supported legacy-browser policy and any allowed client framing origins require AS configuration/evidence. No default application-wide framing guarantee or dynamic registration of frame origins is supplied by the package. |
| SC29 / [4.17](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.17), [4.17.2](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.17.2) | Browser messages | S12 has no OAuth `postMessage` response transport; query/form-POST/JARM paths have their own response/state checks. The examples in 4.17.1 are therefore an unsupported transport, not passing origin-validation cases. | Unrelated Shiny messages/sessionStorage binding do not establish OAuth message sender/receiver-origin enforcement. Any future or application-added transport needs independent exact-origin, destination, injection and transaction evidence; existing redirect results cannot supply it. |

## Attacker assumptions and evidence boundary

[Section 3](https://www.rfc-editor.org/rfc/rfc9700.html#section-3) supplies the
attacker categories. This table describes the actual scenarios and untested
assumptions in this repository; it is not a formal security proof or an
exhaustive model of a deployment.

| Category | Existing scenario or control | Unresolved environment assumption |
| --- | --- | --- |
| A1, web | S2/S3 isolate browser transactions, clients, issuers and receiving routes; wrapper cases use independent browser contexts. S9 limits configured resource destinations. | Operators still trust issuers/AS endpoint tuples and resource configuration. Tests of selected attacker pages/providers do not cover every application route, external script, login trigger or tenant selector. |
| A2, network | S11 supplies verified backend TLS/minima; the FAPI map identifies trusted-TLS and wrong-host/pin probes. | There is no arbitrary network-attacker experiment or complete browser/proxy/backend policy audit. Availability, trusted roots, DNS/deployment administration and internal hops remain environmental; client code cannot prevent network blocking. |
| A3, response observation | S1/S8 supply S256 and enforcing-provider scenarios; S2 binds/consumes state, and SC06–SC07 retain referrer/history limits. | State rejection alone is not credited for all response-disclosure scenarios. Initial URL/history/log visibility and compromised clients need separate treatment even when the final URL is clean. |
| A4, request observation | S1 sends an S256 challenge while retaining its verifier; selected PAR/JAR request evidence is indexed separately. | Plain/disabled PKCE does not inherit S256 protection. Front-channel minimization and signatures do not establish that an AS, operator log or custom request handler keeps all authorization data confidential. |
| A5, token acquisition | S7 distinguishes ordinary Bearer from configured sender constraints; S9 and the resource fixtures check selected destination/audience cases. | A real RS compromise or key-and-token theft is not simulated as a complete deployment. Key custody, token copies, RS enforcement and application compromise remain explicit limits. |

Client/browser or R-process compromise, untrusted dependencies, shared-worker
isolation and malicious endpoint configuration also need deployment-specific
assessment. In particular, a trusted issuer string and valid HTTPS syntax do not
prove that its endpoint tuple belongs to the intended authority. The tests
cover named boundaries and compatibility choices, not every stronger attacker
that an application may face.

## Selected rejected-callback cleanup

The SC06–SC07 finding at `5f218e22f8156c65efaf9cf204a12d6fdff0d9b5`
remains historical evidence: malformed HTTP callbacks returned the rejection at
the credential-bearing query URL. Those reports required
`callback_cleaned = false` and retain
`http_callback_rejection_retains_query`. The
[assessment policy](assessment.md#rejected-callback-cleanup) preserves their
original evidence; report schema 4 alone cannot grant cleanup credit.

SA07's implementation at `9288fbbe98c4d2730db5a1c1060b75588a3d2ab5`, with
the approved-diagnosis correction at `8cd6d166`, changes marked package-owned
GET/POST validation failures. The S5 wrapper returns an empty-body 303 to
`?shinyOAuth_callback_error=<opaque handle>#`, then the original rejection status
with an approved static diagnosis before application rendering. The explicit
empty fragment prevents inherited fragment credentials. Its separate process-local
cache holds at most 128 entries/1 MiB for 120 seconds and stores no raw callback
payload or condition. Another worker, expiry, eviction, replay or unavailable
cache yields a generic clean-URL 400; existing rejection audit diagnostics
remain available subject to the operator's retention policy.
Application-provided HTTP errors keep their existing behavior. The implementation
does not consume rightful pending OAuth state or accepted continuation handles.

In [test-callback-rejection-cleanup.R](../../tests/testthat/test-callback-rejection-cleanup.R),
`a missing reference record retains its typed rejection through public JARM callbacks`
uses real ES256 signatures and reference-state preparations through GET/POST
wrappers. Rejection requires the specific missing-record diagnosis, no HTTP
dispatch and an unchanged other pending record; subsequent rightful recovery
fetches only the expected trusted JWKS. Other cases cover marker tampering,
bounded storage, safe diagnosis selection and accepted-handle recovery. These
are package/unit HTTP-boundary controls; the separate Chrome regression serves
precomputed wrapper responses to test navigation/fragment behavior, without a
provider or browser-history claim. Existing direct-R validation controls retain
their own scope and do not earn browser-cleanup credit.

Windows and Linux each passed 3,803 assertions across 22 related package files
for the `9288fbbe` implementation, with browser/Ed25519 cases enabled and zero
failures, errors, test warnings or skips. The later `8cd6d166` diagnosis correction
passed 1,600 assertions per OS in the cleanup, form-POST response-mode and
JARM-response files, also with zero failures, errors, test warnings or skips.
The earlier 22-file result remains attached to its earlier source. The
[implementation record](../../.github/protocol-quality-implementation-plan.md)
retains these distinct scopes and the failed intermediate attempts.

At `8cd6d166`, the clean `fapi-oauth-dpop-reference`/sync selection passed all
11 required modules, including its four malformed-callback HTTP 400 cases.
Current [collector](helper-fapi.R), fixture [HTTP witness](fixture-app.R) and
[evidence checker](helper-evidence.R) require schema-2 `opaque_error_v1` proof
for these cases. This binds both responses and the terminal DOM to the browser's
main-frame navigation, requires an exact same-origin/path marker-only URL with
an empty fragment, checks no-store/no-referrer and long-credential nonreflection,
and combines browser request metadata with actual server-side final-request
Referer absence. It also requires the original audit reason, unchanged nonempty
pending state, no callback module and zero token/UserInfo/resource traffic.
It grants no token-exchange or resource-use credit to a rejection. The same
revision also passed all 29 Message Signing/mirai modules locally and in
[hosted run 44590006270](https://github.com/lukakoning/shinyOAuth/actions/runs/44590006270),
including ten schema-2 HTTP cleanup outcomes in each run. The
[release review](release-review.md)
records independently checked report/source identities, artifact digest and
timings. These selected clean-source results do not substitute for the final
aggregate release matrix.

This is selected final-URL cleanup, not global cleanup, certification or a
completed release matrix. Initial browser history, synchronized history,
server/proxy logs and unrelated application routes remain outside this evidence.
Production HTTPS, proxy headers and internal hops still need deployment checks.
The separate selected cross-site acceptance below does not establish every
browser or cookie/form-POST configuration. Worker-local diagnostic fallback does
not establish a shared rejection cache or universal routing policy.

## Selected HTTPS cross-site Form Post acceptance

At `d532cba3f4df7ce8c4cf9fa85211bf894899060f`,
[form-post-cross-site](cross-site-form-post.md) runs two modules from the pinned
30-module Comprehensive variant with static registration, code flow,
`client_secret_basic` and `response_mode = form_post`. The provider uses HTTPS
`localhost` and the app HTTPS `127.0.0.1`. Both cases require CA-verified app
readiness, wrong-SPKI rejection, Secure SameSite=Strict binding-cookie metadata,
the actual provider Origin and `Sec-Fetch-Site: cross-site`, and absence of that
Strict cookie on the POST. Browser-bound callback processing must finish with a
clean query URL; different port numbers alone earn no cross-site credit.

Success requires validated identity and exactly one token and UserInfo request;
mirai must perform that protocol work in a verified worker. A valid
`login_required` denial instead consumes its own state once, emits the existing
main-process `audit_error_state_consumed` event, shows a safe error and makes no
token/UserInfo request or protocol-worker dispatch. This denial does not use the
malformed HTTP 400 rejection path above, which preserves rightful pending state.

Each actual Windows sync/mirai entrypoint passed 8,274 evidence assertions with
zero failures, errors, test warnings or skips, then both client modules with
matching app/source/installation gates. The hosted Linux/mirai
[run 44640739188](https://github.com/lukakoning/shinyOAuth/actions/runs/44640739188)
also passed both modules, with a 9.92-second module loop and fresh preflight/API
metadata for 16 plan/variant inventories. API inventories earn no client-flow
credit. The [release review](release-review.md) records the separate acceptance
and source evidence. This selected HTTPS loopback deployment leaves production
certificate chains, other browsers, proxy/internal hops and other cookie policies
open. FAPI authorization-initiation consent, the complete release matrix and
certification remain separate work.

## Open work after clause accounting

The remaining decisions/checks are concrete: inventory deployed redirect routes
and custom HTTP/message handling (SC20/SC23/SC29); establish trusted resource
targets and actual AS/RS enforcement (SC16/SC21/SC22/SC26); review HTTPS/proxy
headers, internal hops and cookie/POST deployments beyond the selected cases
(SC19/SC25); review
credential/key storage, exports and cross-process refresh lifecycle (SC18/SC26);
and obtain the AS/application framing policy (SC28). The FAPI map retains its
separate authorization-initiation consent gap. Reuse existing source-qualified
results for each named property before adding missing scenarios.

[Section 5](https://www.rfc-editor.org/rfc/rfc9700.html#section-5) is the registry
note; [section 6](https://www.rfc-editor.org/rfc/rfc9700.html#section-6) introduces
no separate mechanism beyond the security treatment above. This map accounts
for the clauses with explicit limits; it does not resolve the deployment work
by classifying it as external.

Release aggregation and durable retention remain SA08 work. Neither this map
nor synthetic evidence-checker tests turn distinct development/provider runs
into one complete result for an identified release.
