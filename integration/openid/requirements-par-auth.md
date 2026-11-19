# PAR and JWT client-authentication requirements

This map accounts for the directly applicable client and assertion-producer
clauses in [PAR, RFC 9126](https://www.rfc-editor.org/rfc/rfc9126.html),
[the assertion framework, RFC 7521](https://www.rfc-editor.org/rfc/rfc7521.html)
and [the JWT assertion profile, RFC 7523](https://www.rfc-editor.org/rfc/rfc7523.html).
It identifies implementation, regression definitions and existing reports for
the source surveyed at `0d49ad37089109f0c0f65db2b994f87271f777c9`.
The focused development result below is separate from historical provider and
suite reports. Open evidence items remain open; an accounted-for requirement
does not automatically have complete evidence.

The supported assertion role is self-issued JWT client authentication with
`client_secret_jwt` or `private_key_jwt`, including authenticated PAR. A client
authentication assertion, a signed authorization Request Object and an ID token
have different purposes and processing rules. PAR also works with configured
Basic, body-secret, public-client and mTLS authentication, whose additional
rules belong in the [OAuth](requirements-oauth.md) and [FAPI](requirements.md)
maps. The [JWT/Message Signing map](requirements-jwt-signing.md) covers the JAR,
JARM and JWT BCP dependencies; it does not turn client assertions into JAR.

The package implements the client role. The authorization server (AS) registers
credentials, authenticates clients, issues and validates PAR references, and
decides whether to issue grants. Application operators select trusted metadata,
registered identifiers, secrets/keys and TLS endpoints. Server rejection tests
establish only the observed server scenario, while a decoded JWT alone proves
neither its signature nor AS acceptance.

## Concrete evidence

| ID | Implementation and assertions inspected |
| --- | --- |
| P1 | [methods__login.R](../../R/methods__login.R), `build_authorization_params()` / `build_auth_url()` / `push_authorization_request()` / `attach_par_auth_url_metadata()`. [test-par.R](../../tests/testthat/test-par.R) captures the pushed form and browser URL; rejects caller-supplied references, non-201/non-JSON responses, invalid/duplicate references and noninteger lifetimes; verifies that rejected setup registers no pending state; and advances a controlled clock through delayed responses and nonce retries. |
| P2 | `build_auth_url()` composes signed/encrypted `request` mode before PAR. [test-jar.R](../../tests/testthat/test-jar.R) decodes the form's separate Request Object and client-authentication assertion, checks inner authorization claims, and asserts absence of outer `response_type`, `redirect_uri` and shared-secret fields for JWT authentication. It also checks Basic authentication plus client ID and the rule that required PAR cannot be bypassed by caller-published `request_uri` mode. |
| P3 | [utils__state.R](../../R/utils__state.R), generated state/verifier/nonce and transaction binding; [test-state-reference.R](../../tests/testthat/test-state-reference.R) rejects a wrong browser before state consumption and exchange. [Keycloak PAR cases](../keycloak/test_integration_keycloak_par_unhappy.R) cover URI reuse/expiry/client binding; [outer-parameter confusion](../keycloak/test_integration_keycloak_jar_par_confusion.R) checks that outer state/nonce/PKCE/resource values cannot replace pushed parameters. [Browser coverage](../keycloak/browser-attack-coverage.md) supplies the separate cookie/redirect boundary. |
| C1 | [utils__jwt_signing.R](../../R/utils__jwt_signing.R), `build_client_assertion()` / `resolve_client_assertion_audience_url()`, and [utils__http_requests.R](../../R/utils__http_requests.R), `apply_direct_client_auth()` / `req_refresh_jwt_client_assertion_on_retry()`. [test-client-jwt-auth.R](../../tests/testthat/test-client-jwt-auth.R) inspects assertion type, absence of a form secret, signed-header/claim values and audience overrides on code/refresh/introspection/revocation paths. [test-jwt-uri-identifiers.R](../../tests/testthat/test-jwt-uri-identifiers.R) verifies HMAC/asymmetric signatures before checking preserved URI identifiers. |
| C2 | [test-outbound-jws-algs.R](../../tests/testthat/test-outbound-jws-algs.R) verifies real HMAC and asymmetric client-assertion signatures, including RS256. [test-signing-key-strength.R](../../tests/testthat/test-signing-key-strength.R) rejects undersized RSA keys; client-JWT tests reject short HMAC secrets and unadvertised algorithms. [test-input-validation-guards.R](../../tests/testthat/test-input-validation-guards.R) checks assertion lifetime default/clamping; [test-numeric-option-shapes.R](../../tests/testthat/test-numeric-option-shapes.R) checks malformed option shapes. |
| C3 | [utils__endpoint_auth.R](../../R/utils__endpoint_auth.R) resolves endpoint-specific authentication/credentials; [test-endpoint-auth.R](../../tests/testthat/test-endpoint-auth.R) checks independent keys, algorithms and audiences. `test-par.R` inspects a fresh JWT assertion on a DPoP nonce retry and issuer-preferred PAR audiences. [test-dpop.R](../../tests/testthat/test-dpop.R) inspects fresh assertion JTIs during code-exchange nonce retries; [test-no-retry-token-exchange-refresh.R](../../tests/testthat/test-no-retry-token-exchange-refresh.R) checks that ambiguous code/refresh delivery is not generically replayed. |
| C4 | [Keycloak JWT rejection cases](../keycloak/test_integration_keycloak_jwt_auth_unhappy_code_flow.R) check wrong secret/audience/algorithm/key, consumed callback state, no authenticated identity and rejected callback replay. [Keycloak assertion replay](../keycloak/test_integration_keycloak_jwt_client_assertion_replay.R) sends the same prepared assertion twice and separately checks distinct generated JTIs for new requests at PAR/token. The [independent strict AS](../conformance/strict_as.py), `verify_client_assertion()`, verifies signature, client, audience, expiry, issued-at and unused JTI; [test-strict-as.R](../conformance/test-strict-as.R) completes its RS256/RS384 JWT-auth code/refresh/introspection/revocation scenarios with and without PAR. |
| C5 | [test-client-assertion-expiry.R](../conformance/test-client-assertion-expiry.R) changes only the client-authentication assertion's expiration and signs it again with the registered RSA key. It verifies that signature locally, then exercises the real independent Python verifier over HTTPS at PAR/token for RS256/RS384. Exact error-body checks exclude grant/reference data; module assertions exclude tokens, authenticated identity and connections, consume token-callback state, and reject replay without another token request. Each failure is followed by a fresh successful public preparation/login. Separate Request Object, unknown-code, competing-authentication and wrong-signing-key controls distinguish the error boundary. |
| R1 | [helper-auth.R](helper-auth.R) requires named suite signature/type/claim conditions and inspects actual token forms; [helper-fapi.R](helper-fapi.R) checks actual PAR/token requests, matching client/issuer audience, lifetime bounds, distinct JTIs and S256 pairs. Its decoded metadata fields are distinct from the suite's required signature-verification conditions. [helper-signing.R](helper-signing.R) checks the actual JAR body/signature separately. [scope.md](scope.md) retains per-selection limits; [release-review.md](release-review.md) records the complete 29-module Message Signing/mirai result at `65fbdc8e49d70e85f99cbccc527428c91a785992`, including [hosted run 44403727783](https://github.com/lukakoning/shinyOAuth/actions/runs/44403727783). That historical schema-3 result does not acquire later source-qualified status retroactively. |

## RFC 9126 client duties and response handling

| ID / clause | Applicable client duty or conditional feature | Implementation, evidence and boundary |
| --- | --- | --- |
| PA1 / [2](https://www.rfc-editor.org/rfc/rfc9126.html#section-2), [2.1](https://www.rfc-editor.org/rfc/rfc9126.html#section-2.1) | Use authenticated HTTPS POST with a UTF-8 form, as applicable to the client. | P1 applies the resolved authentication method, mTLS if configured, request defaults, form encoding and POST. `test-par.R` inspects Basic/body/JWT/public forms; C3 covers mTLS alias/audience behavior. Public client ID is not authentication. [utils__tls.R](../../R/utils__tls.R) and [test-tls-policy.R](../../tests/testthat/test-tls-policy.R) provide outbound verification controls. HTTP fixture exceptions earn no production TLS credit. |
| PA2 / [2.1](https://www.rfc-editor.org/rfc/rfc9126.html#section-2.1) | Exclude a supplied `request_uri`; keep authentication separate from authorization parameters. | P1 rejects that field before dispatch. Protected provider/extra-parameter validation prevents credential and transaction-field overrides. P2 separates client-authentication fields from the authorization Request Object. Explicit header/parameter-unblock options require a separate configuration assessment. |
| PA3 / [2, audience guidance](https://www.rfc-editor.org/rfc/rfc9126.html#section-2) | Prefer the issuer as a JWT client-assertion audience. | C1/C3 prefer the configured issuer at PAR, including mTLS aliases; without one they retain the canonical PAR URL. Tests inspect the signed claim and explicit override. The AS's obligation to accept its issuer/token/PAR endpoint identifiers is an AS duty. A configured override needs agreement with that AS; FAPI's stricter issuer-string rule remains separate. |
| PA4 / [2.2](https://www.rfc-editor.org/rfc/rfc9126.html#section-2.2), [2.3](https://www.rfc-editor.org/rfc/rfc9126.html#section-2.3) | Consume the successful reference/lifetime contract; stop on PAR failure. | P1 requires 201 JSON, one usable absolute reference without a fragment, and a positive integer lifetime. Duplicate/array/malformed data and already-expired responses fail before pending-state registration. Tests check a conservative deadline from the successful attempt start. Status/body generation, reference entropy and client binding are AS duties; their presence in a response does not prove those properties. |
| PA5 / [3](https://www.rfc-editor.org/rfc/rfc9126.html#section-3) | With JAR, place authorization parameters inside `request`; keep client-authentication data in the form. | P2 decodes both JWT purposes and checks body placement, client ID and absence of copied authorization fields. The [JAR map](requirements-jwt-signing.md) retains signing/encryption and Request Object validation dependencies. Optional caller-published references use a different route and are rejected when PAR is required. |
| PA6 / [4](https://www.rfc-editor.org/rfc/rfc9126.html#section-4) | Build authorization from the returned reference and use it for one authorization attempt. | P1 produces client-ID/reference browser parameters; minimal mode adds no authorization payload. [test-par-transaction-freshness.R](../../tests/testthat/test-par-transaction-freshness.R) prepares two attempts for the same public client with encrypted/reference state: two PAR posts, fresh state/nonce/S256 pairs, distinct intact pending records, and each HTTP stub's exact reference in its own minimal browser URL. [prepare_authorization_request.R](../../R/prepare_authorization_request.R) documents one-login-attempt results and preserves expiry metadata. P3's deliberate URI replay tests AS rejection separately. Custom callers must not cache/reopen a returned authorization request. |
| PA7 / [4](https://www.rfc-editor.org/rfc/rfc9126.html#section-4), [5](https://www.rfc-editor.org/rfc/rfc9126.html#section-5), [6](https://www.rfc-editor.org/rfc/rfc9126.html#section-6) | Respect configured/discovered required-PAR policy. | Discovery retains the endpoint/boolean and rejects required PAR without an endpoint. P2 prevents caller-managed references from bypassing required PAR. `test-par.R` checks that unrelated OIDC `request_uri` capability/registration flags do not veto AS-issued PAR references. Static registration/operator policy still owns the per-client requirement; no dynamic-registration implementation is claimed. |
| PA8 / [7.5](https://www.rfc-editor.org/rfc/rfc9126.html#section-7.5) | Bind the pushed transaction against reference swapping with PKCE, state or nonce. | P1/P3 generate and bind these values, including inside JAR; R1 checks actual S256 pairs and nonce/state relationships. Outer-parameter and browser/callback cases supply distinct rejection evidence. Headless tests alone do not establish the cookie boundary. Disabling the relevant client protections cannot earn this credit. |

The remaining PAR security clauses have different responsible actors.
[2.4](https://www.rfc-editor.org/rfc/rfc9126.html#section-2.4) leaves acceptance
of transaction-specific redirect URIs to AS policy.
[7.1](https://www.rfc-editor.org/rfc/rfc9126.html#section-7.1) assigns reference
entropy to the AS; [7.2](https://www.rfc-editor.org/rfc/rfc9126.html#section-7.2)
assigns acceptance of new redirect URIs to authenticated-AS processing.
[7.3](https://www.rfc-editor.org/rfc/rfc9126.html#section-7.3) and
[7.4](https://www.rfc-editor.org/rfc/rfc9126.html#section-7.4) concern AS reuse and
policy checks. P3 provides selected enforcement scenarios, not a general AS
audit. [8](https://www.rfc-editor.org/rfc/rfc9126.html#section-8) describes privacy
benefits; applications still control authorization data, browser history,
logging and referrer exposure. PAR alone does not establish confidentiality of
every application path.

## RFC 7521/7523 client-authentication duties

RFC 7521 supplies the framework and RFC 7523 its JWT encoding. The numbered
JWT-format items below are producer requirements even though the section also
specifies how the AS must reject invalid assertions. RFC 7521's
[5.1 metamodel](https://www.rfc-editor.org/rfc/rfc7521.html#section-5.1) and
[6.1 client-authentication scenario](https://www.rfc-editor.org/rfc/rfc7521.html#section-6.1)
use the same issuer/subject/audience/time roles accounted for in JA1-JA7.

| ID / clauses | Client or self-issuing producer duty | Implementation, evidence and boundary |
| --- | --- | --- |
| JA1 / [7521 2](https://www.rfc-editor.org/rfc/rfc7521.html#section-2), [4](https://www.rfc-editor.org/rfc/rfc7521.html#section-4), [4.2](https://www.rfc-editor.org/rfc/rfc7521.html#section-4.2); [7523 1.1](https://www.rfc-editor.org/rfc/rfc7523.html#section-1.1), [2.2](https://www.rfc-editor.org/rfc/rfc7523.html#section-2.2) | Send the exact JWT assertion type and one serialized assertion over TLS. | C1 emits the registered `urn:ietf:params:oauth:client-assertion-type:jwt-bearer` and one compact signed JWT in a UTF-8 token form. Tests inspect the literal type and form fields; R1 requires suite extraction/type/signature conditions for actual traffic. Generic request merging cannot replace protected credential fields by default. TLS controls and development exceptions have PA1's scope. |
| JA2 / [7521 4.2](https://www.rfc-editor.org/rfc/rfc7521.html#section-4.2) | If supplying a form client ID, identify the assertion's client. | C1 uses the same client ID for the form and assertion subject; R1 compares the observed form, assertion and registered client. SMART may omit the optional form client ID on token/refresh requests. C3's per-endpoint credentials do not change the underlying client identifier. |
| JA3 / [7521 5.2](https://www.rfc-editor.org/rfc/rfc7521.html#section-5.2); [7523 3(1), 3(2B)](https://www.rfc-editor.org/rfc/rfc7523.html#section-3) | Include the self-issuer and client-authentication subject. | `build_client_assertion()` sets both `iss` and `sub` to the configured client ID. C1 verifies real signatures before exact URI-identifier checks; C4's independent AS separately checks the registered identity. Third-party assertion acquisition and resource-owner subjects are outside this implemented role. |
| JA4 / [7521 5.2](https://www.rfc-editor.org/rfc/rfc7521.html#section-5.2); [7523 3(3)](https://www.rfc-editor.org/rfc/rfc7523.html#section-3) | Identify the intended AS in `aud`. | C1 preserves the explicit audience string; otherwise token/refresh use the actual endpoint and PAR uses PA3's resolver. Tests retain an intentional trailing slash and inspect code/refresh/introspection/revocation overrides. AS audience/issuer comparisons and allowed identifier agreement remain AS/operator duties. A generic audience resolver is not the FAPI preset. |
| JA5 / [7521 5.2](https://www.rfc-editor.org/rfc/rfc7521.html#section-5.2); [7523 3(4)](https://www.rfc-editor.org/rfc/rfc7523.html#section-3) | Include a bounded expiration time. | C1 uses numeric epoch seconds with a default 120-second lifetime, clamped to 60-300 seconds. C2 checks default/minimum/maximum and malformed option behavior; R1 checks numeric claims and the observed window. C5 adds correctly signed expired-assertion rejection at PAR/token and fresh controls. Production AS expiry/leeway enforcement and acceptance of the selected lifetime remain external. |
| JA6 / [7521 5.2](https://www.rfc-editor.org/rfc/rfc7521.html#section-5.2); [7523 3(5-8)](https://www.rfc-editor.org/rfc/rfc7523.html#section-3) | Assess optional time, identifier and extra claims. | C1 emits numeric `iat` and a fresh random `jti`, omits optional `nbf`, and exposes no arbitrary assertion-claim injection. C3 inspects fresh JTIs during retries; R1 checks distinct observed values. `jti` generation does not establish AS replay storage. Omitting optional claims is not a format failure. |
| JA7 / [7521 5.2](https://www.rfc-editor.org/rfc/rfc7521.html#section-5.2); [7523 3(9-10)](https://www.rfc-editor.org/rfc/rfc7523.html#section-3), [5](https://www.rfc-editor.org/rfc/rfc7523.html#section-5) | Apply a signature/MAC and implement RS256. | C1/C2 verify actual HMAC/asymmetric signatures, algorithm/key compatibility and key strength. RS256 is implemented, while other configured algorithms have their own interoperability evidence; the profile does not require every request to use RS256. AS signature/JWT rejection remains separate. The [JWT BCP map](requirements-jwt-signing.md) records additional key/algorithm/validation scope and gaps. |
| JA8 / [7521 4.2.1](https://www.rfc-editor.org/rfc/rfc7521.html#section-4.2.1); [7523 3.2](https://www.rfc-editor.org/rfc/rfc7523.html#section-3.2) | Handle failed client authentication without accepting grants. | C4/C5 check typed/module failure, consumed callback state and absence of authenticated identity. [test-oauth-error-json-shape.R](../../tests/testthat/test-oauth-error-json-shape.R) rejects ambiguous error interpretation. `invalid_client` generation belongs to the AS. C5 requires that code for expired/invalidly signed assertions and competing authentication in the fixture's JWT-authentication profile, applying RFC 7521's assertion-specific rule. Keycloak's PAR replay case expects `401`/`invalid_request`; that remains denial evidence, not proof of the specified AS error code. |
| JA9 / [7521 7](https://www.rfc-editor.org/rfc/rfc7521.html#section-7); [7523 5](https://www.rfc-editor.org/rfc/rfc7523.html#section-5) | Agree on identifiers, credentials and accepted assertion policy. | C3 permits explicit endpoint credentials/audiences; static fixture registration in [helper-suite.R](helper-suite.R) publishes only public JWK material and registers the selected authentication algorithm. Operators provision production keys/secrets and accepted lifetime/replay policy. Discovery cannot establish the trustworthiness of an application-supplied issuer. |

## Security, optional paths and exclusions

| Clauses | Responsible actor and evidence | Remaining scope |
| --- | --- | --- |
| [7521 3](https://www.rfc-editor.org/rfc/rfc7521.html#section-3), [8.1](https://www.rfc-editor.org/rfc/rfc7521.html#section-8.1) | Self-issuer/client: C1/C2 sign or MAC with configured credentials. AS: C4 and required R1 suite conditions verify selected assertions. | The transport assertion remains a bearer credential; DPoP/mTLS token constraints are separate mechanisms. No generic holder-of-key assertion exchange or third-party token service is implemented. |
| [7521 8.2](https://www.rfc-editor.org/rfc/rfc7521.html#section-8.2); [7523 6](https://www.rfc-editor.org/rfc/rfc7523.html#section-6) | Client/operator: TLS, short lifetime, fresh assertion per attempt and credential custody. C3 prohibits generic code/refresh replay and rebuilds assertions for allowed nonce/introspection/revocation retries. AS: C4 checks selected replay denial. | Base RFC 7523 replay protection is optional; stricter OIDC/FAPI configurations can require it. Positive fresh-JTI tests cannot establish a production AS replay cache. External credential copies and logs need operator controls. |
| [7521 8.3](https://www.rfc-editor.org/rfc/rfc7521.html#section-8.3), [8.4](https://www.rfc-editor.org/rfc/rfc7521.html#section-8.4); [7523 7](https://www.rfc-editor.org/rfc/rfc7523.html#section-7) | Client/operator: C1 limits claims to client identity, audience, time and JTI. [test-oauth-error-privacy.R](../../tests/testthat/test-oauth-error-privacy.R) and [test-http-metadata-privacy.R](../../tests/testthat/test-http-metadata-privacy.R) check diagnostic disclosure controls. | Encrypted client-authentication assertions, third-party attribute consent and anonymous-resource-owner assertions are not implemented by this builder. Outbound JAR encryption is a different feature. Deployment storage/log confidentiality and privacy assessment for client identifiers linked to end users are not proved by request tests. |
| [7521 4.1, 4.1.1](https://www.rfc-editor.org/rfc/rfc7521.html#section-4.1), [6.2](https://www.rfc-editor.org/rfc/rfc7521.html#section-6.2), [6.3](https://www.rfc-editor.org/rfc/rfc7521.html#section-6.3); [7523 2.1](https://www.rfc-editor.org/rfc/rfc7523.html#section-2.1), [3.1](https://www.rfc-editor.org/rfc/rfc7523.html#section-3.1), [4](https://www.rfc-editor.org/rfc/rfc7523.html#section-4) | Unsupported grant/scenario accounting: public package token builders emit `authorization_code` or `refresh_token`, with JWT as client authentication. | No generic JWT/SAML bearer assertion grant, third-party assertion acquisition, anonymous-user assertion grant or public `client_credentials` grant API is claimed. Manually constructed provider-control requests in integration helpers do not supply such a public client flow. `invalid_grant` and delegated scope rules from those grant sections earn no coverage here. |
| [7523 6](https://www.rfc-editor.org/rfc/rfc7523.html#section-6), inherited specifications | The [OAuth](requirements-oauth.md) and [JWT/Message Signing](requirements-jwt-signing.md) maps account for selected OAuth/JWT BCP/JAR duties; PA1 and C1/C2 identify concrete transport/cryptography controls. | Complete inherited JWT/JWS/JWA, credential-custody and deployment-security audits remain separate. This direct-clause map does not establish AS conformance or close the overall SA04/release-evidence work. |

## Fixture correction and development validation

C5 exposed a concrete fixture defect: assertion-claim and cryptographic
verification failures were reaching the generic `invalid_request` handler.
The fixture now translates failures inside JWT client authentication to
`invalid_client`, including competing authentication under RFC 7521 section
4.2.1. Request Object and authorization-code processing remain outside that
boundary. The validly signed expired assertions must produce the exact
`assertion_expiry` reason; invalid signatures must produce
`assertion_signature`. This changes the independent fixture and its regression
evidence, not the package's assertion producer.

The unknown-code negative deliberately preserves the fixture's existing
`invalid_request` / `invalid_code` response as a non-assertion control. It does
not establish complete RFC 6749 token-error conformance; the `invalid_grant`
taxonomy remains a separate audit item. Sessions are driven in process with a
simulated fresh cookie acknowledgement, without browser transport or mirai
workers. TLS and actual signature verification remain enabled.

The accepted focused runs used private installations of the dirty checkout at
`d287b56f763fd8331c9978d5068adb9ac544e3d6`. Windows and Linux each passed
111 assertions across five cases, with zero failures, errors, skips or test
warnings. Windows additionally reported four locale warnings during R startup;
those were separate from the test results. Before the correction, the expiry
and signature regression produced five assertion failures, with the fresh
controls succeeding. These are development results for the observed local
fixture, not source-qualified release results or a new hosted conformance run.

## Focused preparation regression

The repeated-preparation gap in PA6 now has a focused regression through public
`prepare_call()`. For each state transport, the same public OAuth client prepares
two attempts. Only `httr2::req_perform()` is stubbed, returning a different PAR
reference for each request. The test checks the actual request objects, client
ID and pushed fields, independently recomputes each S256 challenge from its
retained verifier, and compares the nonce with its pending record. Both states,
nonces and verifiers must differ; the first record remains unchanged after the
second preparation. Each browser URL contains exactly one client ID and its own
returned reference, with no pushed authorization parameters copied into it.

On 2026-11-19, all 136 new assertions passed on Windows and Linux. The relevant
PAR/state/callback and parameter-handling scope passed 758 assertions on each
platform, including those 136, with zero failures, errors, test warnings or
skips. Local results are retained under
`codex/par-transaction-freshness/{windows-final,linux-final}/results.csv`.
Windows retained its existing locale messages during R startup. These are unit
results for request construction and state retention, without a live AS,
browser navigation, reference-entropy assessment or server single-use proof.
P3's deliberate URI replay remains separate provider evidence; custom callers
still own their exported browser requests.

No new hosted OIDF or Keycloak run accompanies this map. Retain the original
report/source identities and [source-policy boundary](source-identity.md) when
assembling future release evidence. The focused fixture result does not close
the complete inherited-security audit or establish AS certification.
