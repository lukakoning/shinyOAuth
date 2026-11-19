# JWT and Message Signing requirement map

This SA04 map covers the final [FAPI 2.0 Message Signing profile](https://openid.net/specs/fapi-message-signing-2_0-final.html),
[JAR, RFC 9101](https://www.rfc-editor.org/rfc/rfc9101.html),
[JARM](https://openid.net/specs/oauth-v2-jarm-final.html) and
[JWT BCP, RFC 8725](https://www.rfc-editor.org/rfc/rfc8725.html).
It describes the runtime surveyed at `a009f5cf71b47d2606b75143b08ded925f161220`.
The [Security Profile map](requirements.md) covers inherited FAPI requirements;
the [OIDC](requirements-oidc.md) and [OAuth](requirements-oauth.md) maps account
for their own client duties.

Rows identify code and regression definitions. They do not record fresh test
execution. The [release review](release-review.md) retains the 29-module
Message Signing/mirai result at clean source
`65fbdc8e49d70e85f99cbccc527428c91a785992`, including hosted run
[44403727783](https://github.com/lukakoning/shinyOAuth/actions/runs/44403727783).
That schema-3 result establishes its recorded selection. The later
[schema-4 source policy](source-identity.md) does not retrospectively qualify
it or establish a complete release matrix. No row establishes certification.

## Configuration and evidence boundaries

The `fapi-message-signing` fixture uses discovered OIDC metadata, ES256
private-key JWT authentication, issuer-string assertion audiences, authenticated
PAR, reference state, S256, DPoP, `id_token_profile = "fapi2"`,
`request_object_mode = "request"`, ES256 JAR, `request_object_nbf_skew = 0`,
the default 45-second Request Object TTL, `response_mode = "jwt"` and ES256
JARM. The [fixture](fixture-app.R) constructs those settings through the public
API. A general client does not acquire them by enabling JAR or selecting the
FAPI ID-token algorithm policy alone.

The [manifest](profiles.json) resolves all 29 modules for this particular
OIDC/private-key-JWT/DPoP/query selection. Its completion flag does not cover
other sender constraints, authentication methods, encrypted responses or signed
introspection. The [selection documentation](README.md#fapi-message-signing)
describes its actual request collectors and rejection outcomes.

| Evidence ID | Concrete implementation and regression definitions |
| --- | --- |
| J1 | [utils__jwt_signing.R](../../R/utils__jwt_signing.R), `build_authorization_request_object()`; [methods__login.R](../../R/methods__login.R), `build_auth_url()` / `push_authorization_request()`. [test-jar.R](../../tests/testthat/test-jar.R) covers signed claims, extra authorization parameters inside PAR JAR, repeated resources, JSON claims, managed JWT claims, signing policy, publisher URLs and encrypted Request Objects. |
| J2 | [utils__jwt_jarm.R](../../R/utils__jwt_jarm.R), `validate_jarm_response()` / `verify_jarm_signature()` / `validate_jarm_claims()`; callback and POST-bridge entry points. [test-jarm-response.R](../../tests/testthat/test-jarm-response.R) covers claim/signature rejection, no-JWKS early failures, transport binding, direct-response downgrade, error responses, replay, encryption and delayed-expiry rechecks. |
| J3 | [helper-signing.R](helper-signing.R), `openid_signing_evidence()` / `openid_signing_matches()`: actual PAR JAR claims and ES256 signatures, named suite conditions, JARM mutations and independent signature checks, and zero code-redemption traffic for rejected callbacks. [test-signing.R](test-signing.R) mutates these proofs; synthetic gate tests earn no live protocol credit. The release review above records the live selection. |
| J4 | [utils__jwt_signing.R](../../R/utils__jwt_signing.R), `build_client_assertion()`; [test-client-jwt-auth.R](../../tests/testthat/test-client-jwt-auth.R), [test-client-jwt-defaults.R](../../tests/testthat/test-client-jwt-defaults.R), [test-endpoint-auth.R](../../tests/testthat/test-endpoint-auth.R) and [test-par.R](../../tests/testthat/test-par.R). [helper-fapi.R](helper-fapi.R) checks actual assertion signatures, metadata and issuer audiences at PAR/token. These are client-authentication assertions, distinct from JAR and signed introspection responses. |
| J5 | [utils__jwt_id_token.R](../../R/utils__jwt_id_token.R), `validate_id_token()`; [utils__jwt_parse.R](../../R/utils__jwt_parse.R), shared strict parsing/header/signature helpers; [utils__jwks_keys.R](../../R/utils__jwks_keys.R), key eligibility and verification; [utils__jwks_fetch.R](../../R/utils__jwks_fetch.R), trusted-provider key retrieval and refresh. Tests cited in the JWT BCP table isolate these controls. |
| J6 | [utils__jwt_jwe.R](../../R/utils__jwt_jwe.R), compact nested-JWT encryption/decryption; [test-jwt-jwe-roundtrip.R](../../tests/testthat/test-jwt-jwe-roundtrip.R), authenticated-decryption errors and RSA strength; [test-jarm-compression.R](../../tests/testthat/test-jarm-compression.R), `zip` rejection. |
| J7 | [Independent Python fixture](../conformance/README.md) / [test-strict-as.R](../conformance/test-strict-as.R) verifies RS256/RS384 JAR and exercises JAR plus signed JARM. [test-jar-jarm-live.R](../../tests/testthat/test-jar-jarm-live.R) exercises a local HTTP/module flow. These fixtures do not establish FAPI ES256 coverage or a real browser cookie boundary. |
| J8 | [Keycloak JAR](../keycloak/test_integration_keycloak_jar.R), [JAR rejection](../keycloak/test_integration_keycloak_jar_unhappy.R), [parameter confusion](../keycloak/test_integration_keycloak_jar_par_confusion.R) and [JARM](../keycloak/test_integration_keycloak_jarm.R) provide separate provider scenarios. [JAR claim observations](../keycloak/test_integration_keycloak_jar_claims.R) explicitly record server acceptance of wrong `aud`/`iss` and expired Request Objects; they supply no server-enforcement credit. Keycloak also rejects its tested signed-JAR-plus-JARM combination before login. |

## Final Message Signing client clauses

The topic column indexes the normative source; the implementation column names
the configuration to which the evidence applies.

| Clause / topic | Implementation and evidence | Boundary or remaining work |
| --- | --- | --- |
| [5, inherited profile](https://openid.net/specs/fapi-message-signing-2_0-final.html#section-5) | [Security Profile map](requirements.md); the configured flow above uses its PAR/authentication/sender-constraint controls. | JAR/JARM success does not close inherited deployment or lifecycle gaps. |
| [5.3.2(1), all authorization parameters in signed PAR JAR](https://openid.net/specs/fapi-message-signing-2_0-final.html#section-5.3.2-2.1) | J1/J3; collector checks the actual signed Request Object and permits only `client_id`, `request` and JWT client-authentication fields in the PAR form. | This pairing requires PAR plus JAR. General JAR-by-value and caller-published `request_uri` remain separate configurations. |
| [5.3.2(2), issuer audience](https://openid.net/specs/fapi-message-signing-2_0-final.html#section-5.3.2-2.2) | J1/J3; default Request Object audience resolves to the configured issuer, and the collector requires that exact scalar. | A caller-supplied `request_object_audience` can change the general client setting; review it explicitly. |
| [5.3.2(3), `nbf`](https://openid.net/specs/fapi-message-signing-2_0-final.html#section-5.3.2-2.3) | J1/J3; fixture sets `request_object_nbf_skew = 0`; generated `nbf` equals `iat`. | General default `NULL` omits `nbf`. Enabling JAR alone therefore does not satisfy this clause. |
| [5.3.2(4), bounded `exp`](https://openid.net/specs/fapi-message-signing-2_0-final.html#section-5.3.2-2.4) | J1/J3; fixture uses the 45-second default, with actual `exp`, `iat` and `nbf` checked. | General TTL/skew validation accepts positive TTL and nonnegative skew without a FAPI ceiling. For this profile, preserve an `exp`/`nbf` window within 3,600 seconds; G3 records missing configuration-boundary coverage. |
| [5.3.2(5), recommended JAR type](https://openid.net/specs/fapi-message-signing-2_0-final.html#section-5.3.2-2.5) | J1/J3; builder emits `typ = "oauth-authz-req+jwt"`, including the signed inner object when encryption is enabled. | No gap identified for the configured signing path. |
| [5.4.2(1), `jwt` response mode](https://openid.net/specs/fapi-message-signing-2_0-final.html#section-5.4.2-2.1) | J1/J3; `response_mode = "jwt"` appears inside the signed PAR object. | Explicit `query.jwt` and `form_post.jwt` are general JARM features; the recorded Message Signing result selects the `jwt` alias. |
| [5.4.2(2), JARM verification](https://openid.net/specs/fapi-message-signing-2_0-final.html#section-5.4.2-2.2) | J2/J3; see the JARM table below. | The live selection covers signed query responses, with invalid claims/signatures rejected before token traffic. |
| [5.5.2(1), requesting signed introspection](https://openid.net/specs/fapi-message-signing-2_0-final.html#section-5.5.2-2.1) | Unsupported conditional method. `introspect_token()` in [methods__token.R](../../R/methods__token.R) requests/parses JSON introspection. | JWT authentication of the request, including [test-introspect-jwt-auth.R](../../tests/testthat/test-introspect-jwt-auth.R), does not request RFC 9701 responses. |
| [5.5.2(2), verifying signed introspection](https://openid.net/specs/fapi-message-signing-2_0-final.html#section-5.5.2-2.2) | Unsupported conditional method. Current introspection parsing requires a JSON media type. | No RFC 9701 envelope/signature/audience validation or signed-introspection result exists. The [separate-method model in 5.1](https://openid.net/specs/fapi-message-signing-2_0-final.html#section-5.1) keeps this outside the selected JAR/JARM claim. |
| [5.6.2(1), ID-token signature](https://openid.net/specs/fapi-message-signing-2_0-final.html#section-5.6.2-2.1) | J5; FAPI algorithm policy plus actual signature verification, independent of transport security. J3 selection also exercises its declared invalid-ID-token modules. | Claims apply with signature validation enabled and unsafe testing overrides disabled. ID-token semantic coverage belongs in the OIDC map. |

Authorization servers own [5.3.1](https://openid.net/specs/fapi-message-signing-2_0-final.html#section-5.3.1),
[5.4.1](https://openid.net/specs/fapi-message-signing-2_0-final.html#section-5.4.1),
[5.5.1](https://openid.net/specs/fapi-message-signing-2_0-final.html#section-5.5.1)
and [5.6.1](https://openid.net/specs/fapi-message-signing-2_0-final.html#section-5.6.1).
Client tests cannot establish their production enforcement. Applications own
registration, key custody and message retention; this package's sanitized
reports are not a non-repudiation archive. [Sections 5.2, 6.3–6.6 and 7](https://openid.net/specs/fapi-message-signing-2_0-final.html#section-5.2)
also bound the legal/identity/sequence and privacy interpretation of signatures.

## JAR client accounting

| Exact section / topic | Supported behavior and regression | Limit or role distinction |
| --- | --- | --- |
| [4, Request Object contents and representation](https://www.rfc-editor.org/rfc/rfc9101.html#section-4) | J1 serializes the effective authorization parameters, nested `claims`, repeated resources and managed issuer/audience/time/JTI fields; rejects embedded `request`/`request_uri`; always signs before optional encryption. | General OAuth/OIDC extensions retain their own value rules. JAR audiences are separate from client-assertion audiences. |
| [4, algorithm agreement](https://www.rfc-editor.org/rfc/rfc9101.html#section-4) | Explicit/client-key defaults plus provider-advertised restrictions; `request mode rejects provider-disallowed request object algs` in J1. | Application/operator must register the matching key and algorithms with the AS. No dynamic registration client runs here. |
| [5 and 5.1, by-value request and outer identity](https://www.rfc-editor.org/rfc/rfc9101.html#section-5) | J1 places signed JAR in `request` and preserves outer `client_id`; OIDC compatibility mode also duplicates its required outer parameters. J7/J8 test outer-ID mismatch and parameter precedence. | The AS owns rejecting a mismatch and choosing signed values; those server behaviors are observations of the named fixtures. |
| [5.2 and 5.2.1, referenced requests](https://www.rfc-editor.org/rfc/rfc9101.html#section-5.2) | J1 supports a caller-supplied publisher, validates its HTTPS URL, warns beyond 512 bytes, and rejects caller-managed `request_uri` when PAR is required. | Publisher must enforce retrieval, correct media type, unpredictable handles, expiry and one-use/data-disclosure policy. Package validation of the returned URL proves none of those service properties. AS-issued PAR references use the PAR flow. |
| [8, TLS identity](https://www.rfc-editor.org/rfc/rfc9101.html#section-8) | [utils__tls.R](../../R/utils__tls.R) applies client HTTP TLS policy; [test-tls-policy.R](../../tests/testthat/test-tls-policy.R) checks protocol/verification settings. | Publisher hosting and AS retrieval are external responsibilities. Existing tests do not establish every certificate-name rule in this section, including rejection of CN-only identity fallback. |
| [10.1 and 10.5, signing/downgrade](https://www.rfc-editor.org/rfc/rfc9101.html#section-10.5) | J1 rejects `none`, incompatible keys and provider-required signed requests in parameter mode; J3 observes signed PAR. | Server-side `require_signed_request_object` registration/enforcement remains an AS/operator duty. J8's documented claim-acceptance limits remain visible. |
| [10.3, explicit endpoints](https://www.rfc-editor.org/rfc/rfc9101.html#section-10.3) | J1 includes `redirect_uri` and binds `aud` to the issuer. | Builder does not automatically add the other recommended endpoint claims; assess interoperability and intent before adding them. |
| [10.8, cross-JWT confusion](https://www.rfc-editor.org/rfc/rfc9101.html#section-10.8) | J1 sets the request-specific type and rejects `sub == client_id`; `request mode rejects client_id as request object sub` tests that rule. J4 assertions intentionally use `sub == client_id`. | The receiving AS must distinguish assertions from JAR. G2 covers the separate inbound-profile regression gap. |
| [11.1 and 11.2, disclosure and URI tracking](https://www.rfc-editor.org/rfc/rfc9101.html#section-11.2) | J1 supports optional Request Object encryption and PAR transport. | Application chooses authorization data; publisher and deployment own confidential storage, URI reuse and browser-history/referrer exposure. |

JAR [5.2.3 and 6–7](https://www.rfc-editor.org/rfc/rfc9101.html#section-6)
primarily specify the AS's retrieval, verification, parameter assembly and
error responses. J7/J8 exercise selected outcomes without transferring those
duties to the client library.

## JARM receiving-client accounting

| Exact section / topic | Implementation and evidence | Limit or remaining action |
| --- | --- | --- |
| [2.1, response shape](https://openid.net/specs/oauth-v2-jarm-final.html#section-2.1) | J2 requires `iss`, `aud`, `exp`, state and exactly one code/error response; preserves additional claims without using them as grant parameters. Tests cover error callbacks/replay and malformed claim types. | Application supports the authorization-code flow. It does not implement every response type the AS-side encoding description permits. |
| [2.2 and 2.4(1), optional nested encryption](https://openid.net/specs/oauth-v2-jarm-final.html#section-2.4-3.1) | J2/J6 check configured outer `alg`/`enc`/key identifier and `cty`, decrypt, then validate the inner signed JWT. | G1 now covers valid authenticated encryption containing an invalid or unsigned inner JWT through both callback transports. |
| [2.3.1–2.3.4, response transport](https://openid.net/specs/oauth-v2-jarm-final.html#section-2.3) | J2 accepts `query.jwt`, `form_post.jwt` and `jwt` as the code-flow query alias; rejects transport mismatch and raw-code downgrade. | `fragment.jwt` and implicit/hybrid response types are outside the supported client flow. POST uses the package's configured bridge and browser/state checks. |
| [2.4(2), expected issuer](https://openid.net/specs/oauth-v2-jarm-final.html#section-2.4-3.2) | J2 compares exact configured issuer before JWKS work. J3 checks live missing/wrong issuer rejection. | Key lookup uses the trusted provider, not the untrusted claim as a new discovery URL. |
| [2.4(3), audience](https://openid.net/specs/oauth-v2-jarm-final.html#section-2.4-3.3) | J2 normalizes typed string/string-array audiences and requires the client ID. J3 checks live missing/wrong audience rejection. | Additional profile-specific audience restrictions need their own configuration. |
| [2.4(4), validity](https://openid.net/specs/oauth-v2-jarm-final.html#section-2.4-3.4) | J2 rejects missing, malformed or expired `exp`; checks optional `iat`/`nbf`, configured maximum lifetime and delayed callback revalidation. J3 includes expired/missing-exp modules. | Default `jarm_max_lifetime = 600` supplies the local policy; leeway and overrides are explicit configuration. |
| [2.4(5), signature and `none`](https://openid.net/specs/oauth-v2-jarm-final.html#section-2.4-3.5) | J2 pins the expected signing algorithm, filters eligible provider keys and performs real verification with bounded refresh. J3 independently checks the invalid-signature and unsigned variants. | Caller registration must match the local algorithm. Optional generic HMAC JARM is outside the ES256 Message Signing selection. |
| [2.4, final processing barrier](https://openid.net/specs/oauth-v2-jarm-final.html#section-2.4-6) | J2 callback paths complete JARM validation before consuming state or exchanging code; pending/POST paths recheck expiry. J3 requires zero token calls on rejected callbacks. | Tests of sealed-state authentication before JWKS lookup do not replace signature validation. |
| [3 and 4, registration/discovery](https://openid.net/specs/oauth-v2-jarm-final.html#section-3) | Provider discovery records JARM metadata; J2 tests aliases, canonical values and default encryption settings. Local signing expectation defaults to RS256; encryption defaults to `A128CBC-HS256` when configured. | Local configuration is not a registration operation. Operator sets `authorization_signed_response_alg`, optional encryption metadata and public encryption keys at the AS. |
| [5.1–5.4, threat controls](https://openid.net/specs/oauth-v2-jarm-final.html#section-5) | J2 bounds input, authenticates client state before key retrieval, throttles forced refresh, binds issuer and rejects replay. J3 observes callback rejection/no exchange; S256 protects code redemption in the selected flow. | Deployment still owns callback handling/logging and query cleanup. Retain the existing callback error-page query limitation from the manifest. |

## JWT BCP accounting across these uses

These rows cover the shared JOSE implementation, outgoing JAR/assertions and
incoming ID token/JARM/signed UserInfo. Applications still choose trusted
issuers, account authorization and credential storage. Signed UserInfo is
included where it shares code; its full OIDC claim rules belong in the OIDC map.

| RFC 8725 section / topic | Concrete implementation and regressions | Limit or action |
| --- | --- | --- |
| [3.1, algorithm allowlists and key binding](https://www.rfc-editor.org/rfc/rfc8725.html#section-3.1) | J1/J2/J4/J5 enforce role-specific algorithms; [test-rsa-algorithm-binding.R](../../tests/testthat/test-rsa-algorithm-binding.R) and [test-hmac-profile-binding.R](../../tests/testthat/test-hmac-profile-binding.R) cover reused material across profiles; [test-jwks.R](../../tests/testthat/test-jwks.R) covers eligible mixed keys and real signatures. | General OIDC algorithms differ from FAPI policy; use the configured profile and inspect endpoint overrides. |
| [3.2, algorithm suitability/agility](https://www.rfc-editor.org/rfc/rfc8725.html#section-3.2) | Explicit configuration and metadata intersections; J6 implements RSA-OAEP rather than RSA1_5. Signing calls the installed OpenSSL backend. | RFC 6979 deterministic ECDSA behavior is not established by these tests. Audit/document the backend's nonce strategy before claiming that recommendation. Unsupported algorithms are listed below. |
| [3.3, all cryptographic operations](https://www.rfc-editor.org/rfc/rfc8725.html#section-3.3) | J6 checks authenticated decryption; J2 then checks the inner signature; [test-jwt-positive-algs.R](../../tests/testthat/test-jwt-positive-algs.R) rejects cryptographic-backend errors. | G1 adds real nested-JWT negative controls with unchanged signature validation and verifies legitimate pending-state recovery. |
| [3.4, cryptographic inputs](https://www.rfc-editor.org/rfc/rfc8725.html#section-3.4) | JWKS validation checks supported key structure/strength; [test-jwks-rsa-validation.R](../../tests/testthat/test-jwks-rsa-validation.R), [test-signing-key-strength.R](../../tests/testthat/test-signing-key-strength.R), and the exact ECDSA-width cases in [test-jwt-malformed-and-claims.R](../../tests/testthat/test-jwt-malformed-and-claims.R). | ECDH-ES/X25519/X448 encryption is unsupported, so its conditional invalid-curve obligations earn no implementation claim. Cryptographic point validation also depends on the backend. |
| [3.5, entropy](https://www.rfc-editor.org/rfc/rfc8725.html#section-3.5) | HMAC byte minima in signing/verification; `HMAC request objects enforce RFC 7518 HMAC secret lengths` in J1; random JTI/state/CEK/IV generation. | Length is not entropy. Operator must supply random secrets/private keys; a long human password does not satisfy the requirement. |
| [3.6, compression](https://www.rfc-editor.org/rfc/rfc8725.html#section-3.6) | J6 emits no compression; encrypted JARM rejects every `zip` member before decryption in [test-jarm-compression.R](../../tests/testthat/test-jarm-compression.R). | Compression is unsupported. |
| [3.7, UTF-8](https://www.rfc-editor.org/rfc/rfc8725.html#section-3.7) | Outgoing encoders use UTF-8; `strict_decode_jwt_json_text()` rejects NUL/invalid UTF-8. [test-jwt-malformed-and-claims.R](../../tests/testthat/test-jwt-malformed-and-claims.R) and [test-jwt-duplicate-members.R](../../tests/testthat/test-jwt-duplicate-members.R) cover strict text/member handling. | Keycloak duplicate-identical top-level JARM `iss` tolerance is an explicit compatibility option, disabled by default; it does not relax other duplicate-member checks. |
| [3.8, issuer/key and subject binding](https://www.rfc-editor.org/rfc/rfc8725.html#section-3.8) | J2/J5 use provider-bound JWKS and exact expected issuer; ID-token subject/nonce continuity and UserInfo subject matching have dedicated [UserInfo tests](../../tests/testthat/test-userinfo-jwt.R) and [refresh tests](../../tests/testthat/test-refresh-token.R). | Operator must trust the issuer and bind `(iss, sub)` to application accounts. A syntactically valid subject is not application authorization. |
| [3.9, audience](https://www.rfc-editor.org/rfc/rfc8725.html#section-3.9) | J1/J4 create distinct intended audiences; J2/J5 verify inbound audiences. J3 includes real wrong/missing-audience cases. | Preserve FAPI issuer-string assertion overrides; general endpoint defaults have a different purpose. |
| [3.10, untrusted lookup values](https://www.rfc-editor.org/rfc/rfc8725.html#section-3.10) | Key selection compares `kid` against provider JWKS; lookup never fetches token-supplied `jku`/`x5u`. [test-jwks-cache-host-policy.R](../../tests/testthat/test-jwks-cache-host-policy.R) covers provider key-location policy. | G4 now verifies trusted-key lookup and zero header-selected HTTP requests across ID-token/JARM callbacks and signed UserInfo. Applications must also treat returned claims as untrusted for their own databases/output. |
| [3.11, explicit type and nested type](https://www.rfc-editor.org/rfc/rfc8725.html#section-3.11) | J1 sets request-specific `typ` on signed inner JAR; J2 accepts the JARM-specific type and rejects unrelated profiles. [test-jwt-typ-header.R](../../tests/testthat/test-jwt-typ-header.R) checks ID-token type policy. | G2's corpus confirms that JARM-specific type fails outside JARM, while absent/generic types do not identify the JWT's purpose. It does not add a required type to existing ID-token/UserInfo configurations. |
| [3.12, mutually exclusive validation](https://www.rfc-editor.org/rfc/rfc8725.html#section-3.12) | JAR's type and forbidden client-ID subject distinguish it from J4 assertions; JARM requires code/error plus client state; ID tokens require their OIDC claims/nonce context. | G2's implemented corpus tests native contexts and substitution with the same issuer/key/audience. It records accepted ID-token/UserInfo overlap, conditional nonce/subject binding and JARM shape rejection; it does not establish unconditional mutually exclusive validation. |

## Unsupported options and follow-up regressions

Signed introspection responses are outside the implemented methods. General
JAR/JARM encryption supports compact `RSA-OAEP` with `A128CBC-HS256`,
`A192CBC-HS384` or `A256CBC-HS512`; it does not implement RSA-OAEP-256,
RSA1_5, ECDH-ES, symmetric key-management modes, AES-GCM or compression.
Encrypted ID tokens and encrypted UserInfo remain unsupported. The JWE
capability for JARM does not imply those receiving paths can decrypt tokens.

RSA-PSS signing/verification is unsupported. Outgoing JAR/client assertions
also exclude RS512; incoming signed-JWT policy supports RS512 where explicitly
allowed. Generic HMAC options require configured strong shared secrets and do
not earn the selected FAPI asymmetric-signing claim. The code-flow client
supports neither `fragment.jwt` nor implicit/hybrid JARM response types. It
does not implement dynamic client registration, Request Object hosting, or a
durable signed-message retention service.

| ID | Concrete next regression or decision | Acceptance evidence |
| --- | --- | --- |
| G1, completed regression | [test-jarm-inner-signature.R](../../tests/testthat/test-jarm-inner-signature.R) encrypts a bit-flipped RS256 signature with the correct registered `kid`, and an inner `alg=none` JWT, in valid authenticated JWEs. Only HTTP responses are stubbed; actual decryption, JWKS parsing, key selection, signature verification and callback/token handling run. | Four query/POST-bridge cases require the specific signature/unsigned error, zero token HTTP calls, no authenticated token and an identical pending-state record. A correctly signed nested response then uses the same state, exchanges exactly the legitimate code and consumes the record. On 2026-11-19, 68 new assertions and 864 focused JARM assertions passed on both Windows and Linux with zero test warnings/skips. Linux validation installed the missing optional sodium package and system library in its disposable test container; the first attempt's pre-existing Ed25519 skip earned no zero-skip result. |
| G2, corpus implemented; purpose-policy assessment limited | [test-jwt-purpose-separation.R](../../tests/testthat/test-jwt-purpose-separation.R) reuses identical RS256 JWTs across ID-token/JARM validators and public signed-UserInfo retrieval with one trusted issuer/key/audience. Its 48-cell corpus includes native ID-token, JARM, minimal UserInfo and timestamped UserInfo claim sets, absent/generic type and supported-JARM/wrong-profile type controls. Separate module/public-API cases exercise actual nonce, pending-state and validated-subject context. Only HTTP is stubbed. | In the selected nonce-free configuration, an ID token passes signed-UserInfo checks and timestamped UserInfo passes ID-token checks. Requiring the actual login nonce rejects the tested missing/wrong-nonce substitutions before UserInfo/authentication; ordinary ID-token/UserInfo shapes fail JARM before token exchange or pending-state consumption. A verified ID-token baseline rejects a different UserInfo subject but still accepts a same-subject ID token served as UserInfo. On 2026-11-19, 238 new assertions and 482 focused purpose/locator/type/subject assertions passed on both Windows and Linux with zero failures, errors, test warnings or skips. |
| G3 | Assess a complete Message Signing configuration at the `nbf`/TTL boundaries: default omitted `nbf`, an excessive skew, and an `exp - nbf` window over 3,600 seconds. | A named profile assessment/example identifies required settings; the selected construction through the public API emits valid claims at the supported boundary. Preserve valid general OAuth configurations outside this profile. |
| G4, completed regression | [test-jwt-untrusted-locators.R](../../tests/testthat/test-jwt-untrusted-locators.R) runs real RS256 verification with trusted issuer JWKS through ID-token/JARM module callbacks and public signed-UserInfo retrieval. Eight cases per context include ordinary positives, valid ignored optional `jku`/`x5u` headers, attacker signatures advertising attacker key URLs, unmatched SQL/path-shaped `kid`, and registered literal unusual-key-ID positives. Only `httr2::req_perform()` is stubbed; every attempted URL is counted. | No header-selected URL receives a request, even when it could return the attacker's matching JWKS. Unmatched key IDs fail literal selection; registered unusual IDs remain usable. Rejected JARM preserves pending state and makes zero token calls; rejected ID tokens prevent UserInfo and authentication after the required token response; invalid signed UserInfo returns no claims. On 2026-11-19, 171 new assertions and 274 focused locator/JWKS/JOSE assertions passed on both Windows and Linux with zero failures, test warnings or skips. |

G1, G2's corpus and G4 record completed focused regressions; G3 remains an
unexecuted follow-up. G2's accepted overlaps are observed compatibility in the
tested configuration. The tests do not establish attacker control of a trusted
token/UserInfo response, an exploit, or rejection of every extended JWT claim
set. Nonce and subject checks bind transactions and identities; they do not
classify every JWT's purpose. A claim of unconditional purpose separation needs
a separately reviewed OP/RP profile and deployment policy. No default changed.

Separate backend review should resolve deterministic ECDSA and certificate-name behavior
before those recommendations receive credit. Signed-introspection support
would require its own RFC 9701 design, negotiation, envelope-validation and
negative-response tests; it should not be inferred from client JWT authentication.
