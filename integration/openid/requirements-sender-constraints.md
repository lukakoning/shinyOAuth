# Sender constraints and resource-indicator requirements

This map accounts for directly applicable client duties in
[RFC 8705, mTLS](https://www.rfc-editor.org/rfc/rfc8705.html),
[RFC 9449, DPoP](https://www.rfc-editor.org/rfc/rfc9449.html) and
[RFC 8707, resource indicators](https://www.rfc-editor.org/rfc/rfc8707.html).
The source inspected is `ea132bb0de2b84faeeea19ce3bfe66f356d812f7`.
It reviews their protocol and security sections, separates optional features
from conditional duties, and reuses existing assertions and recorded runs.
Writing this map adds no execution result or certification claim. Inherited
security and deployment work remains open; this document does not close SA04.

Three mTLS decisions have different meanings: certificate authentication
identifies the client to the authorization server (AS); certificate-bound
tokens require that issuing certificate at the resource server (RS); endpoint
aliases select the server address. DPoP is another token/proof binding mechanism,
not client authentication. RFC 8707 requests an intended token audience; it
does not itself constrain the sender or prove RS audience enforcement.

The client constructs requests and preserves its transaction/key context.
The AS registers clients, authenticates credentials and issues/binds tokens;
the RS validates each presented token and sender binding. Operators select
trusted issuers, resource addresses, keys, certificates and deployment TLS.
Decoded access-token `cnf` observations are additional local checks, not
access-token signature validation or independent evidence of issuance.

## Concrete evidence and selected configurations

| ID | Implementation, assertions and evidence boundary |
| --- | --- |
| M1 | [utils__mtls.R](../../R/utils__mtls.R), `client_uses_mtls_auth()`, `client_requests_certificate_bound_tokens()`, `resolve_provider_endpoint_url()` and `req_apply_authorization_server_mtls()`; [utils__http_requests.R](../../R/utils__http_requests.R), `apply_direct_client_auth()`. [test-mtls-requests.R](../../tests/testthat/test-mtls-requests.R) inspects token/PAR/refresh/introspection/revocation URLs, certificate/key/CA options, form client ID and absence of competing secrets. Separate cases check that metadata alone does not enable mTLS, that opted-in public clients select aliases, and that missing certificate files stop dispatch. |
| M2 | [mtls_registration.R](../../R/mtls_registration.R), `oauth_client_mtls_registration()` and self-signed JWKS helpers. [test-mtls-registration.R](../../tests/testthat/test-mtls-registration.R) checks exactly one subject/SAN field, preserved escaped DNs, explicit typed SAN values, inline public JWK/`x5c` agreement and external HTTPS `jwks_uri`. These construct metadata; they neither register a client nor establish AS certificate acceptance. |
| M3 | `read_keyed_client_certificate()`, `tls_client_cert_thumbprint_s256()` and `validate_token_certificate_binding()` in M1. [test-mtls-roundtrip.R](../../tests/testthat/test-mtls-roundtrip.R) exercises accepted leaf-first layouts over actual TLS; [test-mtls-thumbprint-cache.R](../../tests/testthat/test-mtls-thumbprint-cache.R) covers bounded cache invalidation. [test-mtls-opaque.R](../../tests/testthat/test-mtls-opaque.R) checks explicit opaque/observation policy, continued certificate presentation and rejection of any observed bad/conflicting binding. |
| M4 | [Independent resource tests](../conformance/test-mtls-resource.R), [PKI authentication tests](../conformance/test-mtls-authentication.R) and [strict_as.py](../conformance/strict_as.py) use actual TLS peers, two eligible certificates with identical subjects, a fixed CA/subject registration and opaque per-token issuance records. Wrong/missing certificates and forged headers must yield denial without resource content; the rightful holder remains usable. The PKI variant also checks AS authentication rejection and module state/token/connection cleanup. RS256/RS384, direct JAR/PAR and sync/mirai token callbacks are separate selected dimensions. [Fixture scope](../conformance/README.md) excludes independent self-signed authentication, SAN/revocation coverage and bound refresh. |
| D1 | [utils__dpop.R](../../R/utils__dpop.R), `build_dpop_proof()`, `dpop_public_jwk()`, `dpop_target_uri()` and `dpop_access_token_hash()`. [test-dpop.R](../../tests/testthat/test-dpop.R) verifies actual signatures before inspecting header/claims, public-only JWKs, fresh JTIs, numeric creation time, token hashes, supported algorithms and key-binding failures. [test-outbound-jws-algs.R](../../tests/testthat/test-outbound-jws-algs.R) and [cross-language RS384 tests](../conformance/test-rs384-interop.R) provide separate cryptographic evidence, including fixed SHA-256 `ath` with RS384 proofs. |
| D2 | `req_with_dpop_retry()`, nonce parsing/cache and prepare-attempt/response hooks in D1; [test-dpop.R](../../tests/testthat/test-dpop.R) captures code/refresh/UserInfo retries, distinct proof/JTI values on transient retries, successful-response nonce updates and isolation between endpoint paths, issuers, keys and token/resource roles. [Challenge limits](../../tests/testthat/test-dpop-challenge-limits.R), [target paths](../../tests/testthat/test-dpop-target-paths.R) and [redirect tests](../../tests/testthat/test-dpop-redirects.R) check parser bounds and actual transmitted method/path/authority. |
| D3 | [Keycloak DPoP](../keycloak/test_integration_keycloak_dpop.R), [nonce retries](../keycloak/test_integration_keycloak_dpop_nonce_retry.R) and [resource attacks](../keycloak/test_integration_attack_dpop_resource.R) distinguish actual provider/resource rejection from local preflight failure. Public-client refresh requires the original proof key; raw missing/wrong-key attempts fail. The independent resource verifier checks real signatures, token hash and proof replay separately from the package-backed verifier. The strict AS verifies ES256 DPoP against the signed Request Object's key and PKCE at token issuance; it is not a general DPoP RS. |
| R1 | [test-resource-indicators.R](../../tests/testthat/test-resource-indicators.R) inspects repeated fields at authorization/code/refresh and exact form escaping. [test-par.R](../../tests/testthat/test-par.R) checks repeated PAR fields; [test-jar.R](../../tests/testthat/test-jar.R) checks the multiple-value JSON claim. [utils__url_helpers.R](../../R/utils__url_helpers.R), `resource_indicator_problem()`, rejects nonabsolute/malformed URIs and fragments. [connection_targets.R](../../R/connection_targets.R), `token_target_parameters()`, and [target contracts](../../tests/testthat/test-connection-targets.R) inspect separate resource/scope requests for declared RFC 8707 targets. |
| R2 | [oidc-provider resource selection](../oidc-provider/README.md), [request collector](../oidc-provider/helper-resources.R) and [evidence gate](../oidc-provider/helper-resource-evidence.R): two separate API targets plus an unknown resource, confidential Basic authentication, direct query/S256, no PAR. Browser and native events check the same indicator at authorization/code/refresh; native introspection checks current audience/scope. The development RS uses the provider's public AccessToken/Grant model API; it rejects a valid token for the other API, absent credentials and an invalid token. This is not an independent RS product or JWT verifier. |
| H1 | [FAPI scope](scope.md), [requirement map](requirements.md) and [release review](release-review.md) retain the executed DPoP/mTLS selections and their source identities. OIDF DPoP uses ES256, private-key JWT, S256 and authenticated PAR, with OIDC and OAuth-only selections. mTLS selections distinguish JWT versus certificate authentication. The pinned mTLS simulator detects certificate mismatch but still returns resource content, and its authentication model compares exact certificates. M4 supplies separate enforcing evidence; it does not remove those OIDF limits. |
| H2 | The [implementation record](../../.github/protocol-quality-implementation-plan.md) retains independent mTLS results with report identity `df714b2c`, advanced `oidc-provider` results at `c615cdda526a796112028f374b93317e567f3113`, and resource results at `f2f78a2d502817522155837529683e7f4acbd155`. The advanced selection checks native DPoP replay/wrong-key/Bearer denials and mTLS wrong/missing-peer/header-forgery denials. Its mTLS authentication is Basic plus certificate binding with temporary self-signed peers, not PKI client authentication. Resource reports cover single-resource requests in separate cases, not simultaneous multi-resource issuance or sender-constraint combinations. Historical results retain their original source/transport/coverage limits; none is rerun or upgraded by this map. |

## RFC 8705 client duties

| ID / clause | Client duty or optional feature | Concrete mapping and limits |
| --- | --- | --- |
| MT1 / [2](https://www.rfc-editor.org/rfc/rfc8705.html#section-2) | Authenticate over actual mTLS; include client ID. | M1 attaches the configured certificate/private key to direct AS requests and emits the same form `client_id`. M4 checks the real TLS peer and explicit missing/wrong-identity controls, beyond captured curl options. Server certificate-request behavior, client/certificate registration and `invalid_client` generation are AS duties. |
| MT2 / [2.1](https://www.rfc-editor.org/rfc/rfc8705.html#section-2.1), [2.1.1](https://www.rfc-editor.org/rfc/rfc8705.html#section-2.1.1), [2.1.2](https://www.rfc-editor.org/rfc/rfc8705.html#section-2.1.2) | For PKI registration, select exactly one certificate identifier. | M2 emits `tls_client_auth` and one DN or explicitly typed SAN field. The operator must select an identifier actually present in the certificate; shape normalization alone cannot prove that choice. M4 verifies one fixed DN/CA profile. SAN matching, DN-equivalence edge cases and production CA/revocation policy remain outside that execution. |
| MT3 / [2.2](https://www.rfc-editor.org/rfc/rfc8705.html#section-2.2), [2.2.1](https://www.rfc-editor.org/rfc/rfc8705.html#section-2.2.1), [2.2.2](https://www.rfc-editor.org/rfc/rfc8705.html#section-2.2.2) | Self-signed authentication: publish the corresponding certificate/public JWK. | M2 supports `self_signed_tls_client_auth`, inline `jwks`/`x5c` or an explicit HTTPS `jwks_uri`, including required public key members and matching first certificate. M1 supplies TLS possession. Dynamic registration, JWKS hosting/update and an enforcing independent AS self-signed-authentication profile are not supplied by the helper or M4. |
| MT4 / [3](https://www.rfc-editor.org/rfc/rfc8705.html#section-3) | Present the issuing certificate at protected resources. | M3 checks observable token bindings against the actual configured leaf; [methods__client_bearer_req.R](../../R/methods__client_bearer_req.R) attaches it to resource/UserInfo requests. M4/H2 distinguish two certificates with the same subject and reject raw attacker requests. Observed `cnf` is optional client-side evidence, while the RS must enforce its issuance record. With opaque tokens and `mtls_require_observed_cnf = FALSE`, operators must preserve issuing certificate/key availability; local observation cannot detect every wrong choice. |
| MT5 / [3.1](https://www.rfc-editor.org/rfc/rfc8705.html#section-3.1), [3.2](https://www.rfc-editor.org/rfc/rfc8705.html#section-3.2) | Consume confirmation consistently when observable. | M3 computes unpadded base64url SHA-256 over leaf DER and rejects malformed/conflicting `x5t#S256` values from response, introspection or an inspectable JWT. Access-token representation and confirmation generation belong to AS/RS processing. JWT inspection does not verify that access token's signature. Opaque mode deliberately avoids decoding; an omitted confirmation is not proof of an unbound token. |
| MT6 / [3.3](https://www.rfc-editor.org/rfc/rfc8705.html#section-3.3), [3.4](https://www.rfc-editor.org/rfc/rfc8705.html#section-3.4), [4](https://www.rfc-editor.org/rfc/rfc8705.html#section-4) | Optional binding intent is separate from authentication. | M1 requires configured client intent, provider capability and certificate material for requested binding. M2 can emit binding intent with `none`, secret/JWT or certificate authentication. Unit public-client/opaque cases preserve that separation. A binding flag does not replace authentication credentials, and certificate authentication alone does not establish that an access token is bound. |
| MT7 / [5](https://www.rfc-editor.org/rfc/rfc8705.html#section-5) | Prefer advertised aliases for direct mTLS endpoints. | M1 resolves token, PAR, introspection, revocation and UserInfo aliases, falls back for omitted entries and does not route browser authorization through them. It uses aliases for mTLS authentication or intended/observed token binding. Unused alias members do not become arbitrary request destinations. The existing [FAPI follow-up](requirements.md) separately tracks alias-only ecosystems: there is no independent public alias-intent setting for a client using neither modeled condition. Do not credit that configuration from the selected flows. |
| MT8 / [6.3](https://www.rfc-editor.org/rfc/rfc8705.html#section-6.3), [7.1](https://www.rfc-editor.org/rfc/rfc8705.html#section-7.1) | Assess certificate lifetime/rotation and bound refresh conditionally. | M3 detects changed files and revalidates certificate/key agreement; resource checks retain token-specific binding. AS refresh/introspection/revocation deliberately do not compare an old access-token thumbprint with the new certificate. [Keycloak mTLS refresh](../keycloak/test_integration_keycloak_mtls.R) rejects missing/wrong authentication certificates. That does not by itself isolate refresh-token binding from client authentication or establish public-client bound refresh; M4 omits refresh. Certificate renewal and token reacquisition policy remain deployment responsibilities. |

[6.1](https://www.rfc-editor.org/rfc/rfc8705.html#section-6.1),
[6.2](https://www.rfc-editor.org/rfc/rfc8705.html#section-6.2) and
[6.5](https://www.rfc-editor.org/rfc/rfc8705.html#section-6.5) concern server
behavior and secure TLS termination. Forwarded certificate headers are not
proof of a peer. [6.4](https://www.rfc-editor.org/rfc/rfc8705.html#section-6.4)'s
implicit flow is outside the supported code/refresh paths.
[7.2](https://www.rfc-editor.org/rfc/rfc8705.html#section-7.2) is reflected by M3's
fixed certificate hash. [7.3](https://www.rfc-editor.org/rfc/rfc8705.html#section-7.3)
uses the [TLS policy](../../R/utils__tls.R) and [its tests](../../tests/testthat/test-tls-policy.R);
production cipher/version/termination assurance remains separate.
[7.4](https://www.rfc-editor.org/rfc/rfc8705.html#section-7.4)'s trust anchors and
[7.5](https://www.rfc-editor.org/rfc/rfc8705.html#section-7.5)'s certificate
validation are delegated to established TLS/OpenSSL libraries, not a new chain
validator. Their production configuration and
[8](https://www.rfc-editor.org/rfc/rfc8705.html#section-8)'s certificate-linkability
assessment still require operator review.

## RFC 9449 client duties

| ID / clause | Client duty or optional feature | Concrete mapping and limits |
| --- | --- | --- |
| DP1 / [2](https://www.rfc-editor.org/rfc/rfc9449.html#section-2) | Use HTTPS with DPoP. | Provider/resource request policy applies TLS verification; D1 does not replace transport security. Loopback development exceptions and permissive URL/TLS overrides earn no production-HTTPS credit. [Resource redirects](../../tests/testthat/test-dpop-redirects.R) stop credentials/proofs from following to a new endpoint. |
| DP2 / [4.1](https://www.rfc-editor.org/rfc/rfc9449.html#section-4.1), [4.2](https://www.rfc-editor.org/rfc/rfc9449.html#section-4.2), [11.6](https://www.rfc-editor.org/rfc/rfc9449.html#section-11.6) | Emit one signed proof with the required public header. | D1 constructs compact JWS with `typ = dpop+jwt`, a compatible asymmetric algorithm and a public-only `jwk`. Key/algorithm validation excludes HMAC/`none`; actual-signature tests and Python comparisons distinguish signing from decoding. Caller resource headers cannot replace managed `DPoP`/`Authorization`. The configured supported algorithm set is narrower than the entire JOSE registry. |
| DP3 / [4.2](https://www.rfc-editor.org/rfc/rfc9449.html#section-4.2) | Include unique JTI, actual method/URI and creation time. | D1 generates a 32-character CSPRNG-backed JTI, numeric current `iat`, final uppercase method and target without query/fragment. D2 compares escaped/Unicode/dot-segment paths and actual wire authority, rejects `Host` overrides and disables redirects. No statistical test establishes randomness, server clock tolerance or replay storage; those require the implementation and server policy. |
| DP4 / [4.2](https://www.rfc-editor.org/rfc/rfc9449.html#section-4.2), [7](https://www.rfc-editor.org/rfc/rfc9449.html#section-7), [7.1](https://www.rfc-editor.org/rfc/rfc9449.html#section-7.1) | Resource requests need the token and its SHA-256 proof hash. | Resource/UserInfo helpers emit `Authorization: DPoP` and a matching proof `ath`; non-ASCII token values are rejected. D1 checks the fixed hash even with other signature digests. D3/H2 require native denial for missing proof, wrong key and Bearer downgrade. Unknown challenge parameters are ignored by the scheme/error selector; the package generates no DPoP proxy-authentication scheme. RS validation remains the RS's duty. |
| DP5 / [5](https://www.rfc-editor.org/rfc/rfc9449.html#section-5) | Token requests need proofs; bound public refresh keeps the key. | Code/refresh builders use D2 with the configured key; D3's public refresh scenario accepts the original key and denies raw missing/wrong-key attempts. DPoP does not replace configured client authentication. Confidential refresh credentials have their own client-authentication binding; the map does not assume they are all DPoP-key-bound. |
| DP6 / [5](https://www.rfc-editor.org/rfc/rfc9449.html#section-5), [7.2](https://www.rfc-editor.org/rfc/rfc9449.html#section-7.2) | Discard a downgrade when DPoP protection is required. | `dpop_require_access_token` defaults to strict for a DPoP-enabled client; token verification and resource helpers reject Bearer fallback/overrides for DPoP tokens. Explicit permissive policy remains available under the RFC's conditional choice. Returned token type and any observed key confirmation are checked separately; `dpop_require_observed_cnf` defaults to `FALSE` and can require positive local binding evidence. Raw strings need explicit type/context rather than speculative DPoP inference. |
| DP7 / [5.1](https://www.rfc-editor.org/rfc/rfc9449.html#section-5.1), [5.2](https://www.rfc-editor.org/rfc/rfc9449.html#section-5.2) | Assess optional algorithm and registration metadata. | [Discovery](../../R/providers__oidc_discovery.R) checks wire JOSE spelling with `.discover_validate_jose_metadata()` before internal normalization. [test-discovery-jose-case.R](../../tests/testthat/test-discovery-jose-case.R) includes the DPoP field; D1 checks explicit/inferred algorithm membership. Static fixture registration selects the profile. No automatic DPoP dynamic-registration API or complete RS `algs` negotiation is claimed. |
| DP8 / [4.2](https://www.rfc-editor.org/rfc/rfc9449.html#section-4.2), [8](https://www.rfc-editor.org/rfc/rfc9449.html#section-8), [8.1](https://www.rfc-editor.org/rfc/rfc9449.html#section-8.1), [8.2](https://www.rfc-editor.org/rfc/rfc9449.html#section-8.2), [9](https://www.rfc-editor.org/rfc/rfc9449.html#section-9) | Use the issuing server's recent/replacement nonce. | D2 accepts valid bounded nonce syntax, learns from success/transient/challenge responses, updates the next attempt and keeps token/resource, issuer, key and endpoint contexts separate. It retries one valid token 400/JSON or resource 401/DPoP challenge with a new proof; absent/malformed nonce or a second challenge terminates normally as failure. The volatile cache has age/entry bounds, so later requests may need a new server challenge; these cases do not establish uninterrupted retention across eviction, restart or workers. OIDC transaction nonces are separate. |
| DP9 / [7.3](https://www.rfc-editor.org/rfc/rfc9449.html#section-7.3) | Generate a new proof for every permitted retry. | D2 installs a prepare-attempt hook, preserves prior JWT-authentication hooks and captures distinct JTIs/signatures across allowed transient/nonce retries. Successful-response nonce rotation is tested too. [No generic code/refresh replay](../../tests/testthat/test-no-retry-token-exchange-refresh.R) preserves single-use grant safety; a nonce retry is the separate bounded protocol case. Custom callers sending a prepared `resource_req()` directly through httr2 own subsequent re-signing/retry behavior; `perform_resource_req()` supplies the managed path. |
| DP10 / [10](https://www.rfc-editor.org/rfc/rfc9449.html#section-10), [10.1](https://www.rfc-editor.org/rfc/rfc9449.html#section-10.1) | Optional code binding/PAR must use the intended proof key. | `build_authorization_params()` adds the configured key's JWK thumbprint as `dpop_jkt`, including in signed requests. PAR sends authorization data in its body and D2 adds the PAR-targeted proof. `test-dpop.R`/`test-par.R` inspect generated parameters and nonce retries; D3, H1 and the strict AS check subsequent proof/transaction binding in their selected profiles. The [PAR/JAR maps](requirements-par-auth.md) retain their placement/signature dependencies. |

The receiving-server checks in
[4.3](https://www.rfc-editor.org/rfc/rfc9449.html#section-4.3),
[6](https://www.rfc-editor.org/rfc/rfc9449.html#section-6),
[6.1](https://www.rfc-editor.org/rfc/rfc9449.html#section-6.1) and
[6.2](https://www.rfc-editor.org/rfc/rfc9449.html#section-6.2) are not extra client
verifier obligations. Local `cnf.jkt` consistency checks supplement those roles;
opaque access tokens remain possible. H1's decoded fields and named upstream
signature conditions are separate evidence inputs.

Security accounting keeps
[11.1](https://www.rfc-editor.org/rfc/rfc9449.html#section-11.1)'s replay window/cache
with the receiver;
[11.2](https://www.rfc-editor.org/rfc/rfc9449.html#section-11.2)'s pre-generation and
[11.3](https://www.rfc-editor.org/rfc/rfc9449.html#section-11.3)'s nonce downgrade
depend on that server's nonce/lifetime policy. D2/D3 supply selected client and
denial cases, not a production replay-cache audit.
[11.4](https://www.rfc-editor.org/rfc/rfc9449.html#section-11.4)'s compromised-client
context requires application/key-custody review.
[11.5](https://www.rfc-editor.org/rfc/rfc9449.html#section-11.5)'s JWT-purpose typing
is emitted by D1 and checked by the selected verifiers; inherited JWT/JWS/JWK
processing remains under the [JWT map](requirements-jwt-signing.md).
[11.7](https://www.rfc-editor.org/rfc/rfc9449.html#section-11.7) leaves body/header
integrity to TLS or another mechanism. The bindings discussed in
[11.8](https://www.rfc-editor.org/rfc/rfc9449.html#section-11.8) and
[11.9](https://www.rfc-editor.org/rfc/rfc9449.html#section-11.9) have the separate
AS/RS evidence above;
[11.10](https://www.rfc-editor.org/rfc/rfc9449.html#section-11.10)'s hash dependencies
do not change D1's fixed SHA-256 fields.
[11.11](https://www.rfc-editor.org/rfc/rfc9449.html#section-11.11) does not turn a
possession proof into registered client authentication.

## RFC 8707 client duties

| ID / clause | Client duty or optional feature | Concrete mapping and limits |
| --- | --- | --- |
| RI1 / [2](https://www.rfc-editor.org/rfc/rfc8707.html#section-2) | Optional indicators must be absolute and fragment-free. | R1 validates each URI without converting abstract identifiers into URLs or rewriting their identity, and encodes multiple HTTP values as repeated fields. Query components remain allowed for the RFC's stated exceptions; choosing one is an application decision. Malformed URI escaping and delimiter encoding have distinct checks. |
| RI2 / [2](https://www.rfc-editor.org/rfc/rfc8707.html#section-2), [3](https://www.rfc-editor.org/rfc/rfc8707.html#section-3) | Prefer the specific API base; assess query/multiple-audience choices. | Operators supply `resource` or declared target resources, including tenant paths where needed. The package cannot infer the correct API/audience from arbitrary scopes. `token_target_mode = rfc8707` requests one selected target per exchange/acquisition; generic `resource` also supports multiple values. That support does not establish mutual trust among all requested audiences or provider acceptance. |
| RI3 / [2.1](https://www.rfc-editor.org/rfc/rfc8707.html#section-2.1) | Authorization/JAR conveys the grant's intended resources. | `build_authorization_params()` emits configured values; R1 checks query/PAR repeated fields and JSON multi-value claims. JAR encoding uses a string for one value and an array for multiple values. Signed-request/PAR processing has its separate maps. R2's browser/native observations establish only direct single-resource requests, not successful combined JAR/PAR/resource interoperability. |
| RI4 / [2.2](https://www.rfc-editor.org/rfc/rfc8707.html#section-2.2) | Token/refresh requests identify the selected resource and scope. | Code/refresh builders preserve configured `resource`; target contracts capture different resource/scope pairs and one rotating refresh credential. The AS decides permitted subsets and what remains authorized by the original grant. Microsoft target mode selects through provider-specific scopes and is a separate contract, not RFC 8707 wire evidence. |
| RI5 / [2](https://www.rfc-editor.org/rfc/rfc8707.html#section-2), [2.1](https://www.rfc-editor.org/rfc/rfc8707.html#section-2.1), [2.2](https://www.rfc-editor.org/rfc/rfc8707.html#section-2.2) | Handle provider rejection; do not infer audience from request acceptance. | R2 checks native `invalid_target` before code/token issuance and empty client identity/credential state. Its positive cases require current native introspection audience/scope before and after refresh, plus wrong-audience RS denial. [Keycloak resource cases](../keycloak/test_integration_keycloak_resource_indicators.R) retain the accepting-but-unaudienced control separately from explicitly audience-mapped tokens. Acceptance of a query field alone earns no enforcement credit. |
| RI6 / [3](https://www.rfc-editor.org/rfc/rfc8707.html#section-3), [4](https://www.rfc-editor.org/rfc/rfc8707.html#section-4) | Send credentials only to the intended resource; assess disclosure. | [utils__resource_binding.R](../../R/utils__resource_binding.R) and [test-resource-binding.R](../../tests/testthat/test-resource-binding.R) restrict named connection destinations before attaching credentials. `resource_bases` is local routing policy, not an OAuth parameter or token-audience verifier. Abstract identifiers require an operator-established endpoint association; AS audience mapping may differ from the literal resource. R2's opaque-token RS checks actual audience through the provider model. Deployment logging, tenant boundaries and resource-level tracking/privacy still need review. |

## Remaining evidence and audit work

One narrowly missing regression is an end-to-end constructor check for the
already implemented DPoP JOSE-case guard: serve invalid-case and mixed
canonical/invalid-case `dpop_signing_alg_values_supported` arrays to both public
OAuth/OIDC discovery constructors, require the parse failure before client
setup, and retain a canonical-array control. The inspected case test directly
exercises `.discover_validate_jose_metadata()` for this field; other discovery
tests cover array shape and canonical capabilities. Internal uppercase policy
normalization is not evidence of accepting malformed wire metadata, because
the guard runs first. No runtime defect is established by this inspection.

Keep alias-only mTLS policy, independent self-signed/PKI-SAN/revocation/bound-refresh
profiles, multi-resource enforcing-provider scenarios and combinations outside
the recorded selections explicit. Complete inherited TLS, X.509, JWT/JWS/JWK,
key custody and deployment-security audits remain separate from this direct
client-clause account. Preserve each historical report's
[source-policy boundary](source-identity.md) when assembling release evidence;
SA08 still owns the complete source-qualified release matrix.
