**Coverage scope**

Current stage: all fourteen modules in the pinned Basic RP plan execute in a
real browser with matching app evidence. The variant uses static registration,
code flow and `client_secret_basic`, the selected sync/mirai transport and query callbacks.
Thirteen modules finish `PASSED`. The unsigned-token module finishes `SKIPPED`
after the app rejects `alg=none`, as its documented optional behavior permits.
For this exact plan/variant, `basic` reports `coverage_complete = true`; the
three-module `smoke` selection keeps it false. This establishes local Basic RP
test coverage; OpenID certification and other profiles remain separate.

The fourteen-module Form Post Basic plan also passes with its fixed
`response_mode=form_post` variant, normal browser POST callbacks and verified
bridge, binding and URL-cleanup evidence. The deployment uses two HTTPS
`localhost` ports; Chrome records it as cross-origin and same-site. This does
not establish cross-site deployment coverage.

All three modules in the pinned client refresh plan pass on Windows and Linux
with the original login retained through refresh. Positive refresh preserves
identity; changed issuer and subject responses clear the session and leave
the retained connection unable to export credentials.

The Configuration selection now exercises all six pinned modules. It separates
discovery-only setup from authentication and explicitly runs both signing-key
rotation modules. Configuration coverage remains partial: the suite forbids
storing JWKS, so these executions cannot establish refresh from a warm key cache.

Preflight's `required_plans_present` proves suite capability. The separate
synthetic-metadata fixture checks prove authorization-request plumbing. The API
check and app-stop control create interrupted modules for harness validation;
neither interruption counts as a client test pass.

| Target | Existing local evidence | Planned independent gate |
| --- | --- | --- |
| OIDC Core code flow, ID token and UserInfo validation | Unit tests, Keycloak browser/code flows, complete pinned Basic RP module selection (C05) | Basic implemented for the variant above; further profiles below |
| Discovery, exact issuer and signing-key changes | Discovery/JWKS tests, Keycloak rotation, and six Configuration module outcomes (C06) | Warm-cache refresh remains a C06 follow-up; pinned suite JWKS is `no-store` |
| Form POST callback and browser binding | Real browser and retained-connection tests; complete pinned Form Post Basic plan on the same-site local rig (C07) | Form Post Basic implemented; cross-site attack cases stay in their separate layer |
| Refresh identity continuity | Refresh validation, retained-connection tests and all three pinned client refresh modules (C08, extended in C09) | Code flow with HTTP Basic authentication in sync/mirai, plus future parity |
| Worker transport | Package worker tests; verified mirai transport for the core selections, future smoke/refresh parity, and an alternating shared-pool selection (C09) | Shared-pool scope is sequential reuse across distinct suite issuers, with fresh per-case app/cache objects |
| Additional client authentication | Keycloak/worker tests and paired positive/issuer-rejection selections for POST, HS256 secret JWT and RS256 private-key JWT (C09) | Public-client discovery remains blocked by the pinned suite's metadata; shared-pool coverage pairs POST and private-key JWT |
| PAR, DPoP and mTLS | Keycloak and independent Python exchanges; FAPI OIDC and OAuth-only private-key-JWT/DPoP selections (C10) | OIDC requires all twenty-three modules; OAuth-only runs all eleven with an open state-length advisory; mTLS remains pending |
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

The `form-post` selection follows the pinned
[Form Post Basic plan](https://gitlab.com/openid/conformance-suite/-/blob/410812ef6bc72a84723c1685725edce3558e31e3/src/main/java/net/openid/conformance/openid/client/OIDCCClientFormPostBasicTestPlan.java)
and its
[response-mode adapter](https://gitlab.com/openid/conformance-suite/-/blob/410812ef6bc72a84723c1685725edce3558e31e3/src/main/java/net/openid/conformance/openid/AbstractFormPostTestPlan.java).
They select the same fourteen Basic modules with `form_post`, so every row in
the Basic table above still applies. Each result additionally requires:

- Browser-observed GET authorization, POST callback and the bridge's 303 GET redirect.
- The app's POST metadata: form encoding, expected provider Origin and observed `Sec-Fetch-Site`.
- Secure `SameSite=Strict` binding-cookie metadata and a completed callback-validation audit, including for ID-token rejection cases.
- Real provider/app origins, consistent origin/site labels and an empty final callback query.

Windows and Linux runs each produced thirteen `PASSED` verdicts plus the
existing unsigned-token `SKIPPED` verdict. Chrome sent `Sec-Fetch-Site:
same-site` for every callback. Different HTTPS ports establish different
origins, while these `localhost` origins share a site. Cookies, request bodies,
callback query values and full CDP events are excluded from the report.
The separate `oidcc-client-test-form-post-error` module is not part of this
upstream plan; it earns no verdict in this selection. General error-bridge and
transport rejection tests remain in the package's existing tests, with broader
comprehensive-plan selections deferred to C09.

The `config` selection uses the pinned
[Configuration plan](https://gitlab.com/openid/conformance-suite/-/blob/410812ef6bc72a84723c1685725edce3558e31e3/src/main/java/net/openid/conformance/openid/client/OIDCCClientConfigTestPlan.java).
The upstream runner excludes both rotation modules and links
[issue 837](https://gitlab.com/openid/conformance-suite/-/issues/837), which describes
its sample client's CI failures. Our driver creates those modules explicitly.

| Configuration module suffix (`oidcc-client-test` prefix) | Action and app evidence | Suite verdict |
| --- | --- | --- |
| `-discovery-openid-config` | Public discovery retains the exact issuer; app ready, no login | `PASSED` |
| `-discovery-jwks-uri-keys` | Library JWKS fetch follows discovered randomized URI; prefetch completes, no login | `PASSED` |
| `-discovery-issuer-mismatch` | Setup rejects with typed config error, `iss` and `discovery_issuer_mismatch`; no login | `PASSED` |
| `-idtoken-sig-none` | Typed `disallowed_algorithm` rejection, with no UserInfo | `SKIPPED`, same optional policy as Basic |
| `-signing-key-rotation-just-before-signing` | Prefetched key-ID digests differ from the validated token's key ID; same app/cache | `PASSED` |
| `-signing-key-rotation` | Two validated ID-token/UserInfo logins with distinct signing-key IDs, local logout between them, same app/cache | `PASSED` |

The suite's JWKS responses include `no-store`. The
[security configuration](https://gitlab.com/openid/conformance-suite/-/blob/410812ef6bc72a84723c1685725edce3558e31e3/src/main/java/net/openid/conformance/security/WebSecurityConfig.java)
leaves dynamic `/test/**` endpoints in the security filter chain; its cache
headers prevent key storage in this deployment. A live policy probe records
that condition, and rotation evidence requires zero stored-key updates/hits.
Provider headers, keys, responses and test assertions remain unchanged.
The report lists `suite_jwks_no_store_prevents_cached_key_refresh_test`, keeps
`cached_key_refresh_tested = false` and `coverage_complete = false`, and cannot
turn an unstored key set into warm-cache rotation evidence.

The fixture's prefetch uses the installed library's internal JWKS helper under
its normal policies. Token validation still runs through public login APIs.
Opaque app/cache IDs, callback session numbers, per-login outcomes and key-ID
digests establish continuity without exposing keys, tokens or identity values.
The remaining C06 acceptance case needs cacheable independent-provider evidence;
the local HTTP-cache, invalidation, signature and refresh-throttle tests supply
separate package-owned coverage meanwhile.

Core selections also support actual mirai transport, while future multisession
is limited to smoke and refresh parity selections. Each module case owns a
fresh two-worker pool. Both workers must prove the private package namespace
and verified TLS, including wrong-hostname rejection, before the app starts.
Protocol audit records then identify the worker that performed token/UserInfo
work or rejected the invalid response. Parent-only work cannot satisfy an
async selection. The gate also checks main/worker counter totals and verifies
that observed workers stop during teardown.

The package/TLS probes call only `/api/server` and do not earn client protocol
coverage. Discovery-only Configuration cases still run setup in the main
process and must have no worker protocol events. Other Configuration cases
use the worker path, with serialized cache copies and the existing no-store
coverage limitation. The per-case pool prevents sharing credentials or hooks
between unrelated fixtures. The separate shared-pool scenario below exercises
reuse across issuers. Public-client discovery coverage remains outstanding C09
work. The confidential-client selections cover the additional authentication
methods in sync and mirai.

The `refresh` selection uses the pinned
[client refresh plan](https://gitlab.com/openid/conformance-suite/-/blob/410812ef6bc72a84723c1685725edce3558e31e3/src/main/java/net/openid/conformance/openid/client/OIDCCClientRefreshTokenProfileTestPlan.java).
It selects static registration, code flow, query callbacks, HTTP Basic client
authentication and synchronous transport. The plan has no forced per-module
variants; runtime results must match the full plan variant. Upstream marks
this plan as non-certifiable.

| Refresh module suffix (`oidcc-client-test` prefix) | Required app evidence | Suite verdict |
| --- | --- | --- |
| `-refresh-token` | Original validated login and refresh grant; public connection refresh succeeds, retains issuer/subject and original ID token, fetches UserInfo and exports the replacement access token | `PASSED` |
| `-refresh-token-invalid-issuer` | Original validated login, then ID-token rejection naming `iss`; session cleared, old connection unusable and token export blocked, no further UserInfo | `PASSED` |
| `-refresh-token-invalid-sub` | Original validated login, then ID-token rejection naming `sub`; same retirement checks, no further UserInfo | `PASSED` |

These cases exercise OIDC Core 12.2 through the module's public
`connection()$refresh()` API. Before and after checkpoints must retain the same
app, cache object and callback session. Exactly one login and one explicit
refresh action are permitted. The normal refresh performs the library's
required UserInfo retrieval; the two rejections must leave its count unchanged
from login. Access-token export consumes the successful credential locally and
proves that a retained connection cannot expose a rejected replacement. It
does not send an extra provider request after the suite has finished.

The audit hook observes the underlying typed ID-token error. The connection
API exposes its normal redacted access error to the app. The fixture observes
the default session-clearing policy without logging out or altering token
state itself. Raw identities, tokens and error messages stay private; only
allowlisted labels, counters and comparison booleans enter the report. Refresh
rotation, concurrency and retained connections have their separate regression
layers; this selection does not replace them.

The `auth-post`, `auth-secret-jwt` and `auth-private-jwt` selections use the
pinned [Comprehensive plan](https://gitlab.com/openid/conformance-suite/-/blob/410812ef6bc72a84723c1685725edce3558e31e3/src/main/java/net/openid/conformance/openid/client/OIDCCClientTestPlan.java).
They freeze the resolved code-flow module lists: twenty-nine for shared-secret
methods and twenty-eight for private-key JWT. Each selects
`oidcc-client-test` and `oidcc-client-test-invalid-iss` with static registration,
query callbacks and its declared authentication method. Both suite verdicts
must be `FINISHED/PASSED`. The positive case consumes validated ID-token and
UserInfo results; the negative case must reject `iss` without retaining an
identity or fetching UserInfo. Sync and mirai use the same expected outcomes.

Actual request evidence requires one GET authorization and one POST token
exchange, matching registered client IDs, a correct S256 challenge/verifier
pair, and no Authorization header. POST authentication must contain the matching
body secret and no assertion. JWT authentication must contain an assertion and
no body secret, with the registered HS256/RS256 algorithm, matching issuer and
subject, the token endpoint as audience, a JTI and valid short-lived timestamps.
Private-key JWT also requires the registered key ID. Required suite condition
results establish credential/signature and claim validation. The runner
compares sensitive values only in memory and exports allowlisted flags.

Public-client coverage remains unavailable through normal discovery in this
deployment. The pinned
[server-configuration condition](https://gitlab.com/openid/conformance-suite/-/blob/410812ef6bc72a84723c1685725edce3558e31e3/src/main/java/net/openid/conformance/condition/as/OIDCCGenerateServerConfiguration.java)
omits `none` from `token_endpoint_auth_methods_supported`, including when the
plan selects `client_auth_type=none`. Its
[public authentication sequence](https://gitlab.com/openid/conformance-suite/-/blob/410812ef6bc72a84723c1685725edce3558e31e3/src/main/java/net/openid/conformance/sequence/as/OIDCCValidateClientAuthenticationWithNone.java)
also performs no checks. A separate probe verifies the metadata, observes the
installed package's typed rejection of unadvertised public authentication and
ends `INTERRUPTED`. Its identities remain bound to the run, and it cannot count
as either a positive client test or public authentication coverage. Closing
this gap needs an appropriate independent-provider scenario or a reviewed suite
update; the package's discovery validation stays enabled.

The pinned client tests also skip PKCE verifier validation:
[the client base class](https://gitlab.com/openid/conformance-suite/-/blob/410812ef6bc72a84723c1685725edce3558e31e3/src/main/java/net/openid/conformance/openid/client/AbstractOIDCCClientTest.java)
guards `CheckPkceCodeVerifier` with `env.containsObject("code_challenge")`, while
[the challenge condition](https://gitlab.com/openid/conformance-suite/-/blob/410812ef6bc72a84723c1685725edce3558e31e3/src/main/java/net/openid/conformance/condition/as/EnsureAuthorizationRequestContainsPkceCodeChallenge.java)
stores it with `putString()`. The companion check computes SHA-256 and base64url
from the observed verifier, requires equality with the observed challenge and
requires the suite's successful S256 challenge-presence check. It records
`suite_pkce_verifier_checked = false`. This supplements the suite's verdict
with client-request evidence; rejection of an incorrect verifier needs a
separate enforcing provider. Earlier Basic/Form Post coverage flags describe
their pinned module selections and do not establish that missing enforcement.

All auth selections remain partial coverage of a non-certifiable plan. They
do not establish the entire Comprehensive plan or public-client conformance.
Private keys, request bodies and raw suite logs stay out of uploaded evidence.

The separate `run-shared-pool.R` selection alternates POST and private-key-JWT
clients in one R process with the same two mirai workers. Four plans supply two
credential generations per method. Each plan supplies a distinct discovered
issuer, shared by its positive and negative module instances. All eight cases
must pass the existing confidential-client evidence gates. The execution order returns
to both methods with fresh credentials after the first issuer rejections.

The aggregate gate binds every nested plan and module to the run, requires the
same process and worker identities throughout, and requires at least one worker
to have performed protocol work for both methods. Each case gets a fresh app,
client and cache object, and audit files from completed cases must remain
unchanged. Different hooks and timeout settings must reach the workers during
protocol work. Inspections before and after each case require both workers'
hook/timeout options and async session context to be clear. Final cleanup must
stop the shared process and workers before any nested case gets cleanup credit.

This establishes the recorded sequential reuse scenario. Simultaneous dispatch,
shared caches and other authentication pairings need separate evidence. The
public-client metadata and PKCE verifier-enforcement gaps above still apply.

The `fapi-dpop` selection uses the pinned
[FAPI 2.0 Security Profile client plan](https://gitlab.com/openid/conformance-suite/-/blob/410812ef6bc72a84723c1685725edce3558e31e3/src/main/java/net/openid/conformance/fapi2spfinal/FAPI2SPFinalClientTestPlan.java).
Its generic OIDC, private-key-JWT, DPoP, simple authorization, no-grant-management
variant resolves twenty-three modules. The plan forces unsigned PAR requests
and plain authorization responses. This first selection runs only the happy
path, happy path without DPoP nonce, and invalid ID-token issuer modules.

Configuration follows [client requirements 5.3.3](https://openid.net/specs/fapi-security-profile-2_0-final.html#section-5.3.3)
and [cryptography requirements 5.4.1](https://openid.net/specs/fapi-security-profile-2_0-final.html#section-5.4.1):
ES256 client authentication and proof keys, issuer-string assertion audience,
S256, authenticated PAR, minimal browser parameters, and DPoP-bound resource
access. The normal suite server configuration supplies a fresh ES256 signing
key. Assertions and nonce handling remain unmodified upstream checks.

`id_token_profile = "fapi2"` explicitly selects the library's implemented FAPI
ID-token algorithm set during discovery. It permits metadata without RS256,
keeps the advertised/caller intersection and all other discovery validation,
and does not enable the rest of FAPI automatically. PS256-only metadata has no
supported algorithm overlap under this policy. Standard OIDC discovery retains
its RS256 metadata requirement.

The gate requires both UserInfo and an explicit accounts GET through the public
connection API, with HTTP 200 and the suite's completion marker. Request evidence
binds all logs to the current instance, checks actual ES256 assertions, S256 and
DPoP method/URI/key/JTI/`ath` values in memory, and requires the corresponding
suite conditions. Nonce cases require repeated requests whose final proof has a
different nonce and successful suite nonce validation. The no-nonce module must
make exactly one request at each endpoint and omit nonce claims. Invalid issuer
handling must stop before either resource endpoint and retain no rejected token.

The login path runs in the selected sync/mirai transport. Resource access uses
the connection's synchronous imperative API in the Shiny process, with its PID
recorded explicitly. The complete FAPI module set, OAuth-only flows, callback
issuer/state cases, refresh, mTLS and message signing remain outside this first
selection. Its coverage flag stays false; no certification claim follows.

The `fapi-dpop-full` selection requires every one of those twenty-three modules.
It separates discovery rejection, callback rejection and post-token validation
in its evidence. The discovery module must identify the issuer mismatch and
make no PAR or authorization request. Callback issuer/state cases require the
specific allowlisted audit label, no validated identity and zero token, UserInfo
and accounts requests. Their PAR assertions and minimal browser requests still
need the appropriate suite/request checks. No token-verifier or resource proof
is credited to a pre-token rejection.

The eleven ID-token rejection cases cover issuer, audience (including an
untrusted additional audience or missing authorized party), algorithm, expiry
and nonce mutations. The seven positive cases cover the normal nonce path,
single-element audience arrays, omitted access-token expiry, token-type case,
DPoP challenge-scheme case, no nonce and no mTLS endpoint aliases. All must end
`PASSED`; no optional skip substitutes for an outcome in this configured variant.

All positive cases use the connection request API and check the accounts
completion response, finite expiry and a usable connection. The omitted-expiry
case exercises shinyOAuth's documented 3600-second fallback lifetime. The
fixture supplies no expiry and changes no token state. Resource work stays in
the Shiny process.

Malformed callbacks are rejected by the public UI's HTTP handler before a
callback Shiny session starts. The gate checks the actual HTTP 400 browser
response, privacy headers, body match, absence of reflected credentials and
allowlisted audit label. These error pages retain the callback query in the
address bar; reports record `callback_cleaned = false` for those four cases.
No callback session, token exchange or authenticated identity is credited.

Complete coverage for this selection means the pinned OIDC/private-key-JWT/DPoP
module set. Other sender constraints, refresh and certification
remain separate. The original three-module selection stays partial.

The `fapi-oauth-dpop` selection uses the separately resolved `plain_oauth`
variant. Its eleven modules comprise six positive resource flows, discovery
issuer mismatch and the same four callback issuer/state mutations. It excludes
all twelve modules specific to ID tokens. Static registration requests
`accounts`; the public OAuth discovery helper reads RFC 8414 metadata and
configures no OIDC scope, nonce, ID-token validation or UserInfo request.

An `authorized` outcome requires the actual access token, no ID token in the
suite response or app, zero UserInfo traffic, matching PAR scope with no OIDC
nonce, and a successful public connection request to the accounts endpoint.
The existing private-key-JWT, S256, DPoP key/URI/method/JTI/hash and nonce gates
still apply. Both transports require the same outcome; mirai must perform the
code exchange in a verified worker. Resource work remains in the Shiny process.
The module's `authenticated` signal indicates accepted credentials in this
OAuth-only flow and earns no OIDC identity credit. Discovery and callback
rejections earn no token or resource credit.

All eleven resolved OAuth-only modules are required for selection completion.
Three happy-path modules retain `WARNING` for `CheckStateLength`: encrypted
state exceeds the suite's 128-character interoperability threshold. The gate
checks the exact event source/message, the measured state length and absence
of other warning/failure/review findings. The remaining eight modules require
`PASSED`. This selection always keeps `coverage_complete = false` while the
state-length advisory is expected. It earns execution and resource-use evidence
without claiming complete warning-free OAuth-only coverage.
Metadata is unsigned JSON fetched over verified TLS, with the RFC 8414 URL
layout and exact issuer check. This adds no signed-metadata, refresh, mTLS or
certification claim. Callback error-page query retention remains visible.

The `fapi-oauth-dpop-reference` selection runs the same eleven modules with
`oauth_client(state_transport = "reference")`. All eleven must finish `PASSED`.
Each non-discovery result must report the real client's reference transport
and independent PAR evidence: a 22-128-character opaque URL-safe state value,
unchanged across retries. Only the length and validity result enter the
sanitized report. Missing proof, an encrypted client, oversized state, warning
or skipped result fails the gate. Complete coverage for this selection means
this pinned OAuth/private-key-JWT/DPoP variant using reference state. The
original encrypted-state selection keeps its warning policy and coverage limit.

The `fapi-oauth-mtls` selection resolves nine modules for private-key-JWT client
authentication and mTLS token binding. It excludes the two DPoP-only modules
and requests only `accounts`. All nine require `PASSED`, including the alias
fallback, token type/expiry and five pre-token rejection scenarios. Peer logs
from the TLS listener must correlate with each suite request and the registered
certificate. Authentication and sender constraint have separate evidence fields.
The fixture permits opaque tokens with `mtls_require_observed_cnf = FALSE`;
it retains the certificate on requests and verifies actual TLS and suite checks.

Three separate attacker instances must fail for missing/wrong certificates,
including an attempt to forge the certificate header. Missing certificates
produce HTTP 400. The pinned suite detects wrong certificates but continues to
return HTTP 200 with its resource marker. Those controls establish detection
and header replacement, while resource denial remains unproven. The gate forces
`coverage_complete = false` and the resource-denial coverage limit even if the
manifest's complete flag is changed. Other C11 work includes mTLS client
authentication and an independent resource-denial check. No suite condition or
production library default is changed by this fixture.

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
