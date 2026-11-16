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
