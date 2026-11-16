**shinyOAuth protocol quality: implementation plan**

Prepared 2026-11-12 against shinyOAuth commit
`25318cc6488a2a98bfc83d484cbbdb3190854967` (version `0.7.0.9000`).
Status: implementation started. The original investigation ran no external
tests. C01 supplies a working local suite preflight, and C02 supplies a validated
Shiny fixture. C03 adds the suite API driver and evidence validator. C04 executes
three real-browser smoke modules. C05 extends the runner to all fourteen Basic
RP modules for the pinned static-registration, synchronous code-flow variant.
C06 now executes all six Configuration modules, with cached-key refresh coverage
still incomplete because the pinned suite's JWKS responses prohibit storage.
C07 covers the fourteen-module Form Post Basic plan in Chrome on the local
cross-origin, same-site deployment.
C08 covers all three client refresh modules, including identity substitution
and the module's default credential-retirement policy.
C09 adds verified mirai transport for the core selections, future multisession
smoke/refresh parity, confidential-client authentication selections and sequential
shared-pool issuer isolation. Public-client discovery coverage remains
outstanding, so C09 is not complete.
C10 includes the complete twenty-three-module OIDC/private-key-JWT/DPoP
variant and an eleven-module OAuth-only selection. The OAuth-only state-length
advisory keeps that selection's coverage incomplete and C10 open.

Execution record (2026-11-12): C00 is `d0b62ff`; C01 is `4dee03d`. C01 validated the exact server
image/source correspondence, required plans, R certificate/hostname validation,
Chrome certificate pinning and wrong-pin rejection, and complete owned-resource
cleanup in consecutive disposable deployments on Windows/Docker Linux
containers. Its 11 environment assertions pass with no failures or skips;
formatting and lint checks pass. Startup reports the host's existing C.UTF-8
locale warnings. This establishes environment readiness, not RP conformance.
Chrome uses an isolated SPKI pin instead of installing a temporary root in the
system trust store; the environment README records that scope adjustment.

C02 is `88517ea`. It installed this checkout into an isolated R library and drove its public
module/UI APIs in Chrome against a local HTTPS metadata fixture. The code/S256,
nonce/state and openid-scope checks passed, a discovery issuer mismatch stopped
startup, and the synthetic secret stayed out of the DOM and app logs. No token
was issued and no independent client conformance verdict was collected.
Follow-up validation also requires the failed setup's private diagnostic to
identify an issuer mismatch, so an unrelated app crash cannot satisfy that check.
The follow-up preflight and fixture checks both passed, along with the 11 helper
assertions, `jarl check integration/openid`, `air format integration/openid
--check` and patch whitespace validation.

C03 is `2b06b7a`. It passed 51 evidence assertions with no failures or skips. Its live API check
created the pinned Basic plan, checked all module variants, retrieved a waiting
module's issuer, rejected an unknown instance and verified interruption on
cancellation. Owned Docker resources were removed. Its sanitized report marks
client conformance unattempted and keeps the conformance gate false.

The first C04 browser run produced three passing suite verdicts, but the local
gate correctly failed because issuer/nonce errors lacked safe claim labels.
`83ec40e` adds those labels to the existing typed audit events without exposing
claim values or changing validation. Its focused signed-token regression checks
and neighboring ID-token checks passed: 162 assertions, zero failures, warnings
or skips.

C04 is `d723b6b`. It adds the real Chrome driver, app-stop failure control, callback cleanup
checks and a manual Ubuntu workflow. Two complete Windows smoke runs passed
all three modules with matching app evidence and owned-resource cleanup. The
evidence validator now has 54 passing assertions. Coverage remains partial;
C05 is next. Preflight, API checks and all three smoke modules also passed as
a non-root Linux user (R 4.5.0, Chromium 156), including caller-owned TLS key
generation. The manual GitHub workflow has not run yet; its actionlint check
passes, along with R lint, formatting and patch whitespace checks.

Sanitized reports retained locally under `integration/openid/.artifacts/`:
`smoke-20261112-225149-dbdbc91a7b81/evidence.json` and
`smoke-20261112-225410-77d6e303d949/evidence.json` (Windows), plus
`smoke-20261112-220117-83dd3e2312e6/evidence.json` (Linux). Each reports a
passing smoke gate, verified cleanup and incomplete full-profile coverage.

`02e677e` extends safe ID-token audit classification to audience, subject,
issued-at, disallowed algorithms and invalid signatures. The signed-token
regressions and neighboring claim checks passed 263 assertions with no failures,
warnings or skips. Validation behavior remains unchanged.

C05 is `c4ae74e`. It executes all fourteen modules and requires the corresponding app evidence.
Thirteen require `FINISHED/PASSED`; only `oidcc-client-test-idtoken-sig-none`
requires `FINISHED/SKIPPED`, matching the pinned suite's documented optional
unsigned-token support and shinyOAuth's `disallowed_algorithm` rejection.
The gate also requires no UserInfo completion for rejected ID tokens. For a
UserInfo subject mismatch, the typed error and suite verdict establish the
UserInfo response, while the token-exchange completion audit establishes the
preceding validated ID token. A UserInfo rejection can precede its completion
audit; an initial Linux run caught and corrected that harness assumption.

The evidence validator passes 115 assertions, including all-module coverage,
the exact unsigned-token exception and rejection-category checks. The complete
Windows Basic run took 90.35 seconds for its module loop, and a later smoke run
took 23.31 seconds. Those timings include per-case app/browser startup and
suite waits, but exclude package installation, suite startup, the app-stop
control and stack teardown. The Ubuntu workflow now runs smoke on relevant
pull requests and offers Basic through manual dispatch. Full Basic stays manual
until GitHub runner timings are measured; no GitHub run has executed yet.

Windows reports retained under `integration/openid/.artifacts/`:
`basic-20261112-230808-fe5a9984784b/evidence.json` (complete Basic module coverage)
and `smoke-20261112-231056-3e4d6d264675/evidence.json` (partial coverage).
Both gates pass with verified owned-resource cleanup. C06 is next.

The corrected full Basic gate also passed as a non-root Linux user with R 4.5.0
and Chromium 156. Its module loop took 77.75 seconds; the retained report is
`integration/openid/.artifacts/basic-20261112-221342-9dbc14ec0352/evidence.json`.
All fourteen modules finished with their expected verdict and app evidence,
the app-stop control passed, and owned-resource cleanup completed. R lint,
formatting, actionlint and patch whitespace checks pass.

C06 execution: `efb54a5` adds its runner coverage; `65fb2cb` adds a safe `discovery_issuer_mismatch` audit reason and
the `iss` claim label without changing validation. Discovery and neighboring
JWKS tests passed 234 assertions with no failures, warnings or skips.
The runner now resolves separate Basic/Configuration plans, verifies the exact
six-module Configuration list and schedules both upstream-ignored rotation
modules. Discovery-only results earn no login credit. A failed discovery setup
must identify the expected issuer check through typed audit evidence.

The first live Configuration run completed all six suite modules, but its local
gate rejected the cache evidence. A separate module confirmed that JWKS is sent
with `Cache-Control: no-cache, no-store, max-age=0, must-revalidate`.
shinyOAuth correctly leaves those keys unstored. No suite headers, response
bodies, assertions or client cache policy were changed to force a warm cache.
The recorded limitation is
`suite_jwks_no_store_prevents_cached_key_refresh_test`.

The before-signing scenario prefetches through the installed package's internal
JWKS helper, then requires a validated token with a different signing-key ID.
The repeated-login scenario requires two validated ID-token/UserInfo outcomes,
different key IDs, a local logout between them and the same R app/cache
instances throughout. Only key-ID digests leave the fixture. The driver waits
for the next callback session, which prevents a logged-out state from satisfying
the second-login wait. The evidence validator passes 168 assertions; focused
HTTP-cache, invalidation, signature and refresh-throttle regressions add 74
passing assertions with no failures, warnings or skips.

Configuration gates pass on Windows (R 4.5.1, Chrome 157) and non-root Linux
(R 4.5.0, Chromium 156): five modules are `FINISHED/PASSED`, and unsigned-token
rejection is `FINISHED/SKIPPED` under its existing optional policy. Both runs
verify owned-resource cleanup. Their module loops took 38.35 and 29.79 seconds.
Sanitized reports retained under `integration/openid/.artifacts/` are
`config-20261112-233608-c8bf6297fde2/evidence.json` (Windows) and
`config-20261112-223608-312b32a78ab4/evidence.json` (Linux).
Manifest and client-evidence schemas are now version 2. Manual workflow dispatch
offers `config`; pull requests continue to run smoke.
The full Basic profile also passed again on non-root Linux after the plan and
driver changes, with all fourteen expected module outcomes and complete Basic
coverage. Its retained schema-2 report is
`integration/openid/.artifacts/basic-20261112-223754-36fbb02417e4/evidence.json`;
the module loop took 80.85 seconds. R lint, formatting, actionlint and patch
whitespace checks pass. No owned suite containers remain after validation.

C06 acceptance remains partial: reports keep `selection_complete = true`,
`coverage_complete = false` and `cached_key_refresh_tested = false`, even if the
manifest accidentally requests a complete-coverage label. A follow-up must test
warm-cache key replacement against an independent cacheable provider (an
applicable Keycloak scenario or C13's second provider), or a reviewed suite
configuration/version that permits caching. Preserve the current no-store runs
as their own evidence. C07's form-post work can proceed independently; the first
OIDC milestone retains this C06 coverage gap until that follow-up passes.

C07 is `20966df2`. C07 execution (2026-11-13): the pinned Form Post Basic plan
resolves to the fourteen Basic modules with its fixed `response_mode=form_post` variant. The
runner installs the normal Form Post wrapper and records sanitized Chrome
navigation evidence separately from incoming POST metadata. Every case must
show GET authorization, a form-encoded callback POST from the expected provider
Origin, the 303 bridge redirect, Secure `SameSite=Strict` binding-cookie
metadata, completed callback validation and final callback-query cleanup.
No raw request/response bodies, callback queries or cookie values are retained.

The full profile passes on Windows (R 4.5.1, Chrome 157) and non-root Linux
(R 4.5.0, Chromium 156): thirteen `FINISHED/PASSED` verdicts and the documented
unsigned-token `FINISHED/SKIPPED`, with matching app outcomes and verified
cleanup. Module loops took 103.27 and 81.54 seconds. Retained sanitized reports
under `integration/openid/.artifacts/` are
`form-post-20261113-205121-e013f0e3cb20/evidence.json` (Windows) and
`form-post-20261113-195207-4bded3721513/evidence.json` (Linux).
Their actual provider/app origins were `https://localhost:59182` /
`https://localhost:60189` and `https://localhost:59345` /
`https://localhost:41039`, respectively. Chrome observed `same-site` on every
callback, so `cross_origin = true` and `cross_site = false`. This scope does
not replace the separate cross-site attack fixtures.

The evidence validator passes 208 assertions, including rejection of missing
POST/bridge/binding observations, stale origins, wrong transports and incorrect
site labels. Existing Form Post response-mode, module-transport and candidate
storage regressions passed 532 assertions with no failures, warnings or skips.
The query-callback smoke selection also passed again on Windows, with its
partial-coverage flag and cleanup intact. Its report is
`integration/openid/.artifacts/smoke-20261113-205453-266a10a4126f/evidence.json`;
the module loop took 22.91 seconds. R lint, formatting, actionlint and patch
whitespace checks pass.
Manual workflow dispatch now offers `form-post`; pull requests continue to run
smoke. The upstream Form Post Basic plan does not select the separate
`oidcc-client-test-form-post-error` module; comprehensive-plan coverage remains
a C09 task. The C06 warm-cache gap remains open.

C08 is `3c7aa049`. C08 execution (2026-11-13): the pinned client refresh plan
resolves to three modules with no forced per-module variants. A live API probe established that
the plan uses JSON null for those variants. The driver omits the optional
runner variant parameter for those entries and still requires the complete
plan variant in every runtime result.

Each case completes a normal browser login, retains the original grant and
validated identity in the same app and Shiny session, then explicitly calls
the public connection's `$refresh()` method. The positive case retains the
original ID token, issuer, subject and connection, fetches UserInfo during
refresh, and exports the new access token through `$access_token()`. The two
negative cases require an ID-token audit error naming `iss` or `sub`, the
normal `token_refresh_error`, session clearing, an unusable retained connection
and blocked access-token export. Their UserInfo count stays at the initial
login's one request. The fixture does not log out or modify token state to
produce those outcomes. Reports contain comparison booleans and counts,
without identity or credential values.

The changed-subject rejection already existed; diagnostic commit `bfe4fdf8`
adds its missing safe claim label. The signed-claim audit, refresh issuer/audience
and rejected-refresh cleanup regressions pass 321 assertions with no failures,
warnings or skips. The expanded evidence validator passes 307 assertions,
including attempts to pass with missing grants, new sessions/apps, absent
checkpoints, wrong operation counts or incomplete retirement evidence.

All three modules finish `FINISHED/PASSED` on Windows (R 4.5.1, Chrome 157)
and non-root Linux (R 4.5.0, Chromium 156), with matching app outcomes, the
real-app failure control and verified cleanup. The module loops took 25.53
and 22.96 seconds. Retained sanitized reports are
`integration/openid/.artifacts/refresh-20261113-222805-fd5b072e2f42/evidence.json`
(Windows) and
`integration/openid/.artifacts/refresh-20261113-212915-8f51a2246236/evidence.json`
(Linux). Both record the C08 working tree based on `bfe4fdf8` with
`checkout_dirty = true`. Each reports complete coverage for this exact
synchronous, static-registration, code-flow refresh plan with query callbacks
and HTTP Basic client authentication. The upstream refresh plan is outside
certification.

The query-callback smoke selection passes again with partial coverage and
verified cleanup; its report is
`integration/openid/.artifacts/smoke-20261113-222936-bd3794b1ce39/evidence.json`.
R lint, formatting, actionlint and patch whitespace checks pass.

Manual workflow dispatch now offers `refresh` and uploads only its sanitized
evidence files. Pull requests continue to select smoke. The GitHub workflow
has not run yet. Further C09 work follows below; C06's warm-cache
gap remains open, and rotation/concurrency/retained-connection regressions
remain separate evidence layers.

C09, first slice (2026-11-13): all core selections accept `--transport mirai`.
Future multisession is limited to smoke and refresh parity selections; other
future profile combinations fail explicitly. Each module case starts its own
two-worker pool and checks backend selection. Both workers must load the
private checkout namespace, make a verified HTTPS request to `/api/server`
using the temporary CA and reject a wrong hostname. These setup probes do not
earn protocol coverage. Actual token/UserInfo and validation-error events must
come from the observed worker PIDs, with the matching package version and CA
setting. Main-only execution cannot satisfy an async selection.

The fixture's audit hook now writes only sanitized, allowlisted metadata to
atomic per-event files. The main app aggregates process-specific operation
counts and safe claim/error labels. Every event stays bound to its run and
package installation, while credentials, identities, error messages and paths
stay out of those records. Refresh waits for its promise before checking
identity continuity, token export and credential retirement. Evidence schema 3
requires these transport checks and verified process cleanup; the profile
manifest remains schema 2. The validator passes 363 assertions with no failures,
warnings or skips, including rejection of fallback execution, missing/foreign
worker PIDs, stale installations, failed TLS probes and absent cleanup.

The app registers exit handlers for its worker pool. Linux first interrupts
the app and permits orderly shutdown; forced termination remains a fallback.
Cleanup checks both descendants and the specifically observed worker PIDs.
Docker-hosted drivers need `--init` to reap orphaned workers; a bare R process
as container PID 1 left zombie entries and correctly failed the strict check.
The browser has an explicit temporary profile, a 30-second startup budget and
an observed close-command promise. Browser process termination remains required.
Native websocket EOF messages can appear during intentional browser shutdown.
Browser/port fixes are in the separate harness commit `9b287959`.
The suite now publishes random loopback ports in 20000-45000: Linux-side port
probes could not see Windows Docker Desktop's excluded dynamic-port ranges,
which caused real bind failures in the earlier 49152-65535 range.

Manual dispatch now selects the transport and installs the worker dependencies.
Pull requests retain synchronous smoke; hosted CI timings remain unmeasured.
Configuration keeps `coverage_complete = false` in every transport. Its main
cache template is retained, while async dispatch serializes worker copies;
the report records that scope and does not claim a shared warm cache.

The complete Basic, Form Post Basic, Configuration and refresh selections pass
with mirai on Windows (R 4.5.1, Chrome 157, mirai 2.7.1) and non-root Linux
(R 4.5.0, Chromium 156, mirai 2.7.4). All declared module outcomes match the
suite and application checks, with the real-app failure control and verified
cleanup. Basic and Form Post each retain thirteen `PASSED` verdicts plus the
documented unsigned-token `SKIPPED`; Configuration retains five `PASSED` and
that optional skip. Refresh has three `PASSED` verdicts.

| Selection | Windows module loop | Linux module loop |
| --- | --- | --- |
| Basic / mirai | 157.75 s | 95.50 s |
| Form Post Basic / mirai | 150.83 s | 95.41 s |
| Configuration / mirai | 69.33 s | 32.25 s |
| Refresh / mirai | 37.74 s | 25.45 s |
| Smoke / future | 37.99 s | 24.99 s |
| Refresh / future | 45.31 s | 27.52 s |

The future selections pass with future 1.70.0 on Windows and 1.82.0 on Linux.
Sanitized schema-3 reports under `integration/openid/.artifacts/` include:

- Windows: `basic-20261113-224918-c98fc0ad9117/evidence.json`, `form-post-20261113-231601-f40dd9f616b5/evidence.json`, `config-20261113-225346-c4dd54b93768/evidence.json`, `refresh-20261113-224809-cf25641baaea/evidence.json`, `smoke-20261113-224820-a2840f185a5d/evidence.json` and `refresh-20261113-230418-946e7c173ce2/evidence.json`.
- Linux: `basic-20261113-215019-b5b5bd25b46f/evidence.json`, `form-post-20261113-221551-0dbc136ba7dc/evidence.json`, `config-20261113-220529-54ce297a7813/evidence.json`, `refresh-20261113-220408-cde4fe717945/evidence.json`, `smoke-20261113-220733-29ad7872d4bc/evidence.json` and `refresh-20261113-220851-65f1d7cca4d6/evidence.json`.

These working-tree runs record parent `3c7aa049` and `checkout_dirty = true`.
Earlier Linux attempts failed on reserved Windows ports, unreaped container
zombies or Chrome's 10-second startup limit; they retain failed reports and
earn no coverage. Final Form Post runs include the explicit browser profiles
and longer startup budget. Windows preflight and the synthetic fixture check
also pass, as does synchronous smoke. The GitHub workflow has not run yet.

The existing async serialization, option-restoration and session-context tests
pass 222 assertions on Linux with no failures, warnings or skips after adding
the optional `otelsdk` test dependency to the private runner image. Their
Windows run passes the same 222 assertions with one environment warning: its
installed future binary was built under R 4.5.3 while the host uses R 4.5.1.
No user R installation was changed. R lint, formatting, actionlint and patch
whitespace checks pass. The final evidence gate also accepts all seventeen
retained passing schema-3 reports from this implementation run.

C09, confidential-client slice (completed 2026-11-16): `auth-post`,
`auth-secret-jwt` and `auth-private-jwt` select two modules each from the pinned
Comprehensive plan: the normal login and invalid-issuer modules. The resolved
code-flow lists contain twenty-nine modules for shared-secret authentication
and twenty-eight for private-key JWT; the manifest freezes those lists and
requires their null per-module variants. These selections stay partial and
the upstream plan is non-certifiable.

Static registration declares the selected method, with fresh credentials per
plan. Secret JWT uses HS256; private-key JWT uses RS256 with a fresh RSA key
and public-only JWKS registration. The app receives the private PEM and uses
normal public discovery, client and module APIs. Sync and mirai must each
produce a validated ID-token/UserInfo login and a typed issuer rejection,
with no retained rejected identity or UserInfo request after that rejection.

The evidence helper reads the suite's recorded HTTP requests and authentication
condition results. It requires the actual expected method, matching client IDs,
no mixed authentication mechanisms, correct secret or JWT metadata, and
successful credential/signature and claim checks from the suite. Sensitive
values are compared only in memory. Raw logs, secrets, assertions, private keys,
codes and claim values stay out of the report. Evidence tests cover stale
instance/probe identities, wrong credentials, mixed auth, invalid PKCE, bad
assertion metadata and accidental disclosure. All 547 assertions pass with no
failures, warnings or skips.

Two pinned-suite gaps remain explicit. The public-client variant still omits
`none` from discovery and its public authentication sequence performs no checks.
A separate disposable probe confirms the missing advertised method and the
installed package's typed discovery rejection. The probe is cancelled and
earns no conformance credit; `public_client_authentication_tested = false`.
Metadata and discovery policy remain unchanged.

The client base class also guards verifier validation with
`env.containsObject("code_challenge")`, while the challenge condition stores a
string. Consequently the pinned code-flow client plan skips its verifier check.
The companion helper requires the suite's S256 challenge-presence check and
independently computes the challenge from the actual token-request verifier.
It retains `suite_pkce_verifier_checked = false` and a coverage limitation.
This establishes matching client requests; bad-verifier rejection still needs
an enforcing provider. The [scope record](../integration/openid/scope.md) links
the exact pinned source and describes the limits.

All twelve authentication selections passed on Windows (R 4.5.1, Chrome 157)
and Linux (R 4.5.0, Chromium 156): three methods, two transports and two operating
systems. Their twenty-four modules finished `PASSED`, each with matching app
and request evidence. All twelve current evidence gates pass with verified
cleanup and `coverage_complete = false`. Module-loop times and sanitized reports
under `integration/openid/.artifacts/` are recorded below. Times exclude package
installation, suite startup, the public capability probe, app-stop control and
stack teardown. The four retained 2026-11-13 sync reports identify parent commit
`6870f73d`; the eight 2026-11-16 reports identify `91ef76de`. All record a dirty
checkout containing this authentication slice, rather than claiming a committed
build identity.

| Environment | Profile / transport | Loop seconds | Report directory (`evidence.json`) |
| --- | --- | ---: | --- |
| Windows | `auth-post` / sync | 21.01 | `auth-post-20261113-234810-580da618c227` |
| Windows | `auth-post` / mirai | 30.38 | `auth-post-20261116-195235-cd2ed72978e6` |
| Windows | `auth-secret-jwt` / sync | 21.13 | `auth-secret-jwt-20261113-234810-3c9b4258d04e` |
| Windows | `auth-secret-jwt` / mirai | 30.59 | `auth-secret-jwt-20261116-195235-bd4bee39e8d3` |
| Windows | `auth-private-jwt` / sync | 21.31 | `auth-private-jwt-20261113-234810-9c805b7721d6` |
| Windows | `auth-private-jwt` / mirai | 29.66 | `auth-private-jwt-20261116-195235-cb390ae9e7f0` |
| Linux | `auth-post` / sync | 13.14 | `auth-post-20261113-224811-906941c0d82c` |
| Linux | `auth-post` / mirai | 17.49 | `auth-post-20261116-185235-9be6b0e71593` |
| Linux | `auth-secret-jwt` / sync | 11.61 | `auth-secret-jwt-20261116-185400-9f2942acd2c5` |
| Linux | `auth-secret-jwt` / mirai | 13.82 | `auth-secret-jwt-20261116-185509-7d41755f71d2` |
| Linux | `auth-private-jwt` / sync | 11.91 | `auth-private-jwt-20261116-185616-90666f5c488d` |
| Linux | `auth-private-jwt` / mirai | 14.56 | `auth-private-jwt-20261116-185724-2463f2a9c051` |

The existing synchronous smoke selection also passed again on Windows: three
module verdicts, the current evidence gate and cleanup, in 32.71 seconds. Its
report is `smoke-20261116-195540-a0f48c1f0e5f/evidence.json`. All test installs
used private libraries. R lint, formatting, actionlint and patch whitespace
checks pass. Hosted CI has not run.

Image-acquisition fix `91ef76de` was necessary when validation resumed: on
2026-11-16 the upstream registry returned `not found` for the locked server
digest. Cached images are now accepted only when their `RepoDigests` match the
locked content digest. Missing images must still be pulled by that digest.
The full server-jar source check and live API revision/TLS checks remain intact.
Preflight passes all 26 environment assertions and the live checks using the
verified cache. Reports distinguish cached images from pulled images. A fresh
CI runner needs an available verified mirror or a reviewed lock update; the
hosted workflow has not run and remains blocked by that availability issue.

C09, shared-pool slice (2026-11-16): `run-shared-pool.R` keeps one R process
and two verified mirai workers alive across eight alternating browser flows.
POST and private-key-JWT clients each complete a normal login and a typed
issuer rejection, then repeat with fresh registrations and credentials. Each
plan has a distinct discovered issuer, shared by its two modules. Each case
gets a new app, client and cache object, while the process and worker identities
must stay the same. The gate requires an observed worker to perform protocol work for both
methods; merely starting a pool cannot establish reuse.

Four nested selections retain the existing authentication evidence gates,
including actual request comparisons, S256, suite authentication checks and
typed issuer rejection. The aggregate gate binds the plan/module identities and
execution order. Different audit hooks and timeout settings must reach protocol
work. Both workers are inspected before and after every case for restored
hook/timeout options and empty async session context. Earlier audit files must
remain unchanged after later cases. Cleanup credit stays false until the shared
process and observed workers stop. The first live attempt caught a fixture
handoff bug: a completed case's stop signal could end the next app. The fixture
now closes its session and retires that signal before the next handoff, and an
unrequested app stop fails immediately.

This checks sequential reuse, including returning to both authentication
methods with new credentials after the first rejected logins. Concurrent
multi-issuer dispatch, shared cache objects and other auth pairings remain
outside this selection. Reports keep partial coverage and the existing suite
public-client and PKCE limitations. The manual workflow exposes `shared-pool`
with mirai and uploads only its sanitized root report. Registry availability
still blocks a fresh hosted run.

Validation completed on Windows (R 4.5.1, Chrome 157) and Linux (R 4.5.0,
Chromium 156). Each run exited zero after eight `FINISHED/PASSED` verdicts,
four passing nested authentication gates, the aggregate isolation gate and
verified cleanup. All 640 evidence assertions pass with zero test failures,
warnings or skips. The existing Windows synchronous smoke selection passed
its three modules and cleanup again. R lint, formatting, actionlint and patch
whitespace checks pass. No package R code or user R installation changed.

Sanitized reports under `integration/openid/.artifacts/`:

| Environment / selection | Module-loop seconds | Report directory (`evidence.json`) |
| --- | ---: | --- |
| Windows / shared-pool | 55.98 | `shared-pool-20261116-201955-29f6d05a5ba2` |
| Linux / shared-pool | 47.95 | `shared-pool-20261116-191955-c75314810211` |
| Windows / sync smoke | 39.75 | `smoke-20261116-201946-0a1ebbc1821f` |

The shared-pool timings include all eight per-case app/browser handoffs and
worker-state inspections, but exclude installation, suite/pool startup,
capability/failure controls and final teardown. Both reports identify parent
commit `b409b465` and the dirty checkout containing this slice. They record
verified cached images at the unchanged locked digests and partial coverage.
The gate and documentation now reflect the suite's actual issuer scope: one
distinct issuer per plan, shared by its positive and negative modules. Failed
development runs retain failed gates and earn no validation credit.

C09 follow-up: complete public S256 coverage against an appropriate provider
or corrected suite. Existing Keycloak public and PKCE scenarios remain separate
evidence. Keep C09 open until that acceptance case passes, and retain the C06
warm-cache gap.

C10, first slice (2026-11-16): `fapi-dpop` selects the generic OIDC,
private-key-JWT, DPoP, simple-authorization variant of the pinned final Security
Profile client plan. The API resolves twenty-three modules and forces unsigned
PAR requests with plain authorization responses. The manifest freezes that
module/variant list. This slice selects the nonce happy path, the happy path
without DPoP nonce, and invalid ID-token issuer rejection. Coverage stays false.

Commit `d3736366` adds the explicit `id_token_profile = "fapi2"` discovery
policy. The first live attempt exposed the mismatch between standard OIDC's
RS256 discovery requirement and FAPI's permitted signing algorithms. The new
policy keeps normal issuer, endpoint, JWKS and metadata validation, and
intersects implemented FAPI algorithms with the caller and advertised sets.
Standard OIDC still requires RS256. PS256-only metadata has no supported
algorithm overlap. The discovery fix passed 367 focused assertions with zero
test failures, warnings or skips, including the existing standard OIDC cases.

The fixture supplies separate ephemeral ES256 server, client-authentication
and DPoP keys through the normal suite/provider configuration. Client
registration contains only its public key. Normal discovery selects DPoP token
types and the existing minimal front-channel mode; compatibility mode's extra
browser parameters correctly failed the first suite run. Client assertions
use the discovered issuer as a string audience. The app validates its ID token
and UserInfo before explicitly requesting the exported accounts endpoint
through the public connection API. HTTP 200 and the suite's completion marker
are required; UserInfo alone cannot satisfy resource coverage.

Evidence compares actual PAR, token, UserInfo and accounts requests in memory.
It requires ES256 assertions, correct S256, only client ID/request URI at the
authorization endpoint, DPoP method/URI/key consistency, distinct JTIs and the
resource access-token hash. Nonce cases require observed repeated requests
with changed nonces and the suite's successful nonce checks. The no-nonce case
requires one request at each endpoint and absent proof nonces. The suite's
verifier-matching condition runs in this plan; the separate OIDC-plan PKCE
limitation remains unchanged. Invalid ID-token issuer handling must retain no
token and make no UserInfo or accounts call.

Login executes in the chosen sync/mirai transport. The connection's imperative
resource request runs in the Shiny process, and reports record that PID and
scope. Raw logs, assertions, proofs, keys, credential values and response bodies
stay out of uploaded reports. Manual CI offers this selection; fresh hosted
execution still needs the pinned server image to become available.

Validation completed in sync and mirai on Windows (R 4.5.1, Chrome 157) and
Linux (R 4.5.0, Chromium 156). All four commands exited zero after three
`FINISHED/PASSED` verdicts, matching application/request evidence and verified
cleanup. The nonce happy paths each made two PAR, token, UserInfo and accounts
requests; the no-nonce paths made one at each endpoint. Invalid-issuer cases
stopped after the token response. All 779 evidence assertions pass with no
test failures, warnings or skips. The standard Windows synchronous smoke
selection also passed its three modules and cleanup. R lint, formatting,
actionlint and patch whitespace checks pass.

Sanitized reports under `integration/openid/.artifacts/`:

| Environment / transport | Module-loop seconds | Report directory (`evidence.json`) |
| --- | ---: | --- |
| Windows / sync | 36.49 | `fapi-dpop-20261116-204524-67ca76edf8d7` |
| Windows / mirai | 42.78 | `fapi-dpop-20261116-204730-0eafe2c719b0` |
| Linux / sync | 21.05 | `fapi-dpop-20261116-194525-3e3d0fabba04` |
| Linux / mirai | 25.72 | `fapi-dpop-20261116-194730-30a5b7663c7e` |
| Windows / sync smoke | 40.07 | `smoke-20261116-204730-94d6b0f8e4f9` |

These timings exclude installation, suite startup, the app-stop control and
final teardown. The four FAPI reports identify committed product fix
`d3736366` and the dirty checkout containing this runner slice. All report
verified cached images at the unchanged locked digests and partial coverage.
Private test libraries leave the user's R installation unchanged. Failed
development runs retain failed gates and receive no validation credit.

C10, full OIDC variant (2026-11-16): `fapi-dpop-full` executes all twenty-three
modules resolved for the same pinned OIDC/private-key-JWT/DPoP variant. The
original three-module `fapi-dpop` selection stays partial. Manual CI now offers
both selections without changing the source, images or suite assertions.

The full selection adds discovery issuer mismatch, eleven ID-token rejection
cases, four malformed authorization callbacks and seven positive flows in
total. ID-token failures require the expected typed claim or algorithm reason,
no retained token and no UserInfo/accounts call. The additional-audience case
accepts either an audience or authorized-party rejection, since both reject
the untrusted additional recipient. Positive cases cover audience arrays,
omitted access-token expiry, token-type and DPoP challenge-scheme case, nonce
absence and absent mTLS endpoint aliases. All use the public connection API,
require a usable connection and check the accounts completion response. Missing
`expires_in` exercises the package's documented 3600-second fallback; the
fixture supplies no expiry and changes no token or validation state.

The malformed callbacks are rejected by the public UI's HTTP handler before a
callback Shiny session starts. The driver therefore collects the actual browser
HTTP 400 response instead of waiting for a second Shiny snapshot. Its evidence
requires the matching allowlisted audit label, response body match, no-store,
no-referrer, plain text and no reflected credentials. App/cache/session
identities must match the initial unauthenticated session. No token exchange,
UserInfo or accounts request is allowed, and this stage earns no authentication
or worker protocol-work credit. Discovery rejection likewise earns only
discovery-stage evidence. Malformed-callback error pages retain their query in
the address bar; reports explicitly record `callback_cleaned = false` for those
four cases. Other callback paths still require URL cleanup.
C15 should revisit query retention on these HTTP error pages as a separate
privacy improvement, while preserving rejection and preventing reflection of
callback credentials.

Complete coverage for `fapi-dpop-full` means this exact resolved variant only.
Resource requests still run in the Shiny process, including mirai login runs.
Private HTTP observations, callback values and raw suite logs stay under ignored
artifacts; uploaded reports contain only allowlisted comparisons and counters.
Failed development runs keep failed gates and receive no validation credit.

An initial full run completed all twenty-three suite modules but failed the
local evidence gate: the issuer mutation condition emits a plain event without
a result field, while the gate incorrectly required `SUCCESS`. An attempted
`INFO` interpretation also failed and receives no validation credit. Inspection
of the live API payload confirmed the event shape. The corrected gate matches
its source, exact message and mutated issuer against the suite's exported
issuer, with no result field. Regression checks reject substituted levels,
messages, sources and issuers; the upstream suite verdict independently must
still be `FINISHED/PASSED`.

Commit `29724328` fixes a separate audit gap exposed by the expiry modules:
missing, malformed and expired `exp` values were correctly rejected, but their
typed errors omitted the claim label. They now report `claim = "exp"` without
the value. The rejection rules are unchanged. All 300 focused JWT/audit
assertions pass with zero test failures, warnings or skips. The full selection
continues to require the specific claim label; it does not accept an unrelated
ID-token error. The runner now checks app, transport and FAPI evidence after
each case, naming the failed module and evidence layer immediately. Final
report validation still checks the complete selection, bindings and cleanup.

Final validation passed in sync and mirai on Windows (R 4.5.1, Chrome 157) and
Linux (R 4.5.0, Chromium 156). All four commands exited zero with twenty-three
`FINISHED/PASSED` verdicts each, matching app/request evidence, complete variant
gates and verified cleanup. Independent report revalidation confirmed all 92
outcomes and all four coverage gates. All 966 evidence assertions pass with
zero test failures, warnings or skips. Standard Windows synchronous smoke also
passed its three modules and cleanup. R lint, formatting, actionlint and staged
patch whitespace checks pass.

Sanitized reports under `integration/openid/.artifacts/`:

| Environment / transport | Module-loop seconds | Report directory (`evidence.json`) |
| --- | ---: | --- |
| Windows / sync | 385.97 | `fapi-dpop-full-20261116-214626-859ae6ff835d` |
| Windows / mirai | 430.34 | `fapi-dpop-full-20261116-214626-5a0b7ce12224` |
| Linux / sync | 229.97 | `fapi-dpop-full-20261116-204730-9518d87faa9d` |
| Linux / mirai | 257.91 | `fapi-dpop-full-20261116-204730-2fcc9fc37f06` |
| Windows / sync smoke | 69.42 | `smoke-20261116-214555-4aa673db6b95` |

The selections ran concurrently. Timings exclude installation, suite startup,
the app-stop control and final teardown; they are local measurements, not
hosted CI timings. Reports identify product fix `29724328` and the dirty
checkout containing this harness slice. All images came from the verified
cache at the unchanged locked digests. Test libraries stay private, and no
owned Docker containers remain after cleanup. Earlier failed reports remain
failed and receive no validation credit.

C10, OAuth-only slice (2026-11-16): `fapi-oauth-dpop` freezes the separately
resolved `plain_oauth` variant: eleven modules using ES256 private-key JWT,
DPoP, unsigned PAR and plain query responses. Six flows exercise resource use;
the remaining modules reject discovery issuer mismatch and four malformed
issuer/state callbacks. The twelve ID-token-specific modules are inapplicable.

The first setup attempt exposed a missing package feature: the suite publishes
RFC 8414 metadata for OAuth-only clients. Commit `8a8882cf` adds the public
`oauth_provider_oauth_discover()` helper. It inserts the well-known component
before the issuer path, removes terminal slashes for the metadata request and
retains the exact issuer for comparison and subsequent requests. It shares the
existing transport, endpoint, host, auth, PAR, DPoP and mTLS metadata checks.
OAuth-only mode adds no `openid` scope and enables no OIDC nonce, ID-token or
UserInfo processing. The OIDC helper retains its existing defaults and rules.
All 773 discovery assertions pass with zero test failures, warnings or skips,
including OIDC, FAPI, SMART and runtime-JWKS regressions. NEWS and generated
reference documentation describe the API and its unsigned-JSON/code-flow scope.

The fixture requests only `accounts`. Positive evidence uses an `authorized`
outcome: actual access token, no ID token in the suite response or app, zero
UserInfo traffic and a successful public connection request. The module's
`authenticated` signal indicates accepted credentials here and earns no OIDC
identity credit. Independent comparisons check PAR scope and absent OIDC nonce,
PKCE, assertions, DPoP proofs/retries and resource completion. Mirai must perform
the code exchange in a verified worker; resource requests stay in the Shiny
process. Pre-token rejection stages retain their existing strict checks.

The first complete OAuth-only run exposed a separate interoperability advisory.
The happy-path, happy-path-no-dpop-nonce and happy-path-no-mtls-endpoint-aliases
modules report `WARNING` from the pinned `CheckStateLength` condition because
the encrypted state exceeds 128 characters. Their exchanges succeed; eight
other modules report `PASSED`. The original run's gate failed and receives no
validation credit. The current explicit policy accepts only this fixed warning
in these three modules, with measured state length above 128 and no other
warning/failure/review events. Verdicts remain unchanged. All eleven modules
remain mandatory, and coverage stays false even if the manifest is incorrectly
marked complete. This records the finding without weakening state protection
or claiming warning-free OAuth-only conformance.

Final validation ran all eleven modules in sync and mirai on Windows (R 4.5.1,
Chrome 157) and Linux (R 4.5.0, Chromium 156). Each command exited zero with
eight `PASSED` verdicts and the three verified `WARNING` verdicts above. All
four selection gates and cleanup checks pass; all four coverage flags remain
false. Independent report revalidation confirmed 32 passes and 12 exact
state-length advisories, with measured state lengths of 831-832 characters.
The suite source and assertions remain unchanged.

All 1,045 evidence assertions pass with zero test failures, warnings or skips.
They reject missing modules, substituted OIDC identity evidence, unexpected
UserInfo or ID-token traffic, wrong scopes/nonces and missing or altered
advisory evidence. They also keep coverage incomplete if the manifest's complete
flag is incorrectly enabled. The existing three-module OIDC FAPI selection
passed in Windows mirai, validating the shared discovery path and token/resource
behavior. R lint, formatting, actionlint and patch whitespace checks pass.

Sanitized reports under `integration/openid/.artifacts/`:

| Environment / transport | Module-loop seconds | Report directory (`evidence.json`) |
| --- | ---: | --- |
| Windows / sync | 153.62 | `fapi-oauth-dpop-20261116-222647-30190e0df1c5` |
| Windows / mirai | 168.30 | `fapi-oauth-dpop-20261116-222647-7e3c3bf5f9b8` |
| Linux / sync | 82.82 | `fapi-oauth-dpop-20261116-212648-b9d544031022` |
| Linux / mirai | 95.30 | `fapi-oauth-dpop-20261116-212648-af684d5efe57` |
| Windows / mirai OIDC regression | 43.72 | `fapi-dpop-20261116-221710-d5578745eb01` |

The final OAuth-only selections ran concurrently. Timings exclude package and
suite setup, the app-stop control and final teardown. Reports identify product
commit `8a8882cf` and the dirty checkout containing this harness slice. Images
came from the verified cache at unchanged locked digests. Libraries and raw
diagnostics stay private; no owned Docker containers remain. Earlier setup and
strict-warning failures retain failed reports and receive no validation credit.

C10 follow-up, `feat(oauth): support compact state references`: implement an
opaque state reference of at most 128 characters while retaining an encrypted
pending-login record. Preserve client/provider/policy, redirect, scope, PKCE,
DPoP-key, browser and freshness bindings. Use the state store's atomic single-use
consumption; keep unknown, tampered, expired, wrong-client and replayed references
closed. Validate shared-store and async behavior alongside the existing encrypted
format. Then rerun all eleven OAuth-only modules and require `PASSED` for the
three advisory cases before removing this coverage limit. Further refresh
scenarios remain separate provider interoperability work. C11-C12 retain mTLS
and message signing. The C09 public-client and C06 warm-cache gaps remain open.
Fresh hosted CI still needs an available verified copy of the locked server
image, and C15 retains callback error-page query cleanup.

Add the OpenID Foundation (OIDF) Relying Party tests first. Once that gate works,
extend it to FAPI 2.0, then add `oidc-provider` for interoperability with a second
full provider. Add another mock server only when a remaining test case justifies
its maintenance cost. The ranking below reflects the gaps in this repository;
it is an engineering assessment, not a benchmark of the tools.

**Starting point.** Keep the existing test layers and their stated limits.

| Existing layer | What it contributes | Limit relevant to this work |
| --- | --- | --- |
| [`tests/testthat/`](../tests/testthat/) and the browser runner | Local validation, parsers, state, callbacks, browser binding and regression tests | Package-owned fixtures share assumptions with the implementation. |
| [Keycloak](../integration/keycloak/README.md) | Full provider and browser interoperability, including attack cases | Its documented rejection canaries and accepted invalid JAR claims leave gaps in successful advanced combinations. |
| [Independent Python fixture](../integration/conformance/README.md) | Cross-language signatures and strict selected protocol exchanges | The live AS fixture omits discovery, login, consent, ID tokens and resource endpoints. |
| [Retained connections](../integration/connections/README.md) | Cross-session state, multiple providers, refresh, resource isolation and actual browsers/workers | Synthetic providers establish local behavior, not external conformance. |
| [Inferno](../integration/smart/inferno.md) | Independent SMART client-request verification | The local simulator has documented corrections; its verdict is specific to SMART and that deployment. |
| [`check_oauth21()`](../R/check_oauth21.R) | Versioned configuration assessment against OAuth 2.1 draft 16 | It does not test the running provider or establish protocol conformance. |

The existing integration workflow already installs this checkout for child apps
and mirai workers. Follow that pattern. `integration/` and `.github/` already
stay outside the source package through `.Rbuildignore`; external test tools
must remain development dependencies.

**Tool choice after the initial OIDC gate.** Consider new independent checks,
coverage of supported features, automation effort and duplication of existing
tests. Feature support in a tool's documentation is a candidate for testing;
only an actual successful exchange establishes interoperability.

| Order | Tool or extension | Decision and expected additional value |
| --- | --- | --- |
| 1 | OIDF FAPI 2.0 Security Profile and Message Signing client plans | Highest immediate return after OIDC: reuse the suite, browser driver and evidence handling for independent PAR, sender-constrained token, issuer and JARM checks. Implement C10-C12. |
| 2 | [`oidc-provider`](https://github.com/panva/node-oidc-provider/blob/367cb33b5c2d5efdec538389cbbddd944b330980/README.md) | Highest-value additional tool. It documents JAR, PAR, JARM, DPoP and mTLS, uses a different provider implementation from Keycloak, and can supply successful full flows where the current fixture has rejection canaries. Implement C13-C14. |
| 3 | Targeted adverse-response tests, with [AXA `oauth2-mock-server`](https://github.com/axa-group/oauth2-mock-server/tree/f86f0284292f3dab6adc1e209eafecc50e9fec99) as a conditional dependency | Its per-request hooks can change discovery, token claims and responses. First reuse existing Python/webfakes fixtures; add AXA only if it simplifies specific uncovered scenarios. Make that decision in C15. |
| 4 | [NAV `mock-oauth2-server`](https://github.com/navikt/mock-oauth2-server/tree/71dcbb1423e576fefce23020a21b2867310f87c2) | Useful scripted tokens and multiple issuers, but those overlap with current fixtures. Do not add both mock servers. Prefer AXA for a small Node-based mutation fixture if C15 needs one. |
| 5 | [ZAP](https://www.zaproxy.org/docs/docker/baseline-scan/) | Optional deployment/browser-response check. A baseline scan spiders and performs passive checks; it cannot establish OAuth client protocol compliance. Consider only for deployment checks that remain uncovered. |
| 6 | [PrOfESSOS](https://github.com/RUB-NDS/PrOfESSOS/tree/4e89b3f1f63ad71d771f2191f6dd46a8620a0fb8) | Useful malicious/honest-IdP attack model, but low expected return as a new CI dependency. Its default branch last changed on 2021-05-27, and its build pins Selenium 3.141.59. Borrow attack scenarios first; keep any build experiment separate from the required path. |
| Exclude | [OAuch](https://oauch.io/Tests), provider debuggers and OAuth playground clients | These primarily exercise authorization servers or help debug requests. They do not execute shinyOAuth as the client under test. |

Research snapshots: `oidc-provider` published
[`v9.14.0`](https://github.com/panva/node-oidc-provider/releases/tag/v9.14.0)
on 2026-11-11; AXA published
[`v9.3.0`](https://github.com/axa-group/oauth2-mock-server/releases/tag/v9.3.0)
on 2026-10-14; NAV published
[`6.1.5`](https://github.com/navikt/mock-oauth2-server/releases/tag/6.1.5)
on 2026-11-09. These are research observations, not installed or validated pins.
PrOfESSOS's build evidence comes from its
[`pom.xml`](https://github.com/RUB-NDS/PrOfESSOS/blob/4e89b3f1f63ad71d771f2191f6dd46a8620a0fb8/pom.xml).

**OIDF scope and implementation choices.** The suite acts as the provider while
the real Shiny app acts as the relying party. Use static registration initially;
the [RP testing guide](https://openid.net/certification/connect_rp_testing/)
supports it. Start with authorization code, `client_secret_basic`, RS256, PKCE
S256 and nonce validation. `plain_http_request` in the suite's request-type
selector means an ordinary authorization request; use HTTPS for transport.

Inspect and initially target OIDF source commit
[`410812ef6bc72a84723c1685725edce3558e31e3`](https://gitlab.com/openid/conformance-suite/-/tree/410812ef6bc72a84723c1685725edce3558e31e3),
dated 2026-11-10. Freeze the actual image/build correspondence in C01. A hosted
deployment can run a different release; record its reported version separately.

| Profile key in our runner | Upstream plan ID | Initial scope |
| --- | --- | --- |
| `basic` | `oidcc-client-basic-certification-test-plan` | Full Basic RP plan; its source fixes authentication to `client_secret_basic`. |
| `config` | `oidcc-client-config-certification-test-plan` | Discovery, JWKS and both signing-key rotation modules. |
| `form-post` | `oidcc-client-formpost-basic-certification-test-plan` | Basic RP with real POST callbacks. |
| `refresh` | `oidcc-client-refreshtoken-test-plan` | Refresh plus invalid refreshed issuer/subject cases; outside certification. |
| `extended` | `oidcc-client-test-plan` | Explicit applicable module/variant selection for public clients, other authentication methods and optional supported features. |
| `fapi-dpop`, `fapi-mtls` | `fapi2-security-profile-final-client-test-plan` | Generic `plain_fapi` authorization-code profiles, with selected client authentication and sender constraint. |
| `fapi-signing` | `fapi2-message-signing-final-client-test-plan` | Selected JAR/JARM variants after the Security Profile gates work. |

The pinned [OIDC client plan sources](https://gitlab.com/openid/conformance-suite/-/tree/410812ef6bc72a84723c1685725edce3558e31e3/src/main/java/net/openid/conformance/openid/client)
and [FAPI client plan sources](https://gitlab.com/openid/conformance-suite/-/tree/410812ef6bc72a84723c1685725edce3558e31e3/src/main/java/net/openid/conformance/fapi2spfinal)
define the exact module lists and variants. Freeze the resolved combinations;
do not assume every combination of selector values is valid. Implicit/hybrid,
WebFinger, dynamic registration and provider logout protocols stay outside the
initial claim. Local app logout and revocation do not establish OIDC logout
protocol support. Keep national FAPI ecosystems and unrelated grants separate.

Use an R driver with the existing `httr2`, `jsonlite`, `processx`, `callr` and
`chromote` dependencies. Implement the necessary suite API operations in test
helpers, using the pinned
[`conformance.py`](https://gitlab.com/openid/conformance-suite/-/blob/410812ef6bc72a84723c1685725edce3558e31e3/scripts/conformance.py)
as protocol documentation. This avoids adding another orchestration runtime.
Derive request/response contracts from the pinned server, including plan
creation, runner creation, exported values and results. Preserve server result
fields without guessing their meaning.

The upstream
[`run-test-plan.py`](https://gitlab.com/openid/conformance-suite/-/blob/410812ef6bc72a84723c1685725edce3558e31e3/scripts/run-test-plan.py)
contains client-specific launch code, excludes both key-rotation modules by
default, and disables Node TLS verification in its sample-client path. Our
driver must explicitly cover rotation and maintain certificate verification.
Use a local CA trusted by the browser, R and actual async workers. The suite
offers [prebuilt Compose services](https://gitlab.com/openid/conformance-suite/-/blob/410812ef6bc72a84723c1685725edce3558e31e3/docker-compose-prebuilt.yml);
pin image digests or build the exact pinned source, including its dependencies.

**Execution contract.** C00 is this planning change. C01-C09 establish the first
milestone: a reproducible OIDC client gate. C10-C12 extend the same infrastructure
to FAPI. C13-C16 add provider diversity and close the remaining documented gaps.
All future entries start pending; record actual commit hashes and evidence as
work finishes. Suggested subjects below describe separate commits, not changes
to make in this planning task.

Keep commits reviewable and green for their declared scope. If an external test
finds a product defect, insert a separate `fix(oidc): ...` or `fix(oauth): ...`
commit with the smallest independent reproduction, then rerun the affected
external case and neighboring positive flow. Do not hide a failure by reducing
validation or relabeling a mandatory requirement. A suite defect needs its own
reproduction, exact specification reference and tracked coverage limitation.

**C01: `test(oidc): pin conformance services and add preflight`.** Add
`integration/openid/README.md`, `scope.md`, `compose.yml`, `suite-lock.json`,
`run-preflight.R` and lifecycle helpers. Map supported features to requirements
and existing/external evidence in `scope.md`. Extend `.gitignore` for generated keys,
suite data and `.artifacts/`. Map the source SHA to concrete OCI digests or an
exact source build; pin Compose dependencies and record the build provenance.
Use unique project names, bounded readiness checks and cleanup of owned
processes/volumes. Document and automate API access for the suite's local
development profile; keep hosted API-token setup separate. Check the suite API
and verify the required plan IDs exist.

Acceptance: preflight starts and stops the local stack, rejects unavailable
services and mismatched versions, and proves verified TLS access from R and
Chrome. Run it twice to detect leftover ports or stale state. Missing tools
produce a failing preflight with an actionable message. Linux CI is the primary
execution target; document the Windows/Docker path after actually exercising it.

**C02: `test(oidc): add a configurable Shiny relying party fixture`.** Add
`fixture-app.R` and app-launch helpers using `oauth_provider_oidc_discover()`,
`oauth_ui()` or `oauth_form_post_ui()`, and `oauth_module_server()`. Restrict
configuration inputs to the test process. Keep issuer and mode fixed for each
run; no public endpoint may change the app's provider. Publish only sanitized
authentication state, structured error codes, operation counters and a test
run identifier through the test page. Tokens stay in the R process.

Acceptance: the fixture starts with the installed checkout, reports ready in
Chrome, builds the normal login request and reports setup failures clearly.
Use a package-owned provider for fixture plumbing checks if needed; label those
checks as local. Confirm that neither its DOM nor logs expose credentials or
raw callbacks. Cross-provider login acceptance arrives in C04.

**C03: `test(oidc): add suite API and result validation`.** Add
`helper-suite.R`, `helper-evidence.R`, `test-evidence.R`, `profiles.json` and
`run-tests.R`.
Implement plan/module creation, exported-value retrieval, bounded state waits,
result collection and owned-run cleanup. Use the generated module list plus a
checked-in scope manifest to detect unexpected upstream changes. Keep module
identity, variants and attempt IDs together. Handle authorization failure,
unknown IDs, server restarts and unfinished modules as explicit failures.

Acceptance: focused tests prove that absent, duplicated, unrelated, stale,
unfinished and failed results cannot pass. They also reject an empty run,
missing app evidence, unexpected exceptions and a complete-looking subset.
Exercise the API against the pinned local suite. Result validation must work
before adding a passing CI label.

**C04: `test(oidc): drive real browser conformance smoke flows`.** Add browser
helpers and a checked-in `smoke` selection containing a valid code flow, invalid
issuer and invalid nonce. Start each module before discovery, read its exported
issuer, launch the configured app and drive login in a real browser context.
Follow the module's prescribed action sequence; do not replay intercepted
callbacks directly into R as a replacement for browser navigation. Add an
isolated `workflow_dispatch` job in `.github/workflows/openid-conformance.yml`.

Acceptance: positive login reaches validated identity/UserInfo; each negative
case reaches the intended response and yields the expected rejection category.
A suite timeout without matching app evidence fails. Stopping the app mid-flow
must fail the driver. Run two complete smoke passes and retain sanitized reports.
The CI job uploads only the report artifacts, not raw suite exports.
Local pull-request runs need no external account credentials and must work on
forks. Hosted access tokens belong only to explicitly selected hosted runs.

**C05: `test(oidc): cover the Basic RP profile`.** Resolve every Basic module
and required action into `profiles.json`/the scope manifest. Handle missing
`kid`, required claims, RS256, unsigned tokens, UserInfo subject mismatch and
scope-specific UserInfo requests as the upstream plan requires. Preserve PKCE
S256 and nonce checking. Include the Basic module that requires HTTP Basic
client authentication; other authentication methods get separate variants.

Acceptance: every resolved Basic module has a recorded suite verdict and the
app evidence required for that module. Document legitimate optional outcomes
individually. Run the complete profile without unexplained omissions. Enable
the stable smoke selection on pull requests; measure full-profile runtime before
choosing its pull-request placement.

**C06: `test(oidc): cover discovery and signing key rotation`.** Implement the
Configuration plan's discovery-only actions and repeated-login actions. Keep
the same running R process and key cache across the rotation test's successive
logins; explicitly schedule both rotation modules ignored by the upstream
runner. Preserve the exact discovered issuer and normal JWKS selection rules.

Acceptance: reject the discovery issuer mismatch; complete the prescribed key
fetches and repeated authentication with the rotated key. Reports distinguish
discovery-only success from authentication success. A new app/cache for every
login cannot satisfy the rotation scenario. If a pinned suite issue prevents
completion, record incomplete coverage and keep the milestone claim partial.

**C07: `test(oidc): cover form post callbacks in Chrome`.** Implement the Form
Post Basic plan with the actual bridge page and the normal callback handling.
Treat response `form_post` independently from the outgoing authorization
request's GET/POST method. Use the suite's origin for provider navigation and
the configured HTTPS app origin for callbacks; record the real origins and
whether the browser regarded them as cross-site.

Acceptance: the resolved profile completes in Chrome, including rejection
cases, and callback cleanup/binding stays enabled. Record the deployment's
cookie/site limits; existing cross-site attack tests continue to supply their
separate evidence. A direct HTTP POST from the runner cannot replace the browser.

**C08: `test(oidc): cover refresh token identity continuity`.** Add a fixture
action that explicitly refreshes through the package's public API and consumes
the resulting validated identity/token where the upstream scenario permits.
Drive all refresh-plan modules, including changed issuer and subject. Do not
refresh a fresh app with a manually injected token; retain the original grant
and validated subject across the scenario.

Acceptance: normal refresh succeeds and identity substitutions fail. Observe
the package's declared failure/credential-retirement policy and ensure no
rejected replacement becomes usable. Keep token rotation, concurrency and
retained-connection tests in their existing layers.

**C09: `test(oidc): exercise async transport and client auth variants`.** Run
the core profiles with synchronous transport and actual mirai workers; add a
small future-worker parity selection following the package's existing support.
Verify the installed package revision and TLS trust in child processes. Add
applicable comprehensive-plan selections for public S256 clients,
`client_secret_post`, `client_secret_jwt` and `private_key_jwt`, using metadata
and signing algorithms supported by the pinned suite. Do not pretend the fixed
Basic profile covers those methods.

Acceptance: each declared auth variant completes a positive flow and a relevant
negative case. Core sync/mirai results match their expected application policy.
Neither worker reuse nor the harness leaks issuer-specific configuration or
credentials into another scenario. Record unsupported suite variants as gaps,
with any existing interoperability evidence linked separately.

**C10: `test(fapi): add private key JWT and DPoP client conformance`.** Reuse
the OIDF driver for the generic FAPI 2.0 Security Profile with
`private_key_jwt`, DPoP, PAR and S256. Configure exactly the selected profile's
metadata, algorithms, assertion audience and lifetimes after reviewing the
[client requirements](https://openid.net/specs/fapi-security-profile-2_0-final.html#section-5.3.3).
Use the exported resource endpoint through normal package request APIs; a
validated ID token alone does not establish protected-resource behavior.

Acceptance: complete the resolved applicable module/variant set, including
resource proof use, nonce behavior and issuer/state rejection cases. Record
OIDC-enabled and OAuth-only variants separately when supported by the suite and
package. Keep any missing profile requirements visible; individual feature
support does not establish full FAPI conformance.

**C11: `test(fapi): cover mTLS client authentication and token binding`.** Add
temporary certificate registrations and the selected FAPI mTLS variants. Cover
`private_key_jwt` plus mTLS sender constraint first, then mTLS client
authentication plus mTLS sender constraint if supported. Keep the registration
and resource access bound to the actual TLS peer certificate. Do not infer that
binding from a forwarded header or a decoded token claim alone.

Acceptance: complete required code/resource exchanges, endpoint aliases and
the suite's applicable fallback cases using verified TLS. A mismatched
certificate cannot use a bound token where tested. Keep auth method and token
binding as separate report dimensions. Run the selected variants in sync and
mirai transport.

**C12: `test(fapi): cover message signing client profiles`.** Add supported
Message Signing variants for JAR and JARM, starting with signed requests through
PAR and signed query responses. Select legal combinations from the pinned plan;
do not generate an unverified Cartesian product. Add alternate callback modes
or encryption only where both implementations and the selected profile support
them. Retain upstream assertions unchanged.

Acceptance: successful signed exchanges and the plan's applicable invalid JARM
signature/issuer/audience/expiry cases pass their expected verdicts. Verify
authenticated resource use, not just a redirect. Compare any new findings with
the independent Python tests. A fixture patch requires explicit provenance and
a narrower claim, following the existing Inferno precedent.

**C13: `test(interop): add a pinned oidc-provider environment`.** Create
`integration/oidc-provider/` with a lockfile, runtime/container pin, temporary
keys, provider configuration and a small deterministic login/consent fixture.
Start with the researched release `9.14.0` or document why implementation selects
another supported release. Use the provider's normal protocol handlers and
enable required features explicitly. Reuse browser/evidence helpers when the
interfaces match; avoid a large common-framework refactor.

Acceptance: the unmodified provider completes the code flow with S256, a
validated ID token, UserInfo and refresh for public and confidential
registrations. Both query and form POST callbacks work in Chrome with
sync/mirai transport. Record provider
events and selected discovery capabilities. A provider setup failure fails
preflight rather than becoming an unsupported-client result.

**C14: `test(interop): cover advanced flows against oidc-provider`.** Prioritize
the existing Keycloak gaps: successful JAR + DPoP, JAR + mTLS, and JAR + JARM;
include PAR and direct forms only where the provider actually supports them.
Add signed UserInfo, token revocation/introspection and RFC 8707 resource
indicators where they close a recorded gap. Verify a real resource request with
the issued credential. Add a small retained-connection scenario using
`oauth_connections_server()` for lifecycle behavior across navigation.

Acceptance: each combination advertised as supported finishes its positive
exchange and a relevant rejection case. Document unsupported combinations
without treating their rejection as successful interoperability. Keep provider
configuration and version in the evidence so upgrades can explain changes.
The existing independent fixture remains the separate strict protocol oracle.

**C15: `test(security): close remaining protocol rejection gaps`.** Review the
completed coverage map before adding a dependency. Prioritize untested trust
boundaries: two-issuer mix-up, metadata/JWKS rotation failures, signed response
substitution, refresh identity changes and invalid-response handling across
browser/worker boundaries. Reuse existing tests when they already establish the
same property. For each new scenario define a valid control and the single
changed property, then require a specific app outcome.

Acceptance: add only scenarios with a named requirement or documented package
policy and a remaining coverage gap. Use existing Python/webfakes fixtures
where practical. If per-request signed-response mutation needs a new server,
add AXA in a separate `test(security): add scripted OAuth response mutations`
commit with exact Node/package pins and one justified scenario first. Record a
decision to defer AXA if no such scenario remains. Do not add NAV as well.

**C16: `ci: publish scoped protocol quality evidence`.** Finalize CI tiers,
release evidence and developer instructions using measured runtime. Keep the
OIDF and second-provider jobs separate from the existing 60-minute integration
job. Required pull-request checks use stable selected scenarios; scheduled and
release runs execute the declared larger matrix. An absent required dependency
or unavailable local service fails the selected job. Hosted comparison runs
remain optional and use separate credentials and reported version metadata.

Acceptance: demonstrate that an intentional invalid report fails CI and that
the declared matrix produces complete scoped evidence. Publish a table of
tested profiles, versions, omissions and fixture modifications. Add precise
developer documentation and a NEWS entry; claim OpenID certification only after
the Foundation's separate submission process. Update this plan with commit
hashes, actual commands and remaining gaps.

**Result rules to implement in C03 and extend with each profile.** A passing
gate requires the expected module/variant set and the expected app outcomes.
Keep lifecycle status separate from a suite verdict: `FINISHED` alone proves
neither correctness nor successful authentication. Expected rejection counts as
a successful test only after the fixture proves the intended response reached
the appropriate validation boundary and the client produced the expected
rejection category. No callback, an unavailable server or a dead worker fails.

Some upstream cases allow `SKIPPED`, `REVIEW` or `WARNING`; some signature tests
permit code-flow behavior weaker than shinyOAuth's signature policy. The
pinned [invalid-ID-token base class](https://gitlab.com/openid/conformance-suite/-/blob/410812ef6bc72a84723c1685725edce3558e31e3/src/main/java/net/openid/conformance/openid/client/AbstractOIDCCClientTestExpectingNothingInvalidIdToken.java)
shows the timeout-based observation and signature exception. Record the raw
verdict and an independently checked app outcome. Require an exact
module/variant-specific explanation and evidence for every allowed exception;
never add a wildcard acceptance rule. An inapplicable optional feature does not
erase a required-profile failure. Keep our CI acceptance policy separate from
the Foundation's certification criteria.

Default to fresh registrations, app/browser contexts and run IDs between
independent modules. Multi-step rotation/refresh tests deliberately preserve
the app, relevant cache and original transaction or grant. Respect that state
in the scenario manifest. Never cache a successful verdict across suite or
package revisions, and never keep retrying a protocol failure until it passes.
An infrastructure retry starts a new recorded attempt without discarding the
failed attempt.

The sanitized JSON report should contain `schema_version`, run/attempt IDs,
checkout SHA and dirty flag, installed package identity, suite source/image
identity, R/browser/dependency versions, selected profile and variants,
expected/observed modules, raw suite statuses/verdicts, app outcome categories,
operation evidence, exceptions, `coverage_complete` and `gate_passed`. Keep
configuration-checker findings as their own evidence category. Write a partial
failing report when execution stops early. Never merge results from different
commits into a complete release claim.

Use synthetic accounts and ephemeral credentials. OIDF raw exports, browser
traces and callback screenshots can contain secrets; retain them locally only
as needed for diagnosis and never upload them by a broad artifact glob.
Generate an allowlisted report for CI. If formal certification needs raw logs,
prepare that bundle separately with the required access and provenance.

**Planned command interface.** These commands describe the future runners;
they do not exist yet. Each implementing commit must add the corresponding
usage documentation and validate unknown flags instead of silently falling
back to a smaller test set.

```sh
R CMD INSTALL .
Rscript integration/openid/run-preflight.R
Rscript integration/openid/run-tests.R --profile smoke --transport sync
Rscript integration/openid/run-tests.R --profile core --transport sync
Rscript integration/openid/run-tests.R --profile core --transport mirai
Rscript integration/openid/run-tests.R --profile extended --transport sync
Rscript integration/openid/run-tests.R --profile extended --transport mirai
Rscript integration/openid/run-tests.R --profile smoke --transport future
Rscript integration/openid/run-tests.R --profile fapi-dpop --transport sync
Rscript integration/openid/run-tests.R --profile fapi-dpop --transport mirai
Rscript integration/openid/run-tests.R --profile fapi-mtls --transport sync
Rscript integration/openid/run-tests.R --profile fapi-mtls --transport mirai
Rscript integration/openid/run-tests.R --profile fapi-signing --transport sync
Rscript integration/openid/run-tests.R --profile fapi-signing --transport mirai
Rscript integration/oidc-provider/run-tests.R --profile core --transport sync
Rscript integration/oidc-provider/run-tests.R --profile core --transport mirai
Rscript integration/oidc-provider/run-tests.R --profile advanced --transport sync
Rscript integration/oidc-provider/run-tests.R --profile advanced --transport mirai
```

`core` expands to Basic, Configuration, Form Post Basic and refresh; report
the resolved selections. `smoke` always reports partial coverage. Runtime
measurements decide placement, not which required results count as passed.

**Scope and maintenance.** Map baseline checks to OIDC Core/Discovery, OAuth
2.0, bearer transport, PKCE and issuer identification, together with
[RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html) and
[RFC 8725](https://www.rfc-editor.org/rfc/rfc8725.html). Add RFC 7009, 7662, 8705,
8707, 9101, 9126, 9449 and JARM where the enabled operation uses them. Keep the
existing OAuth 2.1 assessment pinned to its declared draft; assess future draft
changes in a separate change. Preserve the distinction between client duties,
server duties, deployment duties and stricter package policy.

Use dedicated dependency-update changes for suite images, provider releases or
test libraries. Re-resolve module lists and compare changed expectations before
updating pins. Existing Keycloak, SMART, independent cryptographic and browser
attack gates continue to carry their own evidence; passing OIDF profiles does
not establish every deployment property or supported extension.

Testing with OIDF is free according to its
[suite overview](https://openid.net/certification/about-conformance-suite/).
Formal certification remains a later optional milestone, with possible
[open-source fee waiver eligibility](https://openid.net/certification/open-source-project-certification-policy/).
No account creation, certification submission or deployment is required to
complete the local implementation path above.
