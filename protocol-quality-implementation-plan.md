# NA

**shinyOAuth protocol quality: implementation plan**

**Steering-agent review and handoff (2026-11-18).** Author: the separate
Codex steering/review agent, at the user’s request. Reviewed clean
checkout `43dd6d80488bae74010e3759017034af068fdce6`, the implementation,
retained reports, pinned upstream plan sources and current OIDF
instructions. The user asked this agent to evaluate the implementation
agent’s work and add these notes so the implementation agent can pick
them up. This section preserves the execution history below; it records
recommendations and review evidence, not completed implementation
changes.

The existing approach should continue: real browser flows through public
package APIs, exact suite module/variant matching, specific application
rejection evidence, verified worker execution and explicit fixture
limitations. Keep the separate suite verdict and application checks.
During this review, all 6,682 evidence regression assertions passed with
no test failures, warnings or skips; R startup emitted the already
documented locale warnings. The steering agent did not run a new
browser/Docker conformance matrix or contact the implementation agent.
The checks described under SA01 and SA02 were read-only.

**Recommended execution order.** Finish recording any validation already
in flight, then prioritize SA01-SA02 before expanding the feature
matrix. Reconcile the requirement map and milestone status through
SA04-SA06; use that map to select the remaining C15 work in SA07. SA08
defines the final release-evidence gate. SA03 is a separate conditional
certification milestone, because the existing local implementation scope
does not authorize account creation, publication or certification
submission. Record the disposition of each note with implementation
commits and evidence, or a concrete reason for deferral. All eight notes
start pending.

**Implementation status (2026-11-19).** SA02’s image, acquisition and
dirty-flag revalidation checks are implemented in the follow-up
execution record below. SA02 now implements source snapshots, archived
installation input and a clean release-source check; local and hosted
acceptance is complete. SA01 now pins the available official
`release-v5.3.4` server and proxy images after source/digest and live
plan comparison. SA01 is complete: fresh hosted smoke, Basic and Message
Signing passed with verified acquisition reports and recorded timings.
SA04 is partial: the [requirement
maps](https://lukakoning.github.io/integration/openid/requirements.md)
account for FAPI’s 20 client clauses, relevant network/cryptography
duties, OIDC code/discovery, OAuth code/refresh/metadata, PAR/JWT client
authentication and JWT/Message Signing. Direct
mTLS/DPoP/resource-indicator client clauses now have a companion map.
G1-G4 now have their recorded regressions; G3 adds a named Message
Signing configuration assessment, while G2 retains its observed
purpose-policy limits. The partial RFC 9700 map adds redirect/replay and
selected attack protections; remaining inherited-security and aggregate
coverage work stays open. SA06’s Keycloak follow-up now proves no-cache
revalidation and rotation; C06 warm-cache acceptance remains open. SA05
now separates upstream execution from local coverage and categorized
limits, with regression and retained-report validation. SA06’s milestone
status now distinguishes completed public/S256 interoperability from the
OIDF public variant limit; C06 warm-cache acceptance remains open. SA03
and SA07-SA08 remain pending. See the [release
review](https://lukakoning.github.io/integration/openid/release-review.md).

| Milestone | Current implemented scope | Remaining boundary |
|----|----|----|
| C01-C05, C07-C08 | Environment/API/browser rig, all Basic/Form Post modules and refresh identity continuity | Exact variants and same-site Form Post deployment limits remain recorded. |
| C06 | All six Configuration modules and separate Keycloak revalidation/rotation | Neither provider fixture proves rotation from a warm key cache. |
| C09 | Sync/mirai core profiles, future smoke/refresh parity, confidential authentication pairs and shared-pool isolation; C13 supplies public/S256 interoperability | The pinned OIDF public variant cannot complete because its metadata omits `none`; no public-client OIDF verdict is claimed. |
| C10 | All 23 OIDC DPoP modules and all 11 OAuth DPoP modules with encrypted/reference state | The encrypted-state advisory and FAPI configuration/requirement limits remain distinct from module execution. |
| C11-C12 | Four full mTLS selections and the 29-module Message Signing selection | mTLS simulated-server enforcement/registration limits and exact signing/callback configurations remain explicit. |
| C13-C14 | Pinned second-provider public/confidential code/refresh/browser flows and the declared advanced-flow/lifecycle selections | These are interoperability evidence, not additional OIDF certification profiles. |
| C15 | Existing rejection/browser controls plus requirement-selected follow-ups | Callback-error URL cleanup, HTTPS cross-site acceptance and named cryptographic regressions remain. |
| C16 / SA08 | CI smoke, manual larger selections, acquisition/source checks | One final revision’s declared aggregate matrix and durable release evidence remain. |

Use the implemented commands in the [environment
README](https://lukakoning.github.io/integration/openid/README.md).
`core`, `extended` and `fapi-signing` below are historical planning
aliases, not accepted current CLI profile names.

**SA01 (high): Restore fresh-machine reproducibility; move this part of
C16 forward.** The review independently obtained an anonymous registry
token and checked the locked server-image manifest. The token endpoint
returned HTTP 200; the manifest for
`sha256:a84e164e59bba31bbca83732a8506f522a746660864da7221428bab4e3157225`
returned HTTP 404. Existing cached-image runs retain their evidence, but
the documented path cannot currently reproduce them on a fresh CI
runner.

Follow-up availability check (2026-11-18): the official registry lists
published release images. Manifest GET requests for `release-v5.3.4`,
`release-v5.3.3`, `release-v5.3.2`, `release-v5.2.4`, `latest` and
`unstable` all returned HTTP 200. For example,
`registry.gitlab.com/openid/conformance-suite:release-v5.3.4` resolved
to multi-platform index
`sha256:dcc4bd1fb7e9c00f048a67373fe2bec5ecf9feb45a6b5d55e237e5c30e5312c6`,
including Linux amd64 and arm64 images. Upstream’s [prebuilt Compose
file](https://gitlab.com/openid/conformance-suite/-/blob/master/docker-compose-prebuilt.yml)
uses this official registry and accepts `IMAGE_TAG`. The 404 concerns
our exact pinned build; other official versions are available. These
checks retrieved image metadata, without pulling or executing
replacement images. The review has not located the exact old digest
elsewhere and cannot rule out other copies.

Prioritize evaluating an available official release and a separately
reviewed lock update. A verified mirror of the exact old image or a
pinned source build remain alternatives. Retain digest/source
correspondence checks and resolve changed modules and variants
explicitly if updating the suite. Do not silently substitute a tag.
Acceptance: demonstrate image acquisition and a successful
preflight/API/browser smoke run on a fresh GitHub runner, then measure
the selected larger jobs there. See
[`openid_prepare_image()`](https://lukakoning.github.io/integration/openid/helper-environment.R)
and the registry limitation in the [environment
README](https://lukakoning.github.io/integration/openid/README.md).

**SA02 (high): Check report provenance during revalidation and identify
the tested source precisely.** In a retained passing Message Signing
report, the review changed `images.server` to `unrelated-image`, deleted
`image_sources` and changed `checkout_dirty` from false to true. Calling
`openid_check_report(changed, original, manifest)` still returned both
`gate_passed = true` and `coverage_complete = true`. The reviewed input
was
`integration/openid/.artifacts/fapi-message-signing-20261117-235701-9cb11a881c13/evidence.json`.
The live runner verifies the image at startup; this finding concerns the
later report validator’s incomplete provenance checks, not evidence that
those live runs used a different image.

Bind report image identities to the lock and expected run context,
validate the required acquisition metadata and add mutation checks for
absent or substituted provenance. Define source identity for release
evidence: require a clean checkout or record a reproducible
source-content identity tied to the installed package and fixture bytes.
A parent SHA plus a dirty flag cannot reconstruct the tested changes.
Development runs may remain dirty when labeled accordingly. Acceptance:
the reproduction above fails revalidation, genuine serialized reports
still pass, and release aggregation rejects unidentified source changes.
See [`openid_check_report()` and
`openid_report_context()`](https://lukakoning.github.io/integration/openid/helper-evidence.R).

**SA03 (conditional, high if certification is intended): Add a concrete
certification-readiness milestone after the local path.** C16 currently
leaves hosted comparison optional, and the closing scope statement
deliberately defers formal certification. Keep that boundary explicit.
If certification becomes the goal, add a separate milestone with the
selected official certification profile names, hosted execution, actual
hosted suite version and plan/module identities, per-test client
evidence, suite exports and a reviewed submission bundle. Resolve the
hosted module lists independently; never reuse pinned-local results as
hosted results or assume the hosted deployment runs the pinned revision.

OIDF’s [RP submission
instructions](https://openid.net/certification/connect_rp_submission/)
require suite logs, client evidence under `client-data` with test-name
prefixes, and a signed Certification of Conformance naming the software
version and official profile. They prescribe the suite’s “Publish for
certification” path. The [FAPI RP testing
instructions](https://openid.net/certification/fapi_rp_testing/)
explicitly exclude local-instance results from certification
submissions. The sanitized CI JSON remains useful; implement a separate
evidence-generation and review path for certification packaging. Use
ephemeral credentials and account for the publication of submitted logs.
Acceptance for readiness: a documented, reviewable bundle-generation
procedure and complete evidence mapping for every selected test. Keep
account actions, publication, attestation and submission outside the
currently authorized local work. Formal certification remains optional
until the user chooses it.

**SA04 (high): Complete the requirement-to-evidence map before expanding
C15.** The current [scope
map](https://lukakoning.github.io/integration/openid/scope.md) maps
suite modules and application outcomes well, but does not yet account
for every applicable normative client requirement behind the intended
claims. Add rows containing the specification clause, responsible role,
selected configuration, existing test/report and remaining limitation.
Distinguish client duties, AS/resource server duties, deployment duties,
optional features and stricter package policy.

For FAPI, review the [client
requirements](https://openid.net/specs/fapi-security-profile-2_0-final.html#section-5.3.3)
and applicable network/cryptography sections explicitly. Include refresh
and rotation support, assertion audience, browser-bound per-request
PKCE, authorization-initiation protection, endpoint aliases and signing
restrictions. Several already have Keycloak or unit-test evidence; link
and reuse it before adding scenarios. Keep RS256-based general
interoperability selections separate from claims about FAPI’s permitted
signing algorithms. Acceptance: every applicable requirement for each
declared claim has evidence or a named remaining gap. This matrix is an
engineering safeguard, not an extra OIDF submission rule.

**SA05 (medium): Separate plan completion from policy and fixture
limitations.** `coverage_complete` currently combines upstream-plan
completion, stricter local policy, interoperability advisories and
simulated-server limitations. Retain the raw verdicts and exact
exception allowlists, but give these judgments distinct meanings in
reports and documentation. In particular, consider an explicit
upstream-plan-completion field alongside selected-scenario completion
and additional security limitations; certification status needs its own
accounting.

The encrypted-state OAuth selection executes all eleven modules but
remains incomplete because of the 128-character advisory. FAPI Security
Profile section 5.3.2.2 note 4 anticipates encoded state exceeding 1,000
characters, and the [OIDF RP testing
guide](https://openid.net/certification/connect_rp_testing/) allows
explained WARNING, REVIEW and SKIPPED results as well as PASSED. Keep
the reference-state feature and the advisory evidence without implying
that the advisory alone establishes protocol nonconformance. Likewise,
the mTLS checker forces incomplete coverage partly because the simulated
resource server fails to deny certificate misuse; preserve that finding
while separating it from client-plan completion and client obligations.
Unsigned metadata over verified TLS is also a scope description, not
automatically a missing generic-FAPI requirement. Acceptance: explain
each flag and report complete upstream module execution independently of
additional policy or server-enforcement findings. Changes here must
preserve validation and evidence requirements.

**SA06 (medium): Reconcile milestone status with the newer evidence.**
C09 still broadly describes public-client/S256 coverage as outstanding,
although C13 now exercises public clients through discovery, browser
login, S256, UserInfo and refresh. Compare C13 with C09’s precise
positive/negative acceptance criteria, close the overlap it satisfies
and name only the remaining cases. Preserve the pinned suite’s broken
public-client variant as an upstream limitation. Update C10’s opening
status after the compact-state work, and reconcile the older scope table
with completed mTLS and Message Signing selections. Add a short current
status table at the top; retain the dated execution record as history.
Current command documentation should also distinguish implemented
profile names from earlier proposed aliases such as `core`, `extended`
and `fapi-signing`.

C06’s warm-cache gap remains real. The [existing Keycloak rotation
test](https://lukakoning.github.io/integration/keycloak/test_integration_keycloak_jwks_rotation.R)
is a candidate for closing it without adding another provider fixture.
Require observed cache population/use before rotation, retained cache
identity and refresh after rotation, with required setup failures
producing failures rather than skips. Reuse its existing rogue-signature
controls. Acceptance: link the actual cacheable-provider result and its
scope to C06; preserve the separate OIDF no-store results and their
limitation. Do not claim closure from two fresh JWKS fetches.

**SA07 (medium): Give C15 explicit browser acceptance criteria.**
Rejected HTTP callbacks currently retain callback query material in the
address bar, and `openid_http_callback_matches()` requires
`callback_cleaned = false` for those cases. Improve cleanup while
preserving rejection semantics, the specific error category and
credential-nonreflection checks. Update the evidence predicate with the
product change and verify the resulting browser URL. See the [HTTP
callback collector and
matcher](https://lukakoning.github.io/integration/openid/helper-fapi.R).

The new HTTPS Form Post environments are same-site. Existing cross-site
tests add useful evidence but include HTTP loopback development
exceptions. Add a successful HTTPS cross-site flow and its relevant
error path, or explicitly retain that deployment limitation. Reconcile
the separately deferred `oidcc-client-test-form-post-error` module with
the actual selected plan variants and existing tests. These are targeted
browser improvements, not new mandatory OIDF certification profiles. Use
SA04 to decide which other C15 cases remain; reuse existing fixtures
before adding a mock-server dependency.

**SA08 (medium): Require one identifiable final revision and durable
release evidence in C16.** Historical runs span different package
revisions, including dirty development checkouts. They document progress
but cannot collectively establish the final implementation’s full
declared matrix. Choose and publish that matrix, run it against one
identifiable final revision and check its aggregate completeness
automatically. Preserve exact variant limits and failed attempts; a
smoke selection cannot substitute for a required full plan.

The current workflows retain uploaded reports for seven days. Define
durable retention for release evidence and its source/lock identities,
while keeping private diagnostics and certification exports out of broad
artifact uploads. Use actual GitHub runner timings to choose PR,
scheduled and release tiers. Acceptance: a machine-checked aggregate
report rejects missing matrix entries, mixed or unidentified source
revisions and missing required evidence, and the declared release
reports remain available beyond ordinary CI retention. This implements
C16’s existing prohibition on merging results from different commits
into a complete release claim.

**End of steering-agent handoff.** The original plan and implementation
agent’s execution record follow unchanged. Update the status of
SA01-SA08 as work lands.

Prepared 2026-11-12 against shinyOAuth commit
`25318cc6488a2a98bfc83d484cbbdb3190854967` (version `0.7.0.9000`).
Status: implementation started. The original investigation ran no
external tests. C01 supplies a working local suite preflight, and C02
supplies a validated Shiny fixture. C03 adds the suite API driver and
evidence validator. C04 executes three real-browser smoke modules. C05
extends the runner to all fourteen Basic RP modules for the pinned
static-registration, synchronous code-flow variant. C06 now executes all
six Configuration modules, with cached-key refresh coverage still
incomplete because the pinned suite’s JWKS responses prohibit storage.
C07 covers the fourteen-module Form Post Basic plan in Chrome on the
local cross-origin, same-site deployment. C08 covers all three client
refresh modules, including identity substitution and the module’s
default credential-retirement policy. C09 adds verified mirai transport
for the core selections, future multisession smoke/refresh parity,
confidential-client authentication selections and sequential shared-pool
issuer isolation. C13 now supplies public-client discovery, S256/browser
login, ID token, UserInfo and refresh interoperability, including live
missing-PKCE rejection. That closes the overlapping public/S256 baseline
work; the pinned suite’s broken public variant remains an OIDF
capability limit. C10 includes the complete twenty-three-module
OIDC/private-key-JWT/DPoP variant and eleven-module OAuth-only
selections with both encrypted and reference state. All reference-state
outcomes are `PASSED`; encrypted state retains its exact advisory. Both
execute the full upstream module list, while the conservative coverage
field retains the advisory separately. C11’s mTLS and C12’s Message
Signing selections are implemented with the scope limits in the current
table above. C13-C14 supply the second-provider scenarios recorded
below; C15 browser/cryptographic follow-ups and C16 release aggregation
remain.

Execution record (2026-11-12): C00 is `d0b62ff`; C01 is `4dee03d`. C01
validated the exact server image/source correspondence, required plans,
R certificate/hostname validation, Chrome certificate pinning and
wrong-pin rejection, and complete owned-resource cleanup in consecutive
disposable deployments on Windows/Docker Linux containers. Its 11
environment assertions pass with no failures or skips; formatting and
lint checks pass. Startup reports the host’s existing C.UTF-8 locale
warnings. This establishes environment readiness, not RP conformance.
Chrome uses an isolated SPKI pin instead of installing a temporary root
in the system trust store; the environment README records that scope
adjustment.

C02 is `88517ea`. It installed this checkout into an isolated R library
and drove its public module/UI APIs in Chrome against a local HTTPS
metadata fixture. The code/S256, nonce/state and openid-scope checks
passed, a discovery issuer mismatch stopped startup, and the synthetic
secret stayed out of the DOM and app logs. No token was issued and no
independent client conformance verdict was collected. Follow-up
validation also requires the failed setup’s private diagnostic to
identify an issuer mismatch, so an unrelated app crash cannot satisfy
that check. The follow-up preflight and fixture checks both passed,
along with the 11 helper assertions, `jarl check integration/openid`,
`air format integration/openid --check` and patch whitespace validation.

C03 is `2b06b7a`. It passed 51 evidence assertions with no failures or
skips. Its live API check created the pinned Basic plan, checked all
module variants, retrieved a waiting module’s issuer, rejected an
unknown instance and verified interruption on cancellation. Owned Docker
resources were removed. Its sanitized report marks client conformance
unattempted and keeps the conformance gate false.

The first C04 browser run produced three passing suite verdicts, but the
local gate correctly failed because issuer/nonce errors lacked safe
claim labels. `83ec40e` adds those labels to the existing typed audit
events without exposing claim values or changing validation. Its focused
signed-token regression checks and neighboring ID-token checks passed:
162 assertions, zero failures, warnings or skips.

C04 is `d723b6b`. It adds the real Chrome driver, app-stop failure
control, callback cleanup checks and a manual Ubuntu workflow. Two
complete Windows smoke runs passed all three modules with matching app
evidence and owned-resource cleanup. The evidence validator now has 54
passing assertions. Coverage remains partial; C05 is next. Preflight,
API checks and all three smoke modules also passed as a non-root Linux
user (R 4.5.0, Chromium 156), including caller-owned TLS key generation.
The manual GitHub workflow has not run yet; its actionlint check passes,
along with R lint, formatting and patch whitespace checks.

Sanitized reports retained locally under
`integration/openid/.artifacts/`:
`smoke-20261112-225149-dbdbc91a7b81/evidence.json` and
`smoke-20261112-225410-77d6e303d949/evidence.json` (Windows), plus
`smoke-20261112-220117-83dd3e2312e6/evidence.json` (Linux). Each reports
a passing smoke gate, verified cleanup and incomplete full-profile
coverage.

`02e677e` extends safe ID-token audit classification to audience,
subject, issued-at, disallowed algorithms and invalid signatures. The
signed-token regressions and neighboring claim checks passed 263
assertions with no failures, warnings or skips. Validation behavior
remains unchanged.

C05 is `c4ae74e`. It executes all fourteen modules and requires the
corresponding app evidence. Thirteen require `FINISHED/PASSED`; only
`oidcc-client-test-idtoken-sig-none` requires `FINISHED/SKIPPED`,
matching the pinned suite’s documented optional unsigned-token support
and shinyOAuth’s `disallowed_algorithm` rejection. The gate also
requires no UserInfo completion for rejected ID tokens. For a UserInfo
subject mismatch, the typed error and suite verdict establish the
UserInfo response, while the token-exchange completion audit establishes
the preceding validated ID token. A UserInfo rejection can precede its
completion audit; an initial Linux run caught and corrected that harness
assumption.

The evidence validator passes 115 assertions, including all-module
coverage, the exact unsigned-token exception and rejection-category
checks. The complete Windows Basic run took 90.35 seconds for its module
loop, and a later smoke run took 23.31 seconds. Those timings include
per-case app/browser startup and suite waits, but exclude package
installation, suite startup, the app-stop control and stack teardown.
The Ubuntu workflow now runs smoke on relevant pull requests and offers
Basic through manual dispatch. Full Basic stays manual until GitHub
runner timings are measured; no GitHub run has executed yet.

Windows reports retained under `integration/openid/.artifacts/`:
`basic-20261112-230808-fe5a9984784b/evidence.json` (complete Basic
module coverage) and `smoke-20261112-231056-3e4d6d264675/evidence.json`
(partial coverage). Both gates pass with verified owned-resource
cleanup. C06 is next.

The corrected full Basic gate also passed as a non-root Linux user with
R 4.5.0 and Chromium 156. Its module loop took 77.75 seconds; the
retained report is
`integration/openid/.artifacts/basic-20261112-221342-9dbc14ec0352/evidence.json`.
All fourteen modules finished with their expected verdict and app
evidence, the app-stop control passed, and owned-resource cleanup
completed. R lint, formatting, actionlint and patch whitespace checks
pass.

C06 execution: `efb54a5` adds its runner coverage; `65fb2cb` adds a safe
`discovery_issuer_mismatch` audit reason and the `iss` claim label
without changing validation. Discovery and neighboring JWKS tests passed
234 assertions with no failures, warnings or skips. The runner now
resolves separate Basic/Configuration plans, verifies the exact
six-module Configuration list and schedules both upstream-ignored
rotation modules. Discovery-only results earn no login credit. A failed
discovery setup must identify the expected issuer check through typed
audit evidence.

The first live Configuration run completed all six suite modules, but
its local gate rejected the cache evidence. A separate module confirmed
that JWKS is sent with
`Cache-Control: no-cache, no-store, max-age=0, must-revalidate`.
shinyOAuth correctly leaves those keys unstored. No suite headers,
response bodies, assertions or client cache policy were changed to force
a warm cache. The recorded limitation is
`suite_jwks_no_store_prevents_cached_key_refresh_test`.

The before-signing scenario prefetches through the installed package’s
internal JWKS helper, then requires a validated token with a different
signing-key ID. The repeated-login scenario requires two validated
ID-token/UserInfo outcomes, different key IDs, a local logout between
them and the same R app/cache instances throughout. Only key-ID digests
leave the fixture. The driver waits for the next callback session, which
prevents a logged-out state from satisfying the second-login wait. The
evidence validator passes 168 assertions; focused HTTP-cache,
invalidation, signature and refresh-throttle regressions add 74 passing
assertions with no failures, warnings or skips.

Configuration gates pass on Windows (R 4.5.1, Chrome 157) and non-root
Linux (R 4.5.0, Chromium 156): five modules are `FINISHED/PASSED`, and
unsigned-token rejection is `FINISHED/SKIPPED` under its existing
optional policy. Both runs verify owned-resource cleanup. Their module
loops took 38.35 and 29.79 seconds. Sanitized reports retained under
`integration/openid/.artifacts/` are
`config-20261112-233608-c8bf6297fde2/evidence.json` (Windows) and
`config-20261112-223608-312b32a78ab4/evidence.json` (Linux). Manifest
and client-evidence schemas are now version 2. Manual workflow dispatch
offers `config`; pull requests continue to run smoke. The full Basic
profile also passed again on non-root Linux after the plan and driver
changes, with all fourteen expected module outcomes and complete Basic
coverage. Its retained schema-2 report is
`integration/openid/.artifacts/basic-20261112-223754-36fbb02417e4/evidence.json`;
the module loop took 80.85 seconds. R lint, formatting, actionlint and
patch whitespace checks pass. No owned suite containers remain after
validation.

C06 acceptance remains partial: reports keep
`selection_complete = true`, `coverage_complete = false` and
`cached_key_refresh_tested = false`, even if the manifest accidentally
requests a complete-coverage label. A follow-up must test warm-cache key
replacement against an independent cacheable provider (an applicable
Keycloak scenario or C13’s second provider), or a reviewed suite
configuration/version that permits caching. Preserve the current
no-store runs as their own evidence. C07’s form-post work can proceed
independently; the first OIDC milestone retains this C06 coverage gap
until that follow-up passes.

C07 is `20966df2`. C07 execution (2026-11-13): the pinned Form Post
Basic plan resolves to the fourteen Basic modules with its fixed
`response_mode=form_post` variant. The runner installs the normal Form
Post wrapper and records sanitized Chrome navigation evidence separately
from incoming POST metadata. Every case must show GET authorization, a
form-encoded callback POST from the expected provider Origin, the 303
bridge redirect, Secure `SameSite=Strict` binding-cookie metadata,
completed callback validation and final callback-query cleanup. No raw
request/response bodies, callback queries or cookie values are retained.

The full profile passes on Windows (R 4.5.1, Chrome 157) and non-root
Linux (R 4.5.0, Chromium 156): thirteen `FINISHED/PASSED` verdicts and
the documented unsigned-token `FINISHED/SKIPPED`, with matching app
outcomes and verified cleanup. Module loops took 103.27 and 81.54
seconds. Retained sanitized reports under
`integration/openid/.artifacts/` are
`form-post-20261113-205121-e013f0e3cb20/evidence.json` (Windows) and
`form-post-20261113-195207-4bded3721513/evidence.json` (Linux). Their
actual provider/app origins were `https://localhost:59182` /
`https://localhost:60189` and `https://localhost:59345` /
`https://localhost:41039`, respectively. Chrome observed `same-site` on
every callback, so `cross_origin = true` and `cross_site = false`. This
scope does not replace the separate cross-site attack fixtures.

The evidence validator passes 208 assertions, including rejection of
missing POST/bridge/binding observations, stale origins, wrong
transports and incorrect site labels. Existing Form Post response-mode,
module-transport and candidate storage regressions passed 532 assertions
with no failures, warnings or skips. The query-callback smoke selection
also passed again on Windows, with its partial-coverage flag and cleanup
intact. Its report is
`integration/openid/.artifacts/smoke-20261113-205453-266a10a4126f/evidence.json`;
the module loop took 22.91 seconds. R lint, formatting, actionlint and
patch whitespace checks pass. Manual workflow dispatch now offers
`form-post`; pull requests continue to run smoke. The upstream Form Post
Basic plan does not select the separate
`oidcc-client-test-form-post-error` module; comprehensive-plan coverage
remains a C09 task. The C06 warm-cache gap remains open.

C08 is `3c7aa049`. C08 execution (2026-11-13): the pinned client refresh
plan resolves to three modules with no forced per-module variants. A
live API probe established that the plan uses JSON null for those
variants. The driver omits the optional runner variant parameter for
those entries and still requires the complete plan variant in every
runtime result.

Each case completes a normal browser login, retains the original grant
and validated identity in the same app and Shiny session, then
explicitly calls the public connection’s `$refresh()` method. The
positive case retains the original ID token, issuer, subject and
connection, fetches UserInfo during refresh, and exports the new access
token through `$access_token()`. The two negative cases require an
ID-token audit error naming `iss` or `sub`, the normal
`token_refresh_error`, session clearing, an unusable retained connection
and blocked access-token export. Their UserInfo count stays at the
initial login’s one request. The fixture does not log out or modify
token state to produce those outcomes. Reports contain comparison
booleans and counts, without identity or credential values.

The changed-subject rejection already existed; diagnostic commit
`bfe4fdf8` adds its missing safe claim label. The signed-claim audit,
refresh issuer/audience and rejected-refresh cleanup regressions pass
321 assertions with no failures, warnings or skips. The expanded
evidence validator passes 307 assertions, including attempts to pass
with missing grants, new sessions/apps, absent checkpoints, wrong
operation counts or incomplete retirement evidence.

All three modules finish `FINISHED/PASSED` on Windows (R 4.5.1, Chrome
157) and non-root Linux (R 4.5.0, Chromium 156), with matching app
outcomes, the real-app failure control and verified cleanup. The module
loops took 25.53 and 22.96 seconds. Retained sanitized reports are
`integration/openid/.artifacts/refresh-20261113-222805-fd5b072e2f42/evidence.json`
(Windows) and
`integration/openid/.artifacts/refresh-20261113-212915-8f51a2246236/evidence.json`
(Linux). Both record the C08 working tree based on `bfe4fdf8` with
`checkout_dirty = true`. Each reports complete coverage for this exact
synchronous, static-registration, code-flow refresh plan with query
callbacks and HTTP Basic client authentication. The upstream refresh
plan is outside certification.

The query-callback smoke selection passes again with partial coverage
and verified cleanup; its report is
`integration/openid/.artifacts/smoke-20261113-222936-bd3794b1ce39/evidence.json`.
R lint, formatting, actionlint and patch whitespace checks pass.

Manual workflow dispatch now offers `refresh` and uploads only its
sanitized evidence files. Pull requests continue to select smoke. The
GitHub workflow has not run yet. Further C09 work follows below; C06’s
warm-cache gap remains open, and
rotation/concurrency/retained-connection regressions remain separate
evidence layers.

C09, first slice (2026-11-13): all core selections accept
`--transport mirai`. Future multisession is limited to smoke and refresh
parity selections; other future profile combinations fail explicitly.
Each module case starts its own two-worker pool and checks backend
selection. Both workers must load the private checkout namespace, make a
verified HTTPS request to `/api/server` using the temporary CA and
reject a wrong hostname. These setup probes do not earn protocol
coverage. Actual token/UserInfo and validation-error events must come
from the observed worker PIDs, with the matching package version and CA
setting. Main-only execution cannot satisfy an async selection.

The fixture’s audit hook now writes only sanitized, allowlisted metadata
to atomic per-event files. The main app aggregates process-specific
operation counts and safe claim/error labels. Every event stays bound to
its run and package installation, while credentials, identities, error
messages and paths stay out of those records. Refresh waits for its
promise before checking identity continuity, token export and credential
retirement. Evidence schema 3 requires these transport checks and
verified process cleanup; the profile manifest remains schema 2. The
validator passes 363 assertions with no failures, warnings or skips,
including rejection of fallback execution, missing/foreign worker PIDs,
stale installations, failed TLS probes and absent cleanup.

The app registers exit handlers for its worker pool. Linux first
interrupts the app and permits orderly shutdown; forced termination
remains a fallback. Cleanup checks both descendants and the specifically
observed worker PIDs. Docker-hosted drivers need `--init` to reap
orphaned workers; a bare R process as container PID 1 left zombie
entries and correctly failed the strict check. The browser has an
explicit temporary profile, a 30-second startup budget and an observed
close-command promise. Browser process termination remains required.
Native websocket EOF messages can appear during intentional browser
shutdown. Browser/port fixes are in the separate harness commit
`9b287959`. The suite now publishes random loopback ports in
20000-45000: Linux-side port probes could not see Windows Docker
Desktop’s excluded dynamic-port ranges, which caused real bind failures
in the earlier 49152-65535 range.

Manual dispatch now selects the transport and installs the worker
dependencies. Pull requests retain synchronous smoke; hosted CI timings
remain unmeasured. Configuration keeps `coverage_complete = false` in
every transport. Its main cache template is retained, while async
dispatch serializes worker copies; the report records that scope and
does not claim a shared warm cache.

The complete Basic, Form Post Basic, Configuration and refresh
selections pass with mirai on Windows (R 4.5.1, Chrome 157, mirai 2.7.1)
and non-root Linux (R 4.5.0, Chromium 156, mirai 2.7.4). All declared
module outcomes match the suite and application checks, with the
real-app failure control and verified cleanup. Basic and Form Post each
retain thirteen `PASSED` verdicts plus the documented unsigned-token
`SKIPPED`; Configuration retains five `PASSED` and that optional skip.
Refresh has three `PASSED` verdicts.

| Selection               | Windows module loop | Linux module loop |
|-------------------------|---------------------|-------------------|
| Basic / mirai           | 157.75 s            | 95.50 s           |
| Form Post Basic / mirai | 150.83 s            | 95.41 s           |
| Configuration / mirai   | 69.33 s             | 32.25 s           |
| Refresh / mirai         | 37.74 s             | 25.45 s           |
| Smoke / future          | 37.99 s             | 24.99 s           |
| Refresh / future        | 45.31 s             | 27.52 s           |

The future selections pass with future 1.70.0 on Windows and 1.82.0 on
Linux. Sanitized schema-3 reports under `integration/openid/.artifacts/`
include:

- Windows: `basic-20261113-224918-c98fc0ad9117/evidence.json`,
  `form-post-20261113-231601-f40dd9f616b5/evidence.json`,
  `config-20261113-225346-c4dd54b93768/evidence.json`,
  `refresh-20261113-224809-cf25641baaea/evidence.json`,
  `smoke-20261113-224820-a2840f185a5d/evidence.json` and
  `refresh-20261113-230418-946e7c173ce2/evidence.json`.
- Linux: `basic-20261113-215019-b5b5bd25b46f/evidence.json`,
  `form-post-20261113-221551-0dbc136ba7dc/evidence.json`,
  `config-20261113-220529-54ce297a7813/evidence.json`,
  `refresh-20261113-220408-cde4fe717945/evidence.json`,
  `smoke-20261113-220733-29ad7872d4bc/evidence.json` and
  `refresh-20261113-220851-65f1d7cca4d6/evidence.json`.

These working-tree runs record parent `3c7aa049` and
`checkout_dirty = true`. Earlier Linux attempts failed on reserved
Windows ports, unreaped container zombies or Chrome’s 10-second startup
limit; they retain failed reports and earn no coverage. Final Form Post
runs include the explicit browser profiles and longer startup budget.
Windows preflight and the synthetic fixture check also pass, as does
synchronous smoke. The GitHub workflow has not run yet.

The existing async serialization, option-restoration and session-context
tests pass 222 assertions on Linux with no failures, warnings or skips
after adding the optional `otelsdk` test dependency to the private
runner image. Their Windows run passes the same 222 assertions with one
environment warning: its installed future binary was built under R 4.5.3
while the host uses R 4.5.1. No user R installation was changed. R lint,
formatting, actionlint and patch whitespace checks pass. The final
evidence gate also accepts all seventeen retained passing schema-3
reports from this implementation run.

C09, confidential-client slice (completed 2026-11-16): `auth-post`,
`auth-secret-jwt` and `auth-private-jwt` select two modules each from
the pinned Comprehensive plan: the normal login and invalid-issuer
modules. The resolved code-flow lists contain twenty-nine modules for
shared-secret authentication and twenty-eight for private-key JWT; the
manifest freezes those lists and requires their null per-module
variants. These selections stay partial and the upstream plan is
non-certifiable.

Static registration declares the selected method, with fresh credentials
per plan. Secret JWT uses HS256; private-key JWT uses RS256 with a fresh
RSA key and public-only JWKS registration. The app receives the private
PEM and uses normal public discovery, client and module APIs. Sync and
mirai must each produce a validated ID-token/UserInfo login and a typed
issuer rejection, with no retained rejected identity or UserInfo request
after that rejection.

The evidence helper reads the suite’s recorded HTTP requests and
authentication condition results. It requires the actual expected
method, matching client IDs, no mixed authentication mechanisms, correct
secret or JWT metadata, and successful credential/signature and claim
checks from the suite. Sensitive values are compared only in memory. Raw
logs, secrets, assertions, private keys, codes and claim values stay out
of the report. Evidence tests cover stale instance/probe identities,
wrong credentials, mixed auth, invalid PKCE, bad assertion metadata and
accidental disclosure. All 547 assertions pass with no failures,
warnings or skips.

Two pinned-suite gaps remain explicit. The public-client variant still
omits `none` from discovery and its public authentication sequence
performs no checks. A separate disposable probe confirms the missing
advertised method and the installed package’s typed discovery rejection.
The probe is cancelled and earns no conformance credit;
`public_client_authentication_tested = false`. Metadata and discovery
policy remain unchanged.

The client base class also guards verifier validation with
`env.containsObject("code_challenge")`, while the challenge condition
stores a string. Consequently the pinned code-flow client plan skips its
verifier check. The companion helper requires the suite’s S256
challenge-presence check and independently computes the challenge from
the actual token-request verifier. It retains
`suite_pkce_verifier_checked = false` and a coverage limitation. This
establishes matching client requests; bad-verifier rejection still needs
an enforcing provider. The [scope
record](https://lukakoning.github.io/integration/openid/scope.md) links
the exact pinned source and describes the limits.

All twelve authentication selections passed on Windows (R 4.5.1, Chrome
157) and Linux (R 4.5.0, Chromium 156): three methods, two transports
and two operating systems. Their twenty-four modules finished `PASSED`,
each with matching app and request evidence. All twelve current evidence
gates pass with verified cleanup and `coverage_complete = false`.
Module-loop times and sanitized reports under
`integration/openid/.artifacts/` are recorded below. Times exclude
package installation, suite startup, the public capability probe,
app-stop control and stack teardown. The four retained 2026-11-13 sync
reports identify parent commit `6870f73d`; the eight 2026-11-16 reports
identify `91ef76de`. All record a dirty checkout containing this
authentication slice, rather than claiming a committed build identity.

| Environment | Profile / transport | Loop seconds | Report directory (`evidence.json`) |
|----|----|---:|----|
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

The existing synchronous smoke selection also passed again on Windows:
three module verdicts, the current evidence gate and cleanup, in 32.71
seconds. Its report is
`smoke-20261116-195540-a0f48c1f0e5f/evidence.json`. All test installs
used private libraries. R lint, formatting, actionlint and patch
whitespace checks pass. Hosted CI has not run.

Image-acquisition fix `91ef76de` was necessary when validation resumed:
on 2026-11-16 the upstream registry returned `not found` for the locked
server digest. Cached images are now accepted only when their
`RepoDigests` match the locked content digest. Missing images must still
be pulled by that digest. The full server-jar source check and live API
revision/TLS checks remain intact. Preflight passes all 26 environment
assertions and the live checks using the verified cache. Reports
distinguish cached images from pulled images. A fresh CI runner needs an
available verified mirror or a reviewed lock update; the hosted workflow
has not run and remains blocked by that availability issue.

C09, shared-pool slice (2026-11-16): `run-shared-pool.R` keeps one R
process and two verified mirai workers alive across eight alternating
browser flows. POST and private-key-JWT clients each complete a normal
login and a typed issuer rejection, then repeat with fresh registrations
and credentials. Each plan has a distinct discovered issuer, shared by
its two modules. Each case gets a new app, client and cache object,
while the process and worker identities must stay the same. The gate
requires an observed worker to perform protocol work for both methods;
merely starting a pool cannot establish reuse.

Four nested selections retain the existing authentication evidence
gates, including actual request comparisons, S256, suite authentication
checks and typed issuer rejection. The aggregate gate binds the
plan/module identities and execution order. Different audit hooks and
timeout settings must reach protocol work. Both workers are inspected
before and after every case for restored hook/timeout options and empty
async session context. Earlier audit files must remain unchanged after
later cases. Cleanup credit stays false until the shared process and
observed workers stop. The first live attempt caught a fixture handoff
bug: a completed case’s stop signal could end the next app. The fixture
now closes its session and retires that signal before the next handoff,
and an unrequested app stop fails immediately.

This checks sequential reuse, including returning to both authentication
methods with new credentials after the first rejected logins. Concurrent
multi-issuer dispatch, shared cache objects and other auth pairings
remain outside this selection. Reports keep partial coverage and the
existing suite public-client and PKCE limitations. The manual workflow
exposes `shared-pool` with mirai and uploads only its sanitized root
report. Registry availability still blocks a fresh hosted run.

Validation completed on Windows (R 4.5.1, Chrome 157) and Linux (R
4.5.0, Chromium 156). Each run exited zero after eight `FINISHED/PASSED`
verdicts, four passing nested authentication gates, the aggregate
isolation gate and verified cleanup. All 640 evidence assertions pass
with zero test failures, warnings or skips. The existing Windows
synchronous smoke selection passed its three modules and cleanup again.
R lint, formatting, actionlint and patch whitespace checks pass. No
package R code or user R installation changed.

Sanitized reports under `integration/openid/.artifacts/`:

| Environment / selection | Module-loop seconds | Report directory (`evidence.json`) |
|----|---:|----|
| Windows / shared-pool | 55.98 | `shared-pool-20261116-201955-29f6d05a5ba2` |
| Linux / shared-pool | 47.95 | `shared-pool-20261116-191955-c75314810211` |
| Windows / sync smoke | 39.75 | `smoke-20261116-201946-0a1ebbc1821f` |

The shared-pool timings include all eight per-case app/browser handoffs
and worker-state inspections, but exclude installation, suite/pool
startup, capability/failure controls and final teardown. Both reports
identify parent commit `b409b465` and the dirty checkout containing this
slice. They record verified cached images at the unchanged locked
digests and partial coverage. The gate and documentation now reflect the
suite’s actual issuer scope: one distinct issuer per plan, shared by its
positive and negative modules. Failed development runs retain failed
gates and earn no validation credit.

C09 follow-up: complete public S256 coverage against an appropriate
provider or corrected suite. Existing Keycloak public and PKCE scenarios
remain separate evidence. Keep C09 open until that acceptance case
passes, and retain the C06 warm-cache gap.

C10, first slice (2026-11-16): `fapi-dpop` selects the generic OIDC,
private-key-JWT, DPoP, simple-authorization variant of the pinned final
Security Profile client plan. The API resolves twenty-three modules and
forces unsigned PAR requests with plain authorization responses. The
manifest freezes that module/variant list. This slice selects the nonce
happy path, the happy path without DPoP nonce, and invalid ID-token
issuer rejection. Coverage stays false.

Commit `d3736366` adds the explicit `id_token_profile = "fapi2"`
discovery policy. The first live attempt exposed the mismatch between
standard OIDC’s RS256 discovery requirement and FAPI’s permitted signing
algorithms. The new policy keeps normal issuer, endpoint, JWKS and
metadata validation, and intersects implemented FAPI algorithms with the
caller and advertised sets. Standard OIDC still requires RS256.
PS256-only metadata has no supported algorithm overlap. The discovery
fix passed 367 focused assertions with zero test failures, warnings or
skips, including the existing standard OIDC cases.

The fixture supplies separate ephemeral ES256 server,
client-authentication and DPoP keys through the normal suite/provider
configuration. Client registration contains only its public key. Normal
discovery selects DPoP token types and the existing minimal
front-channel mode; compatibility mode’s extra browser parameters
correctly failed the first suite run. Client assertions use the
discovered issuer as a string audience. The app validates its ID token
and UserInfo before explicitly requesting the exported accounts endpoint
through the public connection API. HTTP 200 and the suite’s completion
marker are required; UserInfo alone cannot satisfy resource coverage.

Evidence compares actual PAR, token, UserInfo and accounts requests in
memory. It requires ES256 assertions, correct S256, only client
ID/request URI at the authorization endpoint, DPoP method/URI/key
consistency, distinct JTIs and the resource access-token hash. Nonce
cases require observed repeated requests with changed nonces and the
suite’s successful nonce checks. The no-nonce case requires one request
at each endpoint and absent proof nonces. The suite’s verifier-matching
condition runs in this plan; the separate OIDC-plan PKCE limitation
remains unchanged. Invalid ID-token issuer handling must retain no token
and make no UserInfo or accounts call.

Login executes in the chosen sync/mirai transport. The connection’s
imperative resource request runs in the Shiny process, and reports
record that PID and scope. Raw logs, assertions, proofs, keys,
credential values and response bodies stay out of uploaded reports.
Manual CI offers this selection; fresh hosted execution still needs the
pinned server image to become available.

Validation completed in sync and mirai on Windows (R 4.5.1, Chrome 157)
and Linux (R 4.5.0, Chromium 156). All four commands exited zero after
three `FINISHED/PASSED` verdicts, matching application/request evidence
and verified cleanup. The nonce happy paths each made two PAR, token,
UserInfo and accounts requests; the no-nonce paths made one at each
endpoint. Invalid-issuer cases stopped after the token response. All 779
evidence assertions pass with no test failures, warnings or skips. The
standard Windows synchronous smoke selection also passed its three
modules and cleanup. R lint, formatting, actionlint and patch whitespace
checks pass.

Sanitized reports under `integration/openid/.artifacts/`:

| Environment / transport | Module-loop seconds | Report directory (`evidence.json`) |
|----|---:|----|
| Windows / sync | 36.49 | `fapi-dpop-20261116-204524-67ca76edf8d7` |
| Windows / mirai | 42.78 | `fapi-dpop-20261116-204730-0eafe2c719b0` |
| Linux / sync | 21.05 | `fapi-dpop-20261116-194525-3e3d0fabba04` |
| Linux / mirai | 25.72 | `fapi-dpop-20261116-194730-30a5b7663c7e` |
| Windows / sync smoke | 40.07 | `smoke-20261116-204730-94d6b0f8e4f9` |

These timings exclude installation, suite startup, the app-stop control
and final teardown. The four FAPI reports identify committed product fix
`d3736366` and the dirty checkout containing this runner slice. All
report verified cached images at the unchanged locked digests and
partial coverage. Private test libraries leave the user’s R installation
unchanged. Failed development runs retain failed gates and receive no
validation credit.

C10, full OIDC variant (2026-11-16): `fapi-dpop-full` executes all
twenty-three modules resolved for the same pinned
OIDC/private-key-JWT/DPoP variant. The original three-module `fapi-dpop`
selection stays partial. Manual CI now offers both selections without
changing the source, images or suite assertions.

The full selection adds discovery issuer mismatch, eleven ID-token
rejection cases, four malformed authorization callbacks and seven
positive flows in total. ID-token failures require the expected typed
claim or algorithm reason, no retained token and no UserInfo/accounts
call. The additional-audience case accepts either an audience or
authorized-party rejection, since both reject the untrusted additional
recipient. Positive cases cover audience arrays, omitted access-token
expiry, token-type and DPoP challenge-scheme case, nonce absence and
absent mTLS endpoint aliases. All use the public connection API, require
a usable connection and check the accounts completion response. Missing
`expires_in` exercises the package’s documented 3600-second fallback;
the fixture supplies no expiry and changes no token or validation state.

The malformed callbacks are rejected by the public UI’s HTTP handler
before a callback Shiny session starts. The driver therefore collects
the actual browser HTTP 400 response instead of waiting for a second
Shiny snapshot. Its evidence requires the matching allowlisted audit
label, response body match, no-store, no-referrer, plain text and no
reflected credentials. App/cache/session identities must match the
initial unauthenticated session. No token exchange, UserInfo or accounts
request is allowed, and this stage earns no authentication or worker
protocol-work credit. Discovery rejection likewise earns only
discovery-stage evidence. Malformed-callback error pages retain their
query in the address bar; reports explicitly record
`callback_cleaned = false` for those four cases. Other callback paths
still require URL cleanup. C15 should revisit query retention on these
HTTP error pages as a separate privacy improvement, while preserving
rejection and preventing reflection of callback credentials.

Complete coverage for `fapi-dpop-full` means this exact resolved variant
only. Resource requests still run in the Shiny process, including mirai
login runs. Private HTTP observations, callback values and raw suite
logs stay under ignored artifacts; uploaded reports contain only
allowlisted comparisons and counters. Failed development runs keep
failed gates and receive no validation credit.

An initial full run completed all twenty-three suite modules but failed
the local evidence gate: the issuer mutation condition emits a plain
event without a result field, while the gate incorrectly required
`SUCCESS`. An attempted `INFO` interpretation also failed and receives
no validation credit. Inspection of the live API payload confirmed the
event shape. The corrected gate matches its source, exact message and
mutated issuer against the suite’s exported issuer, with no result
field. Regression checks reject substituted levels, messages, sources
and issuers; the upstream suite verdict independently must still be
`FINISHED/PASSED`.

Commit `29724328` fixes a separate audit gap exposed by the expiry
modules: missing, malformed and expired `exp` values were correctly
rejected, but their typed errors omitted the claim label. They now
report `claim = "exp"` without the value. The rejection rules are
unchanged. All 300 focused JWT/audit assertions pass with zero test
failures, warnings or skips. The full selection continues to require the
specific claim label; it does not accept an unrelated ID-token error.
The runner now checks app, transport and FAPI evidence after each case,
naming the failed module and evidence layer immediately. Final report
validation still checks the complete selection, bindings and cleanup.

Final validation passed in sync and mirai on Windows (R 4.5.1, Chrome
157) and Linux (R 4.5.0, Chromium 156). All four commands exited zero
with twenty-three `FINISHED/PASSED` verdicts each, matching app/request
evidence, complete variant gates and verified cleanup. Independent
report revalidation confirmed all 92 outcomes and all four coverage
gates. All 966 evidence assertions pass with zero test failures,
warnings or skips. Standard Windows synchronous smoke also passed its
three modules and cleanup. R lint, formatting, actionlint and staged
patch whitespace checks pass.

Sanitized reports under `integration/openid/.artifacts/`:

| Environment / transport | Module-loop seconds | Report directory (`evidence.json`) |
|----|---:|----|
| Windows / sync | 385.97 | `fapi-dpop-full-20261116-214626-859ae6ff835d` |
| Windows / mirai | 430.34 | `fapi-dpop-full-20261116-214626-5a0b7ce12224` |
| Linux / sync | 229.97 | `fapi-dpop-full-20261116-204730-9518d87faa9d` |
| Linux / mirai | 257.91 | `fapi-dpop-full-20261116-204730-2fcc9fc37f06` |
| Windows / sync smoke | 69.42 | `smoke-20261116-214555-4aa673db6b95` |

The selections ran concurrently. Timings exclude installation, suite
startup, the app-stop control and final teardown; they are local
measurements, not hosted CI timings. Reports identify product fix
`29724328` and the dirty checkout containing this harness slice. All
images came from the verified cache at the unchanged locked digests.
Test libraries stay private, and no owned Docker containers remain after
cleanup. Earlier failed reports remain failed and receive no validation
credit.

C10, OAuth-only slice (2026-11-16): `fapi-oauth-dpop` freezes the
separately resolved `plain_oauth` variant: eleven modules using ES256
private-key JWT, DPoP, unsigned PAR and plain query responses. Six flows
exercise resource use; the remaining modules reject discovery issuer
mismatch and four malformed issuer/state callbacks. The twelve
ID-token-specific modules are inapplicable.

The first setup attempt exposed a missing package feature: the suite
publishes RFC 8414 metadata for OAuth-only clients. Commit `8a8882cf`
adds the public
[`oauth_provider_oauth_discover()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_provider_oauth_discover.md)
helper. It inserts the well-known component before the issuer path,
removes terminal slashes for the metadata request and retains the exact
issuer for comparison and subsequent requests. It shares the existing
transport, endpoint, host, auth, PAR, DPoP and mTLS metadata checks.
OAuth-only mode adds no `openid` scope and enables no OIDC nonce,
ID-token or UserInfo processing. The OIDC helper retains its existing
defaults and rules. All 773 discovery assertions pass with zero test
failures, warnings or skips, including OIDC, FAPI, SMART and
runtime-JWKS regressions. NEWS and generated reference documentation
describe the API and its unsigned-JSON/code-flow scope.

The fixture requests only `accounts`. Positive evidence uses an
`authorized` outcome: actual access token, no ID token in the suite
response or app, zero UserInfo traffic and a successful public
connection request. The module’s `authenticated` signal indicates
accepted credentials here and earns no OIDC identity credit. Independent
comparisons check PAR scope and absent OIDC nonce, PKCE, assertions,
DPoP proofs/retries and resource completion. Mirai must perform the code
exchange in a verified worker; resource requests stay in the Shiny
process. Pre-token rejection stages retain their existing strict checks.

The first complete OAuth-only run exposed a separate interoperability
advisory. The happy-path, happy-path-no-dpop-nonce and
happy-path-no-mtls-endpoint-aliases modules report `WARNING` from the
pinned `CheckStateLength` condition because the encrypted state exceeds
128 characters. Their exchanges succeed; eight other modules report
`PASSED`. The original run’s gate failed and receives no validation
credit. The current explicit policy accepts only this fixed warning in
these three modules, with measured state length above 128 and no other
warning/failure/review events. Verdicts remain unchanged. All eleven
modules remain mandatory, and coverage stays false even if the manifest
is incorrectly marked complete. This records the finding without
weakening state protection or claiming warning-free OAuth-only
conformance.

Final validation ran all eleven modules in sync and mirai on Windows (R
4.5.1, Chrome 157) and Linux (R 4.5.0, Chromium 156). Each command
exited zero with eight `PASSED` verdicts and the three verified
`WARNING` verdicts above. All four selection gates and cleanup checks
pass; all four coverage flags remain false. Independent report
revalidation confirmed 32 passes and 12 exact state-length advisories,
with measured state lengths of 831-832 characters. The suite source and
assertions remain unchanged.

All 1,045 evidence assertions pass with zero test failures, warnings or
skips. They reject missing modules, substituted OIDC identity evidence,
unexpected UserInfo or ID-token traffic, wrong scopes/nonces and missing
or altered advisory evidence. They also keep coverage incomplete if the
manifest’s complete flag is incorrectly enabled. The existing
three-module OIDC FAPI selection passed in Windows mirai, validating the
shared discovery path and token/resource behavior. R lint, formatting,
actionlint and patch whitespace checks pass.

Sanitized reports under `integration/openid/.artifacts/`:

| Environment / transport | Module-loop seconds | Report directory (`evidence.json`) |
|----|---:|----|
| Windows / sync | 153.62 | `fapi-oauth-dpop-20261116-222647-30190e0df1c5` |
| Windows / mirai | 168.30 | `fapi-oauth-dpop-20261116-222647-7e3c3bf5f9b8` |
| Linux / sync | 82.82 | `fapi-oauth-dpop-20261116-212648-b9d544031022` |
| Linux / mirai | 95.30 | `fapi-oauth-dpop-20261116-212648-af684d5efe57` |
| Windows / mirai OIDC regression | 43.72 | `fapi-dpop-20261116-221710-d5578745eb01` |

The final OAuth-only selections ran concurrently. Timings exclude
package and suite setup, the app-stop control and final teardown.
Reports identify product commit `8a8882cf` and the dirty checkout
containing this harness slice. Images came from the verified cache at
unchanged locked digests. Libraries and raw diagnostics stay private; no
owned Docker containers remain. Earlier setup and strict-warning
failures retain failed reports and receive no validation credit.

C10 compact state references are implemented in product commit
`0f8c2f8e` as the opt-in `oauth_client(state_transport = "reference")`;
encrypted wire state remains the default. The opaque logical state
resolves the existing pending record’s encrypted payload, with exact
ciphertext binding across cached callbacks and atomic consumption.
Client/provider/policy, redirect, scope, PKCE, DPoP-key, browser and
freshness checks remain enforced. Shared stores require `take()` even
under the legacy non-atomic opt-in.

Validation on 2026-11-16 passed 2,774 state, callback, bridge and
constructor assertions, with no test warnings or skips, including real
browser GET cleanup. Tests cover malformed, missing, expired, swapped
and replayed references, policy/key changes, JSON-cached callbacks,
browser-bound POST success/errors in both store types, and simultaneous
callbacks in two R processes. The race test sets its private library
before deserializing package closures and verifies exactly one token
exchange for each state transport. Jarl checks passed.

The new `fapi-oauth-dpop-reference` profile requires all eleven modules
to finish `PASSED`, with the actual client mode and independently
measured compact PAR state. Mutation checks reject
missing/oversized/inconsistent state evidence, an encrypted client, any
warning/skip and incomplete selections. All 1,328 evidence assertions
passed. The original `fapi-oauth-dpop` profile retains its
encrypted-state advisories and incomplete coverage status.

All four reference-profile runs passed all eleven modules: **44
`PASSED`, zero suite warnings**, four complete scoped gates and verified
cleanup. All forty non-discovery results measured 64-character opaque
state; reports contain the length and validity result without the
reference value.

| Environment / transport | Eleven-module loop (s) | Private artifact directory |
|----|---:|----|
| Windows / sync | 119.76 | `fapi-oauth-dpop-reference-20261116-230216-7f0981a8911f` |
| Windows / mirai | 136.34 | `fapi-oauth-dpop-reference-20261116-230535-27d3e29efff0` |
| Linux / sync | 71.55 | `fapi-oauth-dpop-reference-20261116-220216-3837be342fcd` |
| Linux / mirai | 81.07 | `fapi-oauth-dpop-reference-20261116-220514-3f082a41cdde` |

Windows used R 4.5.1 and Linux used R 4.5.0. Timings exclude
installation, suite setup, the app-stop control and teardown; concurrent
runs share host resources. Reports bind product commit `0f8c2f8e` and
the dirty harness checkout to the unchanged suite lock and cached
images. No owned Docker containers remain.

A separate local fixture probe passed eight OIDC exchanges: valid and
invalid nonce responses over query/form_post in sync/mirai, using
reference state. It checks real POST/303 navigation, browser binding,
worker execution, callback cleanup and the actual 64-character
authorization state. Its private report is
`state-reference-oidc-probe-20261116-230639-cbe7654ecc60`; it explicitly
keeps `gate_passed = false` and `coverage_complete = false` because this
targeted probe is not a complete OIDC profile selection.

This closes the state-length gap for the reference OAuth variant.
Refresh scenarios remain separate provider interoperability work.
C11-C12 retain mTLS and message signing. The C09 public-client and C06
warm-cache gaps remain open. Fresh hosted CI still needs an available
verified copy of the locked server image, and C15 retains callback
error-page query cleanup.

C11’s first slice is implemented in `b3347a41`, with the pinned
informational alias events corrected in `3c065170`. The new
`fapi-oauth-mtls` profile selects all nine modules resolved for
OAuth-only private-key-JWT authentication plus mTLS sender constraint.
It uses temporary client certificates, reference state, ES256
assertions, PAR and S256, and the public connection API for resources.
It explicitly permits opaque tokens with
`mtls_require_observed_cnf = FALSE`; the production library’s defaults
remain unchanged.

The gate correlates suite request IDs with the TLS listener’s actual
peer certificate, method, path and listener. It verifies alias use for
PAR/token and the ordinary PAR URL plus advertised mTLS token URL when
aliases are absent. Reports keep authentication and sender constraint
separate, and omit certificates, TLS fingerprints, keys and tokens. All
nine normal modules must finish `PASSED`, including discovery mismatch,
four callback rejections, token expiry/type behavior and alias fallback.

Three isolated attacker instances use the real issued token with a wrong
certificate, a wrong certificate plus a forged certificate header, and
no certificate. All three must produce the expected certificate-failure
verdict and independently observed unexpected TLS peer. They use a raw
attacker request, with a separate report label from the normal
connection request. Their IDs, full variants,
run/attempt/checkout/source/plan identity, application outcome, worker
execution and cleanup must match this run. They receive no normal-module
pass credit.

These controls establish a limitation in the pinned suite. Its
`checkMtlsCertificate()` continues after
`EnsureClientCertificateMatches` fails. Wrong-certificate and
forged-header attempts therefore return HTTP 200 with the resource
marker while the suite marks their instances `FAILED`. Missing
certificates return HTTP 400 and `INTERRUPTED/FAILED`. The harness
preserves those outcomes and always forces `coverage_complete = false`
with `mtls_resource_denial_not_established`, including if the manifest’s
complete flag or coverage limits are changed. The upstream suite remains
unchanged.

Validation on 2026-11-16 passed **36 normal module runs** across four
gates, plus twelve separate expected-failure certificate controls. The
three-module OIDC/DPoP mirai regression also passed. All 1,923 evidence
assertions and Jarl checks passed, with no test warnings or skips.
Reports were revalidated against the final checker, including the full
control-variant binding.

| Environment / transport | Nine-module loop (s) | Private artifact directory |
|----|---:|----|
| Windows / sync | 120.18 | `fapi-oauth-mtls-20261116-233406-4d27ba8a846f` |
| Windows / mirai | 126.61 | `fapi-oauth-mtls-20261116-233512-7207746b711d` |
| Linux / sync | 64.65 | `fapi-oauth-mtls-20261116-223406-3543a6dcac11` |
| Linux / mirai | 70.47 | `fapi-oauth-mtls-20261116-223835-906e46ba60a1` |

The OIDC regression report is `fapi-dpop-20261116-233443-defce702ba4e`.
Windows used R 4.5.1 and Linux used R 4.5.0. Timings exclude certificate
and suite setup, package installation, the app-stop control, certificate
controls and teardown. Concurrent runs share host resources. Reports
identify collector commit `3c065170` and the dirty follow-up checkout,
with unchanged locked images from the verified cache. Earlier collector
failures and a Linux mirai Chrome startup timeout remain failed reports
and earn no validation credit; the final Linux mirai run used less
concurrent work. No owned Docker containers remain.

C11’s independent resource-denial check is implemented in `df714b2c`. It
extends the existing Python strict-AS fixture with a protected resource.
The resource records the actual TLS peer certificate for each issued
token and compares it with the resource request’s TLS peer. Two eligible
certificates have identical subject names but different DER encodings; a
token issued to either certificate requires that particular certificate.

Each platform completes 32 bound grants across RS256/RS384 JAR and
private-key-JWT authentication, direct authorization/PAR, sync/mirai
token callbacks, returned/omitted `cnf`, and both certificates. Public
Shiny module and connection APIs perform the exchange and resource
request. Wrong or missing certificates, forged certificate headers,
unknown tokens and two additional unbound grants produce **162 actual
HTTP 401 responses per platform**, with `invalid_token`, a Bearer
challenge and no resource content. The rightful holder can still access
the resource afterward, including with a misleading certificate header.

The runner installs the checkout in a private library and verifies that
both the main process and callback workers load that installation.
Exchange counts and process IDs distinguish sync from mirai execution.
CI uploads only sanitized JSON reports containing revision, dirty flag,
dependency versions, installation checks and assertion counts; private
libraries, keys and logs are excluded.

Validation on 2026-11-17 passed **1,609 assertions on each platform**,
with zero test failures, errors, warnings or skips. Both runs used the
concurrent state authentication fix `b135ac84` and OpenSSL 2.6.0. Jarl
checks passed too.

| Environment | R / Python / cryptography | Private artifact directory          |
|-------------|---------------------------|-------------------------------------|
| Windows     | 4.5.1 / 3.12.10 / 46.0.5  | `tests-20261116-231600-bb045ec309c` |
| Linux       | 4.5.0 / 3.13.5 / 50.0.2   | `tests-20261116-231747-77a31328c`   |

Report names use UTC. Both reports identify `df714b2c`; the Windows
checkout was clean and Linux recorded documentation-only edits. These
are package-owned, cross-language protocol tests with in-process Shiny
sessions. Authorization/PAR and resource requests run in the main
process; mirai coverage applies to the token callback. Browser login,
full OIDC and refresh of mTLS-bound tokens remain outside this fixture.
The reports keep `coverage_complete = false`, and this separate resource
check does not change the pinned OIDF provider’s HTTP 200 behavior or
its forced resource-denial coverage limit.

C11’s suite client-authentication variant is implemented in `38dd4fd9`
as the separate `fapi-oauth-mtls-auth` profile. It resolves all nine
modules for OAuth-only mTLS client authentication plus mTLS sender
constraint. The suite’s `mtls` variant advertises `tls_client_auth`;
registration includes the public certificate and omits shared secrets
and client assertion keys.

The gate requires `client_id` and the actual registered TLS peer at
PAR/token, with no JWT assertion, shared secret or HTTP Authorization
credentials. It retains reference state, PAR, S256, the public resource
connection and isolated resource attacker controls. The no-alias module
advertises literal mTLS URLs for both PAR and token; the collector now
requires its PAR setup event and actual mTLS listener. The
private-key-JWT profile retains its ordinary TLS PAR fallback. Evidence
checks cover both authentication methods in sync/mirai and reject
missing or changed credentials, TLS peers and suite setup events.

The pinned provider compares one exact registered certificate. This
selection does not establish PKI chain/subject-name validation or
PAR/token authentication failure responses. The checker forces
`suite_exact_certificate_registration_only` and
`mtls_client_authentication_denial_not_tested` into the limits,
alongside the unchanged `mtls_resource_denial_not_established`. Manifest
edits cannot make this profile’s coverage complete.

Validation on 2026-11-17 passed all four Windows/Linux and sync/mirai
gates: **36 normal `PASSED` modules and twelve separate expected-failure
resource controls**, with cleanup verified. All 2,460 evidence
assertions, Jarl checks and workflow validation passed, with zero test
warnings or skips. Every non-discovery module observed valid
64-character reference state and the actual registered PAR peer;
successful exchanges also verified token and resource peers.

| Environment / transport | Nine-module loop (s) | Private artifact directory |
|----|---:|----|
| Windows / sync | 108.16 | `fapi-oauth-mtls-auth-20261117-164503-dc692b256936` |
| Windows / mirai | 132.13 | `fapi-oauth-mtls-auth-20261117-164913-fe3510079345` |
| Linux / sync | 63.22 | `fapi-oauth-mtls-auth-20261117-154536-9f3df22ef539` |
| Linux / mirai | 82.49 | `fapi-oauth-mtls-auth-20261117-154854-6edf2f2c9c6f` |

Windows used R 4.5.1 and Linux used R 4.5.0; both loaded OpenSSL 2.6.0.
Reports identify collector commit `38dd4fd9`. Windows sync recorded a
clean checkout; the other runs recorded documentation-only edits. Locked
images came from the verified cache. Timings exclude setup,
installation, failure controls and teardown; concurrent runs share host
resources. Earlier callback collector and app-discovery startup failures
remain failed reports and receive no pass credit.

The existing private-key-JWT/mTLS profile also passed all nine modules
and three expected-failure controls in Linux sync. Its report is
`fapi-oauth-mtls-20261117-155242-ed41c76ae9a6` (62.47 seconds for the
module loop). This checks the original PAR alias fallback against the
updated collector.

The concurrent authenticated-state compatibility fix `e8b70286` was then
integrated in `9d94af4f`. Two fresh complete gates verified the combined
checkout: Windows mirai with OpenSSL 2.4.0 and Linux sync with OpenSSL
2.6.0. All eighteen normal modules passed, with six separate
expected-failure resource controls, verified cleanup and the same forced
coverage limits. Evidence checks again passed with zero test warnings or
skips. Both reports record documentation-only edits on `9d94af4f`.

| Environment / transport | OpenSSL | Nine-module loop (s) | Private artifact directory |
|----|----|---:|----|
| Windows / mirai | 2.4.0 | 117.69 | `fapi-oauth-mtls-auth-20261117-165756-08cfbdeea48e` |
| Linux / sync | 2.6.0 | 63.33 | `fapi-oauth-mtls-auth-20261117-155756-dd2eb403bcff` |

The fixture README now follows the restored `openssl >= 2.1.2`
dependency requirement without a development repository. No owned Docker
containers remain.

C11’s independent PKI authentication and denial checks are implemented
in `2c7273d5`. The Python fixture now has a fixed `tls_client_auth`
startup mode. Its TLS library verifies client chains against the
temporary CA, and the server compares the actual peer’s subject DN with
the registration. Authentication is required at PAR/token independently
of the requested scopes; competing secrets, JWT assertions and HTTP
Authorization credentials are rejected.

The public Shiny module and resource connection complete 32 bound grants
across RS256/RS384 JAR, direct/PAR authorization, sync/mirai token
callbacks, returned/omitted `cnf` and both eligible certificates. Shared
helpers retain the existing private-key-JWT resource matrix. Each
callback verifies the expected process, exactly one exchange and the
private package installation.

Raw controls require **80 HTTP 400 denials per platform**: 48
`invalid_client` responses for wrong subjects, absent peers, forged
certificate headers and missing/unknown identities, plus 32
`invalid_request` responses for competing credentials, including empty
credential fields. Eight requests with the correct subject but an
untrusted CA must fail during TLS. The same signed Request Object and
authorization code remain usable afterward. A new eligible certificate
with the same registered subject can authenticate, while its token
rejects the certificate used at PAR, including with a forged header.

Four public callback failures across both algorithms and transports
leave no token or connection. Their audit events require an HTTP error
from the correct process and installation. Two public PAR preparations
also reject the wrong subject with HTTP errors. The fixture covers a
single fixed DN and trust anchor; SANs, DN normalization edge cases,
revocation, self-signed client authentication and bound refresh remain
separate. The pinned OIDF suite’s registration model, verdicts and
forced coverage limits remain unchanged.

The concurrent state-encryption selection fix `7f2fa08c` was integrated
in `51c1653f`. Its OpenSSL upgrade warning made the older-version
fixture gate fail as intended. The runner now explicitly checks the one
expected `shinyOAuth_openssl_upgrade_warning` at startup on OpenSSL
below 2.6.0 and records its class, phase and count in sanitized evidence
(`c8ee6f36`). Unexpected warnings from that check and all protocol-test
warnings still fail the run. The production warning remains unchanged,
and the earlier failed run receives no pass credit.

Validation on 2026-11-17 passed **3,281 assertions on each platform**,
including both sync and mirai callbacks and the existing
private-key-JWT, resource, JAR/JARM, refresh and RS384 regressions. Both
runs had zero test failures, errors, warnings or skips. The Windows
startup advisory was checked and recorded once; Linux required none.

| Environment | R / OpenSSL / Python cryptography | Private artifact directory |
|----|----|----|
| Windows | 4.5.1 / 2.4.0 / 46.0.5 | `tests-20261117-163805-37b46d194913` |
| Linux | 4.5.0 / 2.6.0 / 50.0.2 | `tests-20261117-163805-745fbf7b3` |

Reports identify `c8ee6f36` with documentation-only edits and the
correct private package installation. Their complete test-file
selections, assertion totals, dependency versions and startup-advisory
records were revalidated. Only sanitized JSON reports were retained in
the main checkout; private libraries, keys and logs were excluded.
Earlier setup and assertion failures remain failed reports. No owned
Docker containers remain. These are package-owned protocol checks with
`coverage_complete = false`, and they do not establish external provider
conformance or OpenID certification.

The subsequent GCM-only state change requires the CRAN R package
`openssl >= 2.6.0` for all new runs. It removes the older-version
CBC-HMAC fallback and its startup advisory; the reports above describe
the earlier configuration. JWE CBC-HMAC support is unchanged. Upgrade
the dependency and restart every worker before rerunning these protocol
gates.

C11’s OIDC/mTLS selections are implemented in `564316db`: `fapi-mtls`
uses private-key-JWT authentication, and `fapi-mtls-auth` uses the
suite’s mTLS authentication variant. Both resolve all 21 applicable
modules, with reference state and the client’s existing `fapi2` ID-token
profile. The selections cover five successful exchanges, eleven ID-token
rejections, four callback rejections and one discovery rejection. All
modules require `PASSED` without warnings or skips, including the
optional-nonce cases selected by this client configuration.

The collector observes the actual returned ID token and checks the
selected issuer/audience/expiry/algorithm mutation and the nonce
relationship to PAR. It inspects claims; the installed client validates
signatures and claims. Token rejections must make no UserInfo or
resource request. Successful exchanges require both, with the actual
registered TLS peer and the same issued Bearer token. UserInfo’s
no-alias fallback requires its literal mTLS URL and the pinned setup
event. The gate retains separate auth-method and token-binding
dimensions, reference-state measurement and verified worker execution.

The three isolated resource controls remain separate expected-failure
instances. The pinned suite still returns resource content after
detecting a wrong certificate, so every mTLS report retains its forced
incomplete-coverage status. The mTLS authentication variant also retains
the exact-certificate registration and authentication-denial limits. The
independent Python checks remain separate evidence for selected PKI
authentication and actual resource denial.

Validation on 2026-11-17 passed all eight profile/platform/transport
gates: **168 normal `PASSED` modules and 24 separate expected-failure
resource controls**. The normal results include 40 successful resource
exchanges, 88 ID-token rejections, 32 callback rejections and eight
discovery rejections. All 5,276 evidence assertions, Jarl checks and
workflow validation passed, with zero test warnings or skips. Every gate
verified the app-stop control and cleanup.

| Selection | Environment / transport | 21-module loop (s) | Private artifact directory |
|----|----|---:|----|
| `fapi-mtls` | Windows / sync | 237.80 | `fapi-mtls-20261117-175726-6abae364ff71` |
| `fapi-mtls` | Windows / mirai | 277.21 | `fapi-mtls-20261117-180731-486e3bad157c` |
| `fapi-mtls` | Linux / sync | 164.34 | `fapi-mtls-20261117-171257-f6c2f39dd8ec` |
| `fapi-mtls` | Linux / mirai | 189.81 | `fapi-mtls-20261117-171801-84a1383e8263` |
| `fapi-mtls-auth` | Windows / sync | 240.57 | `fapi-mtls-auth-20261117-181434-8f50a5cbf9b4` |
| `fapi-mtls-auth` | Windows / mirai | 268.98 | `fapi-mtls-auth-20261117-182056-1178d7dabc39` |
| `fapi-mtls-auth` | Linux / sync | 163.49 | `fapi-mtls-auth-20261117-165736-72e91f9df037` |
| `fapi-mtls-auth` | Linux / mirai | 187.32 | `fapi-mtls-auth-20261117-170731-b9322416cee6` |

Windows used R 4.5.1 and Linux used R 4.5.0, both with OpenSSL 2.6.0.
Reports identify `564316db`; the first Windows sync checkout was clean
and later dirty flags reflect documentation-only edits. Locked images
came from the verified cache. Timings exclude installation, setup,
failure controls and teardown; concurrent runs share host resources. All
eight reports were revalidated for complete selections, expected stages,
nonce results, actual peers, issued-token use and sanitized output. Only
evidence JSON was retained in the main checkout; keys, libraries and
logs remain private. No owned Docker containers remain.

C11’s selected OAuth/OIDC mTLS variants now have gates for both
transports; coverage remains bounded by these documented suite and
fixture limitations. C12 retains Message Signing; C13-C14 retain
`oidc-provider`. C06 warm-cache, C09 public-client, C15 callback
error-page query cleanup and fresh hosted CI image availability remain
open.

C12 implementation (2026-11-17): `fapi-message-signing` selects the
pinned final Message Signing client plan with OIDC, private-key-JWT,
DPoP, signed Request Objects through PAR and signed query responses. Its
eight plan variants are explicit; its per-module variant is the empty
object returned by the suite. The suite API must return exactly 29
modules. The selected JARM response mode excludes the two plain-response
issuer tests; the eight JARM rejection modules replace that coverage.
Every normal module requires `PASSED` without warning or skip
allowances. The profile and sync/mirai transports are available through
manual workflow dispatch.

The installed app uses ES256 for client assertions and Request Objects,
and requires ES256 JARM responses. The suite advertises only
`response_mode=jwt`; the app sends that supported spelling and uses the
client’s query transport. The initial `query.jwt` fixture configuration
correctly failed the client’s metadata check and was corrected without
changing discovery metadata or any suite assertion. Request Objects
include explicit `nbf` and a short lifetime. The optional `max_age`
claim is absent; evidence requires the pinned suite’s exact
informational event for that case rather than inventing a success event.

Evidence verifies actual JAR signatures against the registered key, the
signed issuer/audience/redirect/scope/nonce/PKCE parameters, PAR-only
authorization and the suite’s validation events. It independently
inspects the actual JARM redirect and verifies its ES256 signature, or
the precise selected invalid signature/algorithm case, without applying
JWT expiry checks during signature inspection. Claim and expiry variants
remain separate checks. Token requests must redeem the code from that
JARM response. Invalid callbacks require the expected browser-observed
HTTP 400 category, no identity and zero token, UserInfo or resource
requests. Legitimate exchanges require validated ID tokens, UserInfo and
a DPoP-protected resource request through the public connection API.
Compact JWTs, claim values, signing keys, codes and raw HTTP error text
stay private. Both top-level and nested response credentials are checked
against the HTTP rejection body before the fixture emits sanitized
evidence.

The independent Python fixture now also combines JAR, PAR and signed
JARM for RS256/RS384, over GET/POST authorization requests. Its targeted
458 assertions passed on each of Windows and Linux. It remains a
separate comparison without OIDC discovery, ID tokens or browser login.
No package behavior or upstream fixture assertion was changed by C12.
Full cross-platform validation is recorded below.

`coverage_complete=true` is limited to the exact resolved 29-module
variant. Other authentication methods, mTLS, signing algorithms,
encryption, Form Post, refresh and grant management remain additional
selections. Resource use stays in the main process. JARM rejection
occurs at the main-process HTTP boundary; mirai does not execute that
rejection. C15 retains error-page query cleanup, and fresh hosted CI
image availability remains unverified. C13-C14 remain the next provider
interoperability work.

C12 validation (2026-11-18), source
`60bb1a3a29bfeb20beb170d52470bb3e5c8e8074`: all four gates completed all
29 normal modules with `FINISHED/PASSED`, for 116 suite passes. The
app-stop failure control and browser, app, worker, proxy and stack
cleanup checks passed in every gate. Reports were revalidated for the
complete selection, signed-request/response evidence, code redemption,
expected rejection stages, worker execution, locked images and absence
of raw credentials. The evidence regression checks passed 6,678
assertions with no test warning or skip. Jarl, formatting and workflow
validation passed.

| Runtime / transport | Module loop seconds | Local sanitized evidence directory |
|----|---:|----|
| Windows / sync | 339.82 | `fapi-message-signing-20261117-235701-9cb11a881c13` |
| Windows / mirai | 372.33 | `fapi-message-signing-20261118-000458-530fc874d842` |
| Linux / sync | 222.96 | `fapi-message-signing-20261117-225641-05a64f8441fa` |
| Linux / mirai | 245.96 | `fapi-message-signing-20261117-230228-0a6027efb908` |

Windows used R 4.5.1 and Linux used R 4.5.0 in a Docker Desktop
container; both used R openssl 2.6.0. Each independent Python comparison
passed 458 assertions from a fresh installation of the same commit.
Python cryptography was 46.0.5 on Windows and 50.0.2 on Linux.
Comparison evidence:

- Linux: `independent-signing-20261117-225755-2ad68ec2d008`.
- Windows: `independent-signing-20261117-235805-860b433fa023`.

Windows checkout flags were clean during validation. Linux reported a
dirty checkout because its default Git configuration interpreted the
Windows mount’s CRLF files differently. A read-only comparison with
matching `core.autocrlf=true` returned no diff and an empty status;
these flags do not represent source edits. The flags are preserved in
the reports.

Locked service images came from the digest-verified cache. Timings cover
module loops only, excluding evidence tests, installation, setup,
failure controls and teardown; concurrent runs shared host resources.
Only sanitized evidence JSON was retained in the main checkout. Keys,
libraries and raw logs remain private. No owned test containers remain.
Fresh hosted CI image availability remains unverified.

C13 implementation (2026-11-18): `integration/oidc-provider/` runs the
published `oidc-provider` 9.14.0 package with Node 24.22.3 LTS. The
official Node container is pinned by digest; the npm lock fixes all 40
dependencies and their integrity values. The runner verifies the locks
and records its built image ID and fixture input hashes. Builds run
three Node fixture tests before starting the server.

Four explicit registrations/callback cases cover public (`none`) and
confidential (`client_secret_basic`) clients with query and Form Post
responses. Every case uses S256, browser login/consent, validated ID
tokens, UserInfo and refresh through the public connection API. Refresh
must preserve identity and the existing connection while rotating its
refresh token. Both UserInfo calls must use the currently issued access
token. A live request missing PKCE must fail before code issuance.
Reports include selected discovery capabilities and provider events,
with no token, code, nonce, credential or raw error values.

The fixture uses the provider’s public interaction API for its fixed
test account and consent screen. Normal provider handlers perform
discovery, authorization, PKCE, token, ID-token, UserInfo and refresh
processing. No provider protocol handler is patched. Development
interactions are disabled; PKCE is required for both client types, and
refresh rotation is explicit. Temporary signing keys, TLS material and
static registrations isolate cases.

The harness reuses the existing Shiny, Chrome, TLS, audit and worker
helpers. The shared app fixture adds public-client authentication and
optional configured authorization parameters for `prompt=consent`. It
continues to install this checkout privately and verify package
identity, worker CA/hostname checks, actual sync/mirai execution and
cleanup. A stopped-app canary must fail; setup or discovery failures
fail preflight instead of becoming unsupported results.

Each successful real report supplies the valid control for 64
report-mutation checks: missing cases, lost provider evidence, failed
PKCE/code/authentication binding, stale UserInfo credentials,
refresh/identity failures, missing worker or Form Post evidence and
incomplete cleanup. The serialized report must also pass the checker.
The new workflow runs sync on relevant pull requests and offers
sync/mirai manual dispatch, uploading only sanitized evidence JSON.

`coverage_complete` remains false: these are selected provider
interoperability checks, not certification. C14 retains advanced
JAR/PAR/sender-constraint/JARM combinations, signed UserInfo, resource
indicators and lifecycle across navigation. The independent Python
fixture remains separate. Validation of the committed C13 implementation
is recorded below.

C13 validation (2026-11-18), source
`6d527c8782f02f13e88eb391c32aaabffc2a3be5`: the four Windows/Linux
sync/mirai gates passed all sixteen selected code flows and refreshes.
Each case completed a live missing-PKCE rejection before the successful
exchange. All four stopped-app canaries and 256 report-mutation controls
passed. Serialized reports were independently rechecked against the
locked runtime, fixture hashes, complete case selection, provider
events, current-token UserInfo use, refresh rotation, worker execution
and cleanup. Both runtime checkouts were clean during validation.

| Runtime / transport | Four-case loop seconds | Local sanitized evidence directory |
|----|---:|----|
| Windows / sync | 39.21 | `basic-20261117-233646-6b10249938f4` |
| Windows / mirai | 46.92 | `basic-20261117-233759-3301a4333dbd` |
| Linux / sync | 22.99 | `basic-20261117-233656-00a611bb695a` |
| Linux / mirai | 26.28 | `basic-20261117-233810-91da40e6d757` |

Windows used R 4.5.1, httr2 1.2.2 and mirai 2.7.1; Linux used R 4.5.0,
httr2 1.3.0 and mirai 2.7.4 in a Docker Desktop container. Both used R
openssl 2.6.0 and chromote 0.5.1, against the same Node 24.22.3 /
oidc-provider 9.14.0 runtime and fixture inputs. Timings cover the four
normal case loops, excluding installation, build, the stopped-app
control and outer teardown. Concurrent runs shared host resources.

The existing OIDF evidence checks still passed 6,678 assertions. Its
Linux/sync smoke regression also passed all three modules, its app-stop
control and cleanup: `smoke-20261117-234004-aa1b30266a8d`. Node’s three
fixture tests, Jarl, R formatting and actionlint passed. Only sanitized
evidence JSON was retained in the main checkout; keys, registrations,
libraries and raw logs remain private. No owned test containers remain.
Hosted CI has not been run for this new gate.

C14 first selection (2026-11-18): the advanced runner adds six explicit
confidential Basic-auth cases: JAR + DPoP, JAR + mTLS token binding and
JAR + signed JARM, each directly and through PAR. Request Objects, ID
tokens, JARM and signed UserInfo use RS256; DPoP uses ES256. Each
positive case must finish browser login, refresh, validated UserInfo, a
real public connection request at native UserInfo, introspection and
access-token revocation. The revoked credential must become inactive and
receive HTTP 401 at UserInfo.

The published provider package and its native claim/signature validation
remain unmodified. Public configuration enables the selected features
and mTLS discovery aliases. Independent observers verify actual Request
Object and response signatures, selected claims, PAR-only browser
parameters, grant sender binding and use of the current credential.
Client private keys are excluded from the provider configuration and
mounted directories. The shared Shiny fixture enables these modes
without changing package production code.

DPoP probes require native HTTP 401 for Bearer fallback, a different
proof key and replay, with HTTP 200 for the first use of the same proof.
mTLS probes require 401 for a missing certificate, a different
certificate with the same subject, and that wrong certificate carrying a
forged certificate header. Binding evidence comes from the actual TLS
peer, not the header. Two further browser cases tamper with real JARM
signatures and require HTTP 400 before any token or UserInfo exchange.
Each report includes the app-stop canary, mutated evidence controls and
serialized report validation.

The mTLS listener is separate from the normal browser listener; normal
discovery configuration supplies token, UserInfo, introspection,
revocation and PAR aliases. This selection tests certificate binding
with Basic authentication and temporary self-signed peers, not PKI
client authentication. Opaque mTLS tokens do not require a locally
observed cnf claim; provider binding and live denial evidence are
required. Refresh evidence requires sender-constrained credentials to
remain blocked from raw export while the connection stays usable.

The advanced selection is available by manual workflow dispatch with
sync or mirai; pull requests retain the four-case basic sync gate. Only
sanitized JSON is uploaded. The new README records the commands and
scope. Token exchange, refresh and validated UserInfo use the selected
transport. Explicit resource/probe/introspection/revocation actions run
in the Shiny main process, and JARM rejection occurs at the pre-session
HTTP boundary.

C14 remains partial. RFC 8707 resource indicators and
oauth_connections_server() retention across navigation are next. This
first selection uses native UserInfo as its resource; it does not
establish separate resource-server audience enforcement, encryption,
other algorithms/auth methods or JAR + DPoP + JARM together. C06
warm-cache, C09 public-client suite capability and C15
rejection/query-cleanup work remain separate.

C14 first-selection validation (2026-11-18), source
`c615cdda526a796112028f374b93317e567f3113`: all four Windows/Linux
sync/mirai advanced gates passed. Together they completed **24 positive
browser logins and refreshes**, **eight tampered-JARM HTTP 400
rejections**, **80 successful signed UserInfo responses** and **72
native UserInfo HTTP 401 denials**. The denials comprise 24 DPoP misuse
requests, 24 mTLS misuse requests and 24 revoked-token requests. All
eight first-use replay controls returned HTTP 200. Each positive case
completed public connection resource use, introspection and revocation;
sender binding and refresh rotation were checked on both grants.

All four advanced stopped-app canaries and **3,952 report-mutation
controls** passed (988 per report). Serialized reports were
independently revalidated against the complete eight-case selection,
source revision, runtime lock, actual fixture input hashes,
sender/signature/resource/lifecycle observations, transport evidence and
cleanup. Removing the control results or changing one to false was also
rejected. All four runtime checkouts were clean.

| Runtime / transport | Eight-case loop seconds | Local sanitized evidence directory |
|----|---:|----|
| Windows / sync | 99.04 | `advanced-20261118-185929-1d129ddc66e9` |
| Windows / mirai | 115.38 | `advanced-20261118-190324-39b58e537a8a` |
| Linux / sync | 68.65 | `advanced-20261118-185937-5142681ec24e` |
| Linux / mirai | 76.81 | `advanced-20261118-190302-7f93dd694d96` |

The four baseline regressions also passed all sixteen login/refresh
flows, sixteen live missing-PKCE rejections, four stopped-app canaries
and 256 report-mutation controls. Their serialized reports received the
same independent revalidation, with clean checkouts:

| Runtime / transport | Four-case loop seconds | Local sanitized evidence directory |
|----|---:|----|
| Windows / sync | 41.47 | `basic-20261118-190744-cc0be7fbe64a` |
| Windows / mirai | 51.43 | `basic-20261118-190906-4547f4b223c2` |
| Linux / sync | 23.75 | `basic-20261118-190630-a8966c3c99ad` |
| Linux / mirai | 29.99 | `basic-20261118-190736-d80b894b307d` |

Windows used R 4.5.1, httr2 1.2.2 and mirai 2.7.1; Linux used R 4.5.0,
httr2 1.3.0 and mirai 2.7.4 inside Docker Desktop. Both used R openssl
2.6.0 and chromote 0.5.1, against the pinned Node 24.22.3 /
oidc-provider 9.14.0 runtime. All eight reports record the same fixture
input hashes and their actual immutable built image IDs. Case-loop
timings exclude installation, build, stopped-app controls and
report-mutation checks; concurrent runs shared host resources. Full
advanced gates took approximately 205-259 seconds.

The OIDF evidence regression passed **6,682 assertions on each
platform**, with zero test warnings or skips. The Linux/sync OIDF smoke
regression passed all three modules, the stopped-app control and
cleanup: `smoke-20261118-190929-f45cfc12aa58`. Its serialized report was
independently rechecked and sanitized. Node’s six fixture tests, Jarl, R
formatting, actionlint and patch whitespace checks passed. Only the nine
sanitized evidence JSON files were copied into the main checkout; keys,
client registrations, installed libraries and raw logs remain private.
No owned test containers remain. Hosted CI has not been run for this
selection. The resource-indicator follow-up is recorded below;
navigation retention remains pending.

C14 resource-indicator implementation (2026-11-18): a separate
`resources` selection adds native RFC 8707 behavior for two API
audiences and a rejected unknown resource. It uses confidential Basic
authentication, direct query authorization and S256. PAR is explicitly
disabled for this selection. Chrome must observe the exact resource
parameter in the outgoing request; native authorization, code and
refresh events must confirm the same indicator. Both APIs must obtain
their own audience and the resource-specific `api.read` scope through
the provider’s normal resource-indicator processing. Consent uses the
public Grant API for resource scopes; no protocol handler is patched.

Each positive case validates its ID token, uses `connection$request()`
at the selected API, refreshes the same connection and uses the
refreshed credential at that API. Native introspection confirms the
current token’s audience and scope before and after refresh. The
original validated identity must survive the native refresh response
without a replacement ID token. Native UserInfo is disabled because it
rejects API-audience tokens. The package’s scope policy remains enabled;
its warning about API access-token scope omitting OIDC/offline scopes is
expected here. The harness independently requires `api.read` and
validated ID-token identity.

The resource server is a development fixture on two HTTPS paths sharing
the provider’s origin. It checks opaque-token validity, audience and
scope through the provider’s public AccessToken/Grant model API. It is
not an independent resource-server product or a JWT access-token
verifier. Native provider handlers validate indicators and mint
audiences. A real token for the other API, absent credentials and an
invalid token must receive HTTP 401. The public connection must also
reject an escaped resource base locally, with no extra server request.
The unknown indicator must produce native `invalid_target` and the
matching client callback error before code or token issuance.

Each report requires all three browser cases, the stopped-app canary,
real sync/mirai exchange and refresh, owned-worker cleanup, complete
provider events, two authenticated resource reads and introspections per
positive case, and the three denial probes. Serialized reports and
altered evidence must also be checked; missing or false control results
cannot pass. Only sanitized evidence JSON is eligible for upload. Manual
workflow dispatch now offers `resources` alongside `basic` and
`advanced`; pull requests keep basic sync.

C14 still retains
[`oauth_connections_server()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_connections_server.md)
navigation retention. This resource selection does not cover other auth
methods, callback modes, multiple requested resources, JWT access
tokens, or indicators combined with JAR/PAR, DPoP or mTLS. These limits
are recorded with `coverage_complete = false`. Resource-indicator
validation (2026-11-18), source
`f2f78a2d502817522155837529683e7f4acbd155`: all four Windows/Linux
sync/mirai resource gates passed with clean checkouts. They completed
**eight positive logins and refreshes**, **sixteen authenticated API
reads**, **sixteen native introspections**, **24 resource HTTP 401
denials**, **eight local resource-base escape rejections** and **four
unknown-resource callback rejections** before code/token issuance. Every
authorization/code/refresh request used the expected resource; both
grants produced the selected audience and `api.read` scope.

All four stopped-app canaries and **948 altered-report controls** passed
(237 per resource report). Serialized reports were independently
rechecked against the complete selection, committed source, runtime
locks, actual fixture input hashes, identity/refresh evidence,
current-token use, transport and cleanup. Missing or false control
results were independently rejected too. The resource server returned
exactly the expected requests, including no extra request from the
locally blocked escape attempt.

| Runtime / transport | Three-case loop seconds | Local sanitized evidence directory |
|----|---:|----|
| Windows / sync | 32.16 | `resources-20261118-193706-6d7c07b36d9d` |
| Windows / mirai | 34.87 | `resources-20261118-193819-b1107faad01f` |
| Linux / sync | 18.29 | `resources-20261118-193713-274ae397ecc5` |
| Linux / mirai | 21.04 | `resources-20261118-193823-2c8682bdea6a` |

The full resource gates took approximately 64-74 seconds. Case-loop
timings exclude installation, build, stopped-app controls and
report-mutation checks; concurrent runs shared host resources. Windows
used R 4.5.1 and Linux used R 4.5.0 inside Docker Desktop. Reports
record their browser/dependency versions, the pinned Node 24.22.3 /
oidc-provider 9.14.0 runtime, actual built image IDs and fixture input
hashes.

The four baseline regression gates also passed all sixteen login/refresh
flows, sixteen missing-PKCE rejections, four stopped-app canaries and
256 altered-report controls, with clean checkouts:

| Runtime / transport | Four-case loop seconds | Local sanitized evidence directory |
|----|---:|----|
| Windows / sync | 39.76 | `basic-20261118-193930-7bff94e3cbee` |
| Windows / mirai | 47.45 | `basic-20261118-194047-72232dc7c8bb` |
| Linux / sync | 21.82 | `basic-20261118-193927-a8d50b7640b1` |
| Linux / mirai | 26.87 | `basic-20261118-194028-f1923d082616` |

The Linux/mirai advanced regression passed all six
login/refresh/resource flows, both tampered-JARM callbacks, its
stopped-app canary and 988 altered-report controls:
`advanced-20261118-194134-58089eecd536`, with a 66.37-second case loop
and clean checkout. All nine resource/baseline/advanced serialized
reports were independently revalidated against the same source and
current fixture bytes.

On each platform, the existing OIDF evidence regression passed **6,682
assertions**, and focused resource-indicator/binding tests passed **86
assertions**, with zero test warnings or skips. All seven Node fixture
tests, Jarl, formatting, actionlint and patch whitespace checks passed.
No owned test containers remain. Only sanitized evidence JSON is
eligible for workflow upload; temporary keys, registrations, libraries
and raw logs remain ignored locally. Hosted CI has not been run for this
new selection. Navigation retention is implemented in the follow-up
below.

C14 browser-retention implementation (2026-11-18): the `retention`
selection adds query and Form Post cases using
[`oauth_connections_server()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_connections_server.md)
against the unmodified pinned provider. A browser owner, one client and
the encrypted memory store persist outside the Shiny server function.
After native OIDC login the browser loads a second page and returns
through full document navigation. New Shiny sessions must restore the
same connection ID and validated identity in the same R process; each
session obtains a new connection reference. Four public resource
requests use native UserInfo, including before/after refresh and after
both navigations. The public
[`identity()`](https://rdrr.io/r/base/identity.html) API verifies
ID-token and UserInfo continuity, with only a salted identity digest
retained in reports.

Each case also opens a separate Chrome profile. That browser must have
no saved connection and must receive the typed unavailable-connection
error when probing the other owner’s ID. Local logout (`revoke = FALSE`,
`reload = FALSE`) must make the old R reference unusable and block token
export. After a full reload, the new empty owner must also reject the
old ID. The test makes no remote revocation claim for this action;
advanced interoperability covers revocation separately. Cookie evidence
requires one Secure, HttpOnly, SameSite=Lax owner cookie at the root
path, unavailable to JavaScript, without retaining its value.

Evidence requires exact native events: the missing-PKCE rejection, one
code exchange, one refresh and six successful current-token UserInfo
calls. This prevents a new authorization from substituting for
restoration. It also checks the complete snapshot sequence, new session
counters, stable app/process/ID, identity comparisons, live denial
outcomes and explicit cleanup. Every report has a stopped-managed-app
canary, altered-evidence checks and serialized report validation,
including rejection of missing or false control results. Form Post uses
the real POST and HTTP 303 bridge.

The selected sync/mirai transport handles exchange, refresh and
validated UserInfo. Explicit resource reads, owner checks and
memory-store updates stay in the main process. Both origins use HTTPS
localhost on different ports; cross-site cookie deployments, account
owners, expiry, multiple clients, sender-bound grants and process
restarts remain outside this selection. The existing synthetic retention
fixtures continue to cover their own scope. Manual dispatch now offers
`retention`, uploading only sanitized evidence JSON.

This implements C14’s final planned scenario; committed-source
validation is recorded below. The declared C13-C14 selections remain
scoped interoperability evidence with `coverage_complete = false`. C06
warm-cache, C09 public-client suite capability and C15 rejection-gap
review remain separate work.

C14 browser-retention validation (2026-11-18): all four Windows/Linux
and sync/mirai retention gates passed, followed by four baseline
regressions and one Linux/mirai resource-indicator regression. These are
**development results**, not a final release matrix. The steering
handoff at the top of this file was edited and committed while the runs
were in progress. Each report retains its actual source revision and
dirty flag; no flag was changed to make the matrix appear clean.

Sources in the table are `46078c618cd225e426f9e0ff264c3448cd24eca9`
(`46078c61`) and `434e59830c39ceeaa17df5a73b76683d671926fc`
(`434e5983`). The latter changes only this plan. Fixture input hashes
were unchanged across those commits. Windows used R 4.5.1 and Linux used
R 4.5.0 inside Docker Desktop. Each report records browser/dependency
versions, the pinned Node 24.22.3 / oidc-provider 9.14.0 runtime, built
image ID and fixture input hashes.

| Selection / runtime / transport | Case-loop seconds | Source | Dirty | Local sanitized evidence directory |
|----|---:|----|----|----|
| Retention / Windows / sync | 160.37 | `46078c61` | false | `retention-20261118-202723-8b65cdf5f597` |
| Retention / Linux / sync | 142.92 | `46078c61` | false | `retention-20261118-202727-961ee7b5266a` |
| Retention / Linux / mirai | 134.47 | `46078c61` | false | `retention-20261118-203045-0069d5dd283b` |
| Retention / Windows / mirai | 173.33 | `46078c61` | true | `retention-20261118-203103-24c5302c00de` |
| Basic / Linux / sync | 25.59 | `46078c61` | true | `basic-20261118-203352-5fdaf0f2533e` |
| Basic / Windows / sync | 50.94 | `46078c61` | true | `basic-20261118-203456-5f991fca9d9c` |
| Basic / Linux / mirai | 33.92 | `46078c61` | true | `basic-20261118-203503-1da30037ddf0` |
| Basic / Windows / mirai | 58.55 | `434e5983` | false | `basic-20261118-203628-b280140cf1ad` |
| Resources / Linux / mirai | 24.93 | `434e5983` | false | `resources-20261118-203628-89061f1fa120` |

The eight retention cases completed eight native OIDC logins and
refreshes, sixteen full-navigation restorations, 32 explicit
authenticated resource reads and 48 native UserInfo HTTP 200 responses.
They also verified eight normal-case missing-PKCE rejections, eight
foreign-owner denials, eight local logout retirements with blocked
stale-reference token exports, and eight post-logout old-ID denials.
Four cases used the real Form Post callback and HTTP 303 bridge. All
four stopped-managed-app canaries and **1,296 altered-report controls**
passed (324 per retention gate).

Baseline regressions passed sixteen login/refresh flows, sixteen
normal-case missing-PKCE rejections, four stopped-app canaries and 256
altered-report controls. The resource regression passed two positive
login/refresh flows, the unknown-resource rejection, four authenticated
reads and introspections, six HTTP 401 denials, two local resource-base
escape rejections, its stopped-app canary and 237 altered-report
controls. In total, the nine gates passed **1,789 altered-report
controls**. Serialized reports were independently rechecked with the
existing scenario validators, actual fixture bytes and the saved built
image-ID files; missing or false control results were rejected. This
does not close SA02’s source/acquisition-provenance work. Timings
exclude installation, build and report controls; concurrent jobs shared
host resources.

An earlier Linux/sync attempt at
`43dd6d80488bae74010e3759017034af068fdce6` timed out on the final
post-logout navigation, with no completed case rows:
`retention-20261118-200310-33b5e0bf3050`. It receives no coverage
credit. The fixture was rescanning a growing audit directory every 100
ms; on the Windows bind mount this starved Shiny’s HTTP handling after
owner retirement. `46078c61` caches sanitized audit observations per
session until a result or connection-state change. The browser still
performs full `Page.navigate` navigation, and no production package
behavior changed.

A subsequent review found that the Form Post navigation observer
remained live through logout, whose cookie-clearing redirect could mask
an incorrect initial bridge status.
`a3f0c9e8dcb965cf8c802e54fd65ecd5484961df` freezes the callback
observations immediately after login. A focused Linux/sync Form Post run
at that revision completed the full retention scenario; its saved row
passed strict scenario and sanitization checks, including the callback
POST and captured HTTP 303 evidence. The row is in
`retention-20261118-204133-e44fc19a603a`. This focused check is separate
from the nine-gate development matrix and is not a complete release
gate.

Before the fixture-only fixes, the OIDF evidence regression at
`43dd6d80` passed **6,682 assertions on each platform**, and
resource-indicator/binding tests passed **86 assertions on each
platform**, with zero test warnings or skips. Windows R still emitted
its existing startup locale warnings. Jarl, formatting, actionlint and
patch whitespace checks passed. No owned test containers remain. Raw
logs, keys and installed test libraries remain ignored; only sanitized
evidence JSON is eligible for workflow upload. Hosted CI was not run for
retention.

C14’s selected implementation is complete, with
`coverage_complete = false` and the deployment limits above. Follow the
steering handoff next: SA01-SA02 take priority before further feature
expansion. SA01-SA08 remain pending; release-source aggregation and
durable release evidence are still future work.

SA02 first implementation and validation (2026-11-18), source
`daae0a1649a6d69cd117a62a1054c307bfd6b5ed`: the report validator now
checks all three image references against the independently loaded suite
lock and the expected run context. Missing images, substituted
references and absent or invalid acquisition entries fail. The
`cached`/`pulled` acquisition entries and Boolean `checkout_dirty` must
equal their original context values. Changing the report and context
image references together still fails against the lock. Shared-pool
runners record this metadata before constructing the four client
selections; both the parent and each selection are checked. Historical
shared reports that lack per-selection provenance require a new run for
this validator.

All **6,808 evidence assertions passed on each platform**, including 126
new provenance assertions, with zero test failures, warnings or skips.
The existing Windows R startup locale warnings remain. The original
retained Message Signing report from SA02 still passes unchanged; each
of the review’s three individual mutations now returns both
`gate_passed = false` and `coverage_complete = false`. The two live
checks below also passed and their serialized reports were independently
revalidated with the known source revision, clean flag, locked images
and observed cached acquisition mode. Missing and substituted metadata
were rejected again, including inside all four shared-pool selections.

| Selection / runtime / transport | Normal cases | Case-loop seconds | Local sanitized evidence directory |
|----|---:|---:|----|
| Smoke / Windows / sync | 3 | 37.85 | `smoke-20261118-215640-ca571d49244e` |
| Shared pool / Linux / mirai | 8 | 47.29 | `shared-pool-20261118-205810-694254d0fbdd` |

Both reports identify the same clean source above, pass the real
app-failure control and verify cleanup. Each complete command took
approximately 206 seconds, including regression tests, installation and
startup; concurrent jobs shared host resources. Both retain
`coverage_complete = false`. Jarl, formatting and patch whitespace
checks passed, and no owned test containers remain. These are local
development checks; hosted CI was not run for this change. SA02 remains
partial: uncommitted source-content identity, its link to the installed
package and release-source enforcement remain pending. Dirty development
runs remain allowed when their metadata matches the expected context.

SA01 candidate investigation (2026-11-18): the old server digest still
returns HTTP 404 after successful anonymous registry authentication. The
official `release-v5.3.4` multi-platform index is available at
`sha256:dcc4bd1fb7e9c00f048a67373fe2bec5ecf9feb45a6b5d55e237e5c30e5312c6`.
It was pulled explicitly by digest, then checked through Docker
`RepoDigests` and the jar’s embedded `git.properties`. The jar
identifies clean source `23353b36957d6466010de767c812d2c91ed37638` with
description `release-v5.3.4`, matching the official source tag. No
replacement suite or client flow was run. The committed lock remains
unchanged. Next, compare the candidate’s complete plan/module/variant
lists and relevant source changes before an explicit lock update; fresh
GitHub acquisition, preflight, API, browser smoke and larger-job timings
remain SA01 acceptance work.

SA01 reviewed lock implementation (2026-11-18), harness source
`65fbdc8e49d70e85f99cbccc527428c91a785992`: both old GitLab digests
proved unavailable, including the proxy. The lock now pins the official
`release-v5.3.4` server and proxy indices; MongoDB’s available digest is
retained. The [release
review](https://lukakoning.github.io/integration/openid/release-review.md)
records both new digests, the exact clean suite source, the 47-commit
source comparison and the unchanged module/variant mapping for all 17
declared selections. The public API check now verifies all 15 plan
configurations, including one live combined- variant/issuer probe and
cancellation per configuration. Those interrupted probes receive no
client-coverage credit.

Local preflight and API checks passed. At the clean harness source
above, Windows/sync Configuration passed all six cases, and Linux/mirai
Message Signing passed all 29 modules. Evidence regression checks passed
6,808 assertions on each platform. Serialized reports were independently
checked against the new lock. Configuration retains its `no-store`
warm-cache limitation. The initial Message Signing attempt remains
failed after a Chrome startup timeout; the release review preserves its
identity and the successful complete rerun. Environment/API reports
currently omit checkout-identity fields; their local execution context
is documented without inventing report fields. SA02 source identity and
SA08 release aggregation remain pending.

Fresh hosted smoke was dispatched at that exact commit: [run
44399653873](https://github.com/lukakoning/shinyOAuth/actions/runs/44399653873).
Its complete preflight/API/browser sequence passed. The downloaded
archive’s SHA-256 matched GitHub’s artifact digest, and its preflight
records all three images as `pulled`. The client report matched the new
lock and clean harness source. The job took 729 seconds, including 422
seconds of dependency setup; the three-case browser loop took 19.85
seconds. Queue time was another 550 seconds. Hosted Basic
[44403591230](https://github.com/lukakoning/shinyOAuth/actions/runs/44403591230)
and Message Signing
[44403727783](https://github.com/lukakoning/shinyOAuth/actions/runs/44403727783)
also passed at that same clean source. Basic completed all fourteen
cases (thirteen suite `PASSED` verdicts and the documented
unsigned-token `SKIPPED` outcome); Message Signing completed all 29 with
suite `PASSED`. Both preflights record all three images as `pulled`,
both API inventories cover all 15 plan configurations, and both
downloaded ZIP hashes matched GitHub’s artifact digests. Their
serialized reports were independently revalidated against the lock and
known harness source. Basic took 412 seconds overall with an
81.44-second module loop; Message Signing took 581 seconds overall with
a 245.08-second loop. SA01’s reproducibility and selected timing
acceptance is complete. These initial measurements support retaining PR
smoke and manual larger selections while SA08 retains the final release
matrix and durable evidence work. SA02 source identity is next;
SA03-SA08 retain their existing status. Only sanitized evidence JSON is
eligible for upload; raw diagnostics and test credentials remain ignored
locally.

SA02 source/installation acceptance (2026-11-18), source
`8d2ec4d90e9645f546f2186f9bb6f0acd3fa2b6f`: schema-4 client reports now
bind source snapshots, exact installation archives and installed-file
hashes to the run. Clean installs use a canonical Git archive of the
selected commit; dirty development installs retain their private built
input and remain ineligible for release evidence. The release-source CLI
independently regenerates the expected commit archive and rejects dirty,
old-schema, mixed or incomplete source proof. The workflow runs it
against `GITHUB_SHA`. Preflight/API reports now record before/after
checkout identity too. See [source
identity](https://lukakoning.github.io/integration/openid/source-identity.md).

All 6,938 evidence assertions passed on Windows and Linux, including 130
new source checks. Windows smoke and Linux/mirai shared-pool scenarios
passed with the same archive hash and clean source. Saved installations
and serialized reports were independently rechecked; missing/altered
records and mixed revisions were rejected. Earlier schema-3 reports
still pass historical scenario checks and fail the new release-source
check. An initial cross-Git configuration failure exposed CRLF/LF
archive differences; the accepted producer forces LF. The earlier
development records retain their original fields and are described in
the source identity record.

Hosted [run
44412596895](https://github.com/lukakoning/shinyOAuth/actions/runs/44412596895)
passed preflight, all 15 API inventories, browser smoke and the new
source gate at that exact clean commit. All three source snapshots
match; its installation archive hash matches Windows and Linux. The
downloaded ZIP matched GitHub’s artifact digest, and its source proof
passed independent Windows revalidation. The hosted job took 397
seconds, including a 20.91-second browser case loop. An independent
agent review found no actionable SA02 defects. SA02 acceptance is
complete for the OIDF harness. SA08 retains full matrix completeness,
other integration layers and durable release evidence. SA04 requirement
mapping and SA06’s Keycloak warm-cache follow-up are being implemented
separately.

SA04 FAPI map and candidate-selection regression (2026-11-19):
[requirements.md](https://lukakoning.github.io/integration/openid/requirements.md)
now maps all 20 numbered FAPI 2.0 Security Profile client clauses, the
client clock note and relevant network/cryptography clauses to
responsible roles, selected configurations, implementation/test
references and remaining limits. It keeps deployment and AS/RS duties
separate from client behavior. The map explicitly records that
`id_token_profile = "fapi2"` is an ID-token policy rather than a
complete FAPI preset, that issuer-string assertion audiences need
explicit configuration, and that ES256 live coverage does not establish
PS256 or RS256 FAPI coverage. Initiation consent, alias-only mTLS
ecosystems, callback-error URL cleanup and source-qualified lifecycle
evidence retain named follow-up work. SA04 remains partial until the
OIDC/OAuth and Message Signing maps are complete.

The map identified a missing mixed same-`kid` candidate combination. A
new regression in
[test-jwks.R](https://lukakoning.github.io/tests/testthat/test-jwks.R)
uses real ES256 signatures with mixed RSA/EC keys, algorithms, uses and
operations. It verifies both candidate orders, an eligible
wrong-signature key before the actual signer, failure without an
eligible signer, and compatible keys with omitted `alg`. Its 15 new
assertions passed; the full JWKS file passed 66 assertions on each of
Windows R 4.5.1 and Linux R 4.5.0, with no failures, test warnings or
skips. Formatting and jarl checks passed. These are focused development
regressions, not a new source-qualified conformance matrix or
certification result. Runtime package behavior is unchanged.

SA06 Keycloak rotation evidence correction (2026-11-19): the original
pinned Keycloak 26.6.1 `start-dev` fixture returns
`Cache-Control: no-cache`, so the earlier two-login test could not
establish a warm cache. The strengthened [rotation
test](https://lukakoning.github.io/integration/keycloak/test_integration_keycloak_jwks_rotation.R)
observes the actual response header, exactly three JWKS downloads across
three authenticated module logins, stale cache metadata, stable
cache/key identity, the new key’s absence before rotation and successful
validation afterward. It retains the rogue-signature rejection controls
for both old and new key IDs. Required dependency/admin/server setup
failures now fail rather than skip.

The focused Windows run passed all 40 assertions, with zero failures,
skips or test warnings. R startup retained the existing locale warnings.
It tested source `d4e6d1275a5858f70741c44fd75e34baff3e895a` with the
rotation test and concurrent mixed-JWKS/requirement-map changes recorded
as dirty. The tested rotation file’s SHA-256 was
`d212ee9000977071a7faa5dfb9ff825932592504cef760af28a5110052d16986`; the
installed-package results, observed header and pinned image receipt
remain in ignored local evidence. Formatting, jarl and whitespace checks
passed; a separate agent review found no actionable issues in either new
test.

Attempts with supported theme cache settings and a non-development
server command still returned `no-cache` in this environment. They did
not establish cacheability, and the original Compose configuration was
restored exactly. Provider headers and client TTLs were not rewritten.
The owned test stack was removed. This is development
revalidation/rotation evidence; C06 remains open until a real
cacheable-provider test proves a pre-rotation cache hit and unknown-key
refresh from that still-fresh entry. SA06’s remaining status
reconciliation is separate from this correction.

SA05 independent completion accounting (2026-11-19): client and
shared-pool checks now return `upstream_plan_complete` separately from
the existing `selection_complete` and conservative `coverage_complete`.
The new assessment counts available/selected/finished modules, preserves
raw verdict counts and lists each accepted non-passing module with its
exact policy. It categorizes selection scope, interoperability
advisories, provider limitations and client limitations. Unsigned
TLS-discovered metadata is a scope description; the state-length warning
remains an advisory; mTLS simulation/registration limits remain
provider-evidence limits. The unsigned-ID-token `SKIPPED` result retains
its stricter local policy and rejection proof.

No verdict allowlist or protocol evidence requirement was broadened.
Assessment runs after the full existing gate, recomputes stored
summaries, rejects unclassified limitation codes and resets completion
on failure. Shared totals come from individually revalidated selections.
Certification is always `not_assessed`; source qualification and release
completeness remain separate. See [interpreting client
evidence](https://lukakoning.github.io/integration/openid/assessment.md).

All 7,059 evidence assertions passed on Windows R 4.5.1 and Linux R
4.5.0, including 121 new assessment assertions; there were no failures,
test warnings or skips. R startup retained the known Windows locale
warnings. Formatting, jarl and independent code review found no
actionable defects. Genuine retained schema-3 Basic/Configuration and
schema-4 smoke/shared-pool reports passed revalidation with the new
accounting: Basic and Configuration establish full upstream module
execution, smoke and shared-pool do not. Their original files were
hash-checked unchanged; derived assessments were saved separately.
Removing a case while forging passing summary fields failed
revalidation. These checks are development acceptance of the report
semantics, not new live client runs or a complete source-qualified
release matrix.

SA04 companion requirement maps (2026-11-19): three maps now accompany
the FAPI Security Profile page. The [OIDC
map](https://lukakoning.github.io/integration/openid/requirements-oidc.md)
accounts for Discovery, code requests/callbacks, all 13 ID-token
validation steps, UserInfo and the eight refresh response conditions.
The [OAuth
map](https://lukakoning.github.io/integration/openid/requirements-oauth.md)
indexes code/refresh, authentication/errors, bearer transport, S256, RFC
8414 and RFC 9207, with partial PAR/mTLS/DPoP/resource-indicator
extension accounting. The [JWT/Message Signing
map](https://lukakoning.github.io/integration/openid/requirements-jwt-signing.md)
accounts for final Message Signing client clauses, JAR, JARM and all 12
JWT BCP sections. Each links concrete code/assertion definitions and
separates client, AS/RS, application and deployment duties, unsupported
options and retained live evidence. The maps do not turn historical
results into a source-qualified release matrix or establish
certification.

All 286 local link occurrences across the four requirement maps
resolved; the three investigations also checked their official
specification anchors. The maps identify focused gaps, including Unicode
comparison, encrypted JARM inner-signature rejection, JWT cross-purpose
substitution and Message Signing profile boundaries. The OAuth
investigation reproduced case folding of provider-advertised
authentication/PKCE method identifiers; MD04 names that runtime defect
separately from the evidence-only gaps. Its narrow fix follows as a
separate implementation change. SA04 remains partial until remaining
OAuth grant/authentication/extension/security-clause accounting is
finished.

SA06 milestone reconciliation (2026-11-19): the current table and
opening status now include completed mTLS, Message Signing and
second-provider work. C13’s public registrations exercise discovered
`none` authentication, browser S256 code login, validated ID tokens,
UserInfo and refresh in query/Form Post and sync/mirai configurations;
its live missing-challenge request is rejected before code issuance.
This closes C09’s overlapping public discovery/S256 interoperability
baseline. It does not supply a missing OIDF public-client verdict or
complete that comprehensive-plan variant. The pinned variant’s metadata
limitation remains explicit rather than hiding the C13 evidence. C10 now
records both full OAuth selections, including the all-`PASSED`
reference-state path, without treating the encrypted-state advisory as
an unqualified client nonconformance. The scope table and CLI alias note
were updated to match implemented selections. C06’s genuine warm-cache
follow-up remains open with its observed provider-cache limits.

SA04 metadata comparison correction (2026-11-19): the OAuth requirement
audit reproduced incorrect case folding of advertised
client-authentication and PKCE method names through the public discovery
constructors. Four substitutions in `providers__oidc_discovery.R` now
retain those wire identifiers’ exact case, while keeping caller-option
normalization. Wrong-case-only metadata fails; mixed arrays can select
an exactly supported method; explicit plain PKCE requires advertised
lowercase `plain` and is never selected as a silent downgrade. The NEWS
entry and OAuth map describe the changed behavior.

The new public OAuth/OIDC regression matrix has 94 assertions; 46 failed
before the correction. All 873 discovery assertions passed on Windows
and Linux with zero failures, skips or test warnings. The initial Linux
run lacked the test-only `webfakes` prerequisite and recorded 36 skips;
a private ignored validation library supplied it for the accepted rerun.
No package dependency or container image changed. Windows retained its
four known R startup locale warnings. Windows used parent `46d65458` and
Linux `543113fb`, both with the recorded working changes; neither is a
clean-source release run. Formatting, jarl and independent review
passed. The four-line runtime patch stays limited to
authentication/PKCE; response-mode metadata folding is a separate named
audit/fix follow-up. These are development regressions, not new OIDF
module results or a complete metadata-field compliance claim.

SA04 JWT regression G1 (2026-11-19): the new encrypted-JARM regression
covers both `query.jwt` module callbacks and the `form_post.jwt`
admission bridge. It encrypts a correctly formed inner response whose
real RS256 signature has one altered byte, or whose inner
algorithm/signature has been changed to `none`. Each case first proves
successful authenticated outer decryption, then requires the specific
inner rejection, no authenticated session/token, zero token-endpoint
HTTP calls and the exact pending state record/keys unchanged. The
original correctly signed response then completes one exchange and
consumes that same state. The 68 new assertions exercise actual
decryption, JWKS selection, signature verification and module/bridge
handling; only HTTP responses are stubbed. This is unit/module coverage
with an explicit browser-marker bypass, not a real browser or encrypted
OIDF profile result. No runtime defect was found.

The new cases plus existing JARM response/compression regressions passed
864 assertions on each of Windows and Linux, including the 68 new
assertions, with zero failures, test warnings or skips. The first Linux
check correctly failed its zero-skip requirement when an existing
Ed25519 case lacked optional `sodium`; the accepted disposable container
supplied the system library and private R package without changing the
base image or package dependencies. Formatting, jarl, whitespace and
independent review passed. G1 is complete as a focused regression; G2-G4
and the broader source-qualified release matrix remain open.

SA04 JWT regression G4 (2026-11-19): a new real-signature corpus
exercises ID-token/JARM module callbacks and public signed-UserInfo
retrieval. Eight cases per context include ordinary signed positives,
valid optional `jku`/`x5u` headers, attacker-signed JWTs pointing to
attacker keys, unmatched SQL/path-shaped key IDs and correctly
registered literal unusual-key-ID positives. The only mock is
[`httr2::req_perform()`](https://httr2.r-lib.org/reference/req_perform.html);
every HTTP destination is recorded, and attacker locations would supply
matching attacker keys if requested. No header-selected location is
contacted. Trusted provider JWKS still supplies the verification keys,
unknown IDs fail and registered literal IDs remain usable.

Rejected JARM keeps the pending state and makes no token request.
Rejected ID tokens stop UserInfo/authentication after the required token
response. Invalid signed UserInfo returns no claims. Windows and Linux
each passed 274 focused locator/JWKS/JOSE assertions, including 171 new
assertions, with zero failures, test warnings or skips; formatting, jarl
and whitespace checks passed. Private result CSVs/RDS remain under
ignored `codex/jwt-untrusted-locators/`. This is unit/module evidence
with an explicit browser-marker bypass, not a browser, filesystem/SQL
audit or new OIDF execution. No runtime defect was found. G1/G4 are now
covered; G2/G3 and the complete source-qualified release matrix remain
open.

SA04 response-mode comparison correction (2026-11-19): discovery and
both provider construction/validation paths now preserve advertised
response-mode strings exactly, as do request selection and provider
policy fingerprints. Uppercase or padded values cannot authorize a
canonical mode; exact matches in mixed arrays still work. Caller-option
normalization, omitted discovery query/fragment defaults, generic
unknown-capability behavior and distinct outbound `jwt`/`query.jwt`
checks remain. Whitespace-only capabilities still fail validation. The
NEWS entry, provider documentation and OAuth map describe the narrowed
behavior.

The new 182-assertion regression covers OAuth/OIDC discovery, both
manual constructors, S7 mutations, implicit query and actual callback
recovery under encrypted/reference state. A changed capability rejects
before any token HTTP request and preserves the pending record; the
original client then exchanges once. Case/whitespace affect the
fingerprint, while order/duplicates do not. All 2,933 targeted
discovery/response-mode/state/callback/JARM/provider/worker assertions
passed on Windows and Linux with zero failures, test warnings or skips.
Jarl, whitespace and independent review passed; the new test is
formatted.

Initial broader attempts exposed validation prerequisites: Windows
`future` 1.70.0 had been built under R 4.5.3, and the Linux subprocess
lacked an installed package. Accepted checks used the same future
version rebuilt from the official CRAN archive in a private Windows
library, plus a private Linux installation of this working source and
its existing optional test dependencies. No package dependency or base
image changed, and warnings were not suppressed. Initial results remain
separately under ignored `codex/response-mode-case/`; Windows retains
the known R startup locale messages. These are development checks, not a
new OIDF browser run or complete source-qualified release matrix.

SA04 PAR and JWT-authentication map (2026-11-19): the new [direct-clause
map](https://lukakoning.github.io/integration/openid/requirements-par-auth.md)
accounts for eight grouped PAR and nine JWT client-authentication duties
from RFC 9126, RFC 7521 and RFC 7523. It links actual
construction/validation assertions, transport/signature collectors and
retained reports, distinguishing client, assertion-producer, AS and
operator duties. Request Objects and authentication assertions remain
distinct JWT purposes. Unsupported assertion grants/SAML, third-party
issuance, registration/deployment obligations and complete inherited
crypto/security audits remain explicit. Mapping a duty does not
establish a new execution or close the overall SA04/release matrix.

That audit identified a concrete independent-fixture error: invalid
client assertions reached the generic `invalid_request` handler. The
strict AS now classifies assertion parsing/claim failures, invalid
signatures and competing credentials as `invalid_client`, with a
specific signature reason. The assertion-profile rule in RFC 7521
section 4.2.1 is kept distinct from generic OAuth error wording. Request
Object and unrelated grant processing stay outside the authentication
boundary; the existing unknown-code `invalid_request` / `invalid_code`
behavior is explicitly retained as a separate fixture limitation.

The new real-HTTPS regression deliberately expires correctly signed
RS256 and RS384 client-authentication assertions at PAR and token
endpoints, verifies the signatures independently, and checks exact
denial bodies/headers. Failed PAR registers no pending state or usable
reference; failed token exchange consumes the callback state and blocks
replay without another request. Neither path retains an authenticated
token or connection. Fresh assertions and a new public preparation then
succeed against the same server. Separate controls cover invalid
signatures, competing nonempty credentials, expired Request Objects and
unknown codes.

Windows and Linux each passed 111 assertions across five focused cases,
with zero failures, errors, test warnings or skips. They used private
installations of dirty source
`d287b56f763fd8331c9978d5068adb9ac544e3d6`; Windows retained its known R
startup locale warnings. The initial protocol reproduction had five
expected expiry/signature classification failures with successful fresh
controls. Accepted results and earlier harness diagnostics remain
separately under ignored `codex/client-assertion-expiry/`. Python
syntax, air, jarl, whitespace and independent review passed; the new
map’s 45 local links and 41 official RFC anchors were checked.
Disposable servers/container were removed. This is in-process
module/independent-fixture evidence with simulated fresh cookie
acknowledgement, not a real-browser, worker, hosted-suite or
source-qualified release result. Overall SA04 and SA08 remain open.

SA04 Unicode comparison regression (2026-11-19): strict requested-claim
checks now have explicit composed/decomposed and case-sensitive Unicode
controls for ID-token and UserInfo targets, with scalar `value` and
array `values` policies. Literal UTF-8 JSON and JSON escapes
representing the same code points match; canonically equivalent
different sequences remain unequal. The test uses the standard free-text
`name` claim, not a non-ASCII client identifier. It exercises normal
selected claim policy after JSON parsing without claiming all
identifier, metadata, signature or browser behavior. No runtime defect
was found.

All 115 focused claim assertions passed on Windows and Linux, including
40 new assertions, with zero failures, test warnings or skips. Jarl and
formatting passed. Docker Desktop was restarted for the Linux check; Git
trust was limited to the mounted workspace in that container, without
global configuration changes. Existing strict essential-claim tests
already cover requested `auth_time` absence/presence, so that suggested
duplicate was removed from the OIDC map. This remains development
regression evidence, not a new conformance run or source-qualified
release matrix.

SA04 PAR transaction freshness (2026-11-19): two successful public
preparations for the same client now have explicit regression coverage
with both encrypted and reference state. Normal request
construction/response validation and state storage run; only the HTTP
response boundary is stubbed. Two actual PAR request objects are
required, each browser URL selects its own returned reference and
contains exactly one client ID and one request URI, and no
credential/pushed transaction fields enter that minimal front channel.
Independently recomputed S256 challenges match the retained verifiers.
State, nonce and PKCE values are fresh, while the first distinct pending
record remains unchanged after the second preparation.

Windows and Linux each passed 758 relevant PAR/state/callback
assertions, including 136 new assertions, with zero failures, test
warnings or skips. Formatting, whitespace, local links and independent
review passed. Results and development-source snapshots remain under
ignored `codex/par-transaction-freshness/`. PA6’s proposed
normal-preparation regression is now covered. This proves the client’s
preparation/data-retention behavior; it does not establish AS reference
entropy or single-use denial, TLS, a browser flow, formal certification
or source-qualified release completeness. No runtime defect or
production code change was needed.

SA04 sender-constraint/resource client map (2026-11-19):
[requirements-sender-constraints.md](https://lukakoning.github.io/integration/openid/requirements-sender-constraints.md)
accounts for directly applicable RFC 8705, RFC 9449 and RFC 8707 client
duties and their conditional security provisions. It separates mTLS
authentication, token binding and endpoint aliases; DPoP proof/nonces
from client authentication; and resource signaling from AS/RS audience
enforcement. It links concrete assertions and historical
enforcing-provider records, including target-specific resource
contracts, while keeping Microsoft-mode behavior separate. No new
fixture run or broad compliance claim follows from writing the map.

All 51 local links and 61 official RFC anchors were checked. A suspected
DPoP metadata-folding issue was ruled out: the existing case-sensitive
JOSE guard runs before internal normalization. A public-constructor
regression for that already implemented guard remains a narrow coverage
candidate. Alias-only mTLS, selected PKI/self-signed/revocation/refresh
profiles, additional resource combinations and complete
inherited-security/deployment audits remain explicit limits. SA04 and
the source-qualified release matrix remain open.

SA04 JWT purpose corpus G2 (2026-11-19): the new corpus reuses identical
real RS256 JWTs across ID-token, JARM and public signed-UserInfo
receivers with one trusted issuer/key/client audience. Forty-eight
receiver cells cover native shapes and absent/generic/profile-specific
types. Actual module/public-API controls separately exercise login
nonce, JARM state/shape and a cryptographically validated ID-token
subject baseline. HTTP is the only substituted boundary.

The corpus records accepted nonce-free ID-token/UserInfo shape overlap,
rather than treating every substitution as a mandatory failure.
Same-subject binding does not identify JWT purpose. Tested nonce-bound
callbacks reject missing or other-transaction nonces before
UserInfo/authentication; ordinary ID/UserInfo shapes fail JARM before
token traffic or state consumption; subject swaps fail the public
UserInfo binding check. These outcomes do not establish attacker control
of a trusted endpoint, an exploit or unconditional mutually exclusive
validation for every extended claim set. No default or production code
changed; broader purpose-policy claims still need a reviewed
OP/RP/deployment contract.

Windows and Linux each passed 482 focused purpose/locator/type/subject
assertions, including 238 new assertions, with zero failures, errors,
test warnings or skips. Formatting, jarl, whitespace, local links and
independent review passed. Results remain under ignored
`codex/jwt-purpose-separation/`. G2’s corpus is implemented with its
purpose-policy assessment explicitly limited; G3 and the overall
SA04/source-qualified release work remain open.

SA04 Message Signing configuration G3 (2026-11-19):
[helper-configuration.R](https://lukakoning.github.io/integration/openid/helper-configuration.R)
now assesses the named OIDC/private-key-JWT/ES256/DPoP/`jwt` selection.
Both fixture subprocess startup paths source the helper; the Message
Signing client is checked before authorization. The result contains only
named boolean checks, stable issue IDs, selected policies and explicit
unassessed limits, with `certification_status = "not_assessed"`. The
[configuration
example](https://lukakoning.github.io/integration/openid/configuration.md)
distinguishes these integration settings from the package’s general
defaults.

The guard covers S256, nonce/ID-token validation, independent UserInfo
signing policy, TLS/unsafe options, reference state, PAR/JAR/JARM and
the effective token/PAR authentication algorithms and issuer audiences.
Real ES256 Request Objects produced by public preparation APIs pass at
TTL/skew pairs 45/0, 3600/0 and 45/3555. Omitted `nbf`, excessive skew
and an `exp - nbf` window over 3,600 seconds fail before HTTP or state
writes. General OAuth/JAR timing defaults and valid broader
configurations remain available.

Independent review identified an alias-selection corner case: additional
mTLS intent can select endpoints outside the checked base HTTPS URLs.
The named DPoP-only assessment now uses the runtime predicate on the
client and resolved token/PAR authentication clients to reject that
intent. Regressions demonstrate actual alias resolution for
generic-valid mixed clients and PAR mTLS overrides, no HTTP/state
changes on rejection, and acceptance of inactive aliases and unused
certificate material. Review of the correction and startup/source hooks
found no further actionable issue.

Windows and Linux each passed 249 new configuration assertions and the
full 7,308-assertion integration evidence regression suite with zero
failures, errors, test warnings or skips. Formatting, jarl, whitespace
and all 85 local links in the touched environment documents passed.
Evidence is retained under ignored `codex/g3-configuration/` and
`codex/message-signing-configuration/`; the earlier pre-alias-review
runs are preserved separately. These are dirty development-checkout
results, including unrelated DESCRIPTION/NEWS edits. Hosted runtime
validation is the next check. G3’s local configuration scope is
implemented; G2’s purpose-policy limits, overall SA04 and the complete
source-qualified release matrix remain open.

SA04 public DPoP discovery case regression (2026-11-19):
[test-discovery-dpop-case.R](https://lukakoning.github.io/tests/testthat/test-discovery-dpop-case.R)
closes the constructor-level follow-up identified by the
sender-constraint map. Both exported OAuth and OIDC discovery APIs run
their actual request, JSON parsing and metadata validation. Invalid or
mixed canonical/invalid ES256/EdDSA/Ed25519 spelling must produce the
specific parse error without returning a provider; canonical controls
preserve the existing internal capabilities. Only HTTP responses are
replaced, and each case requires exactly its expected discovery URL with
no fallback, retry or JWKS request.

Windows and Linux each passed 128 new assertions and 475 scoped
discovery assertions across six files, with zero failures, errors, test
warnings or skips. Before/after and cross-platform hashes of the
selected runtime/helpers/tests matched. Formatting, whitespace and
independent review passed. Ignored evidence is under
`codex/discovery-dpop-case/`; the tested checkout was development source
at `f9056d9b12fd8f11e24eacfcb2c1317ac9b8261b`. No production behavior
changed, and these regressions do not add a live-provider or
release-matrix claim.

SA04 OAuth security map, first slice (2026-11-19):
[requirements-security.md](https://lukakoning.github.io/integration/openid/requirements-security.md)
accounts for RFC 9700 sections 2.1–2.2 and 4.2–4.8 through eight
reusable implementation/test evidence entries and fifteen clause/role
rows. It adds threat-specific accounting to the existing OAuth/extension
maps: redirect and transaction integrity, token replay, referrer/history
disclosure, pre-redemption issuer/route defenses, code/access-token
injection, nonce ordering, CSRF and PKCE downgrade. The other RFC
sections remain named pending audit work.

Independent review corrected one evidence conflation: the linked
Keycloak missing-verifier case fails locally before exchange; only its
wrong-verifier case supplies AS denial. The map also preserves
malformed-callback query cleanup, initiation consent and HTTPS
cross-site/deployment gaps. It does not infer server replay/PKCE
enforcement from client request construction, or unconditional
JWT-purpose separation from nonce/subject checks. All 36 distinct local
links and 30 distinct official RFC links/anchors passed author and
independent checks. This is a source/test audit at `f9056d9b`, with no
runtime change or new execution credit. SA04 and SA08 remain incomplete.

Regression installation boundary correction (2026-11-19): the first
clean local Message Signing attempt at `f9056d9b` stopped before browser
setup. G3’s public-API checks ran before the runner installed its
checkout copy and therefore found the machine’s unrelated `0.6.1.9000`
package, which lacks `state_transport`. That failed
`application_flow = "not_attempted"` report is retained and receives no
conformance credit. Earlier pkgload-based development checks and CI’s
explicit `local::.` dependency installation did not expose this local
namespace boundary.

`run-tests.R` now installs the source archive before regression checks
in both API and client modes. `openid_use_installation()` validates the
installed inventory, explicitly loads its namespace and checks its
normalized path. It rejects an unrelated already-loaded namespace with
fresh-Rscript guidance before changing library precedence; it never
unloads caller state. The checks compare source and installation
inventories afterward, and client execution reuses that same
installation. `run-shared-pool.R` applies equivalent ordering and
guards. API reports retain no client-flow/conformance credit.

Twelve new assertions use real minimal package archives and fresh R
processes to test stale search precedence, repeated private selection,
preloaded-stale rejection without unloading/library changes and an
altered installation record. Windows and Linux each passed all 7,320
evidence assertions with zero failures, errors, test warnings or skips
from actual private checkout installations, without pkgload.
Per-platform source and installation records matched exactly
before/after; both platforms recorded the same dirty-source fingerprint.
Formatting, jarl, whitespace and independent review passed. The accepted
development evidence is under ignored
`codex/openid-installation/*-full-final/`. Preliminary runs rejected by
the source guard after concurrent documentation edits remain preserved
and are excluded from acceptance. Clean client/API and shared-pool
entrypoint validation follows at the committed correction.

G3 clean hosted Message Signing acceptance (2026-11-19): [run
44568024103](https://github.com/lukakoning/shinyOAuth/actions/runs/44568024103)
passed all 29 Message Signing/sync modules at clean source
`f9056d9b12fd8f11e24eacfcb2c1317ac9b8261b`. Fresh pinned-image
acquisition, TLS, all fifteen API inventories, application/module
evidence and cleanup passed. Preflight/API/client source records
matched; the client installation matched the independently regenerated
commit archive. The downloaded ZIP’s SHA-256 matched GitHub metadata,
and independent local report revalidation and the release-source CLI
passed. The module loop took 222.62 seconds; the job took 610 seconds
after 979 seconds in queue. Exact archive/artifact hashes and phase
timings are recorded in the [release
review](https://lukakoning.github.io/integration/openid/release-review.md).

This run validates the named configuration guard and fixture integration
at its recorded source. It does not retrospectively cover the later
namespace correction at `be2abdbc`, or combine different revisions into
an SA08 matrix. The corrected clean API entrypoint has also passed;
corrected clean client/shared-pool acceptance is recorded below. G2’s
compatibility limits, remaining SA04 audit sections and SA08
aggregate/durable release evidence remain open.

Clean regression-namespace correction acceptance (2026-11-19): fresh
actual entrypoints at `be2abdbc75acef61aa4f5141c9c5b41d97fa5dfd` passed
from detached clean Windows worktrees while the machine’s old
`0.6.1.9000` package remained unchanged. Message Signing/sync passed all
29 modules (306.94-second loop). API passed all fifteen
inventories/probes while retaining no client-flow credit.
Shared-pool/mirai passed four selections/eight modules, verified workers
and cleanup (47.53-second loop). Both commands’ regression checks used
their own verified private archive installation; no pkgload was used.

All three source and actual 39-file installation inventories were
independently checked against their receipts.
Initial/post-regression/final records match where recorded; shared-pool
enforces the post-regression comparison and keeps matching initial/final
records in its selections. The canonical archive hashes match across
entrypoints. The release-source CLI accepted the two client reports
together at the selected commit/tree/archive and rejected the API
report. The owned Docker projects are gone, and clean worktree status
remains unchanged. The [source
policy](https://lukakoning.github.io/integration/openid/source-identity.md)
records the exact archive identity, paths, preserved failed attempt and
scope.

Independent hosted/local review also verified actual module/variant
inventory, signed exchange/JARM rejection evidence and source bytes.
Windows clean snapshots use CRLF while the canonical archive uses LF;
each snapshot must validate internally. Future cross-platform SA08
aggregation must compare the selected commit/tree/canonical archive
rather than requiring identical raw working-tree fingerprints across
OSes. The hosted `f9056d9b` selection stays separate from these
`be2abdbc` results. No mixed-revision or complete-matrix claim follows;
remaining RFC 9700 sections, SA07 browser work and SA08
aggregation/durable retention remain open.

Add the OpenID Foundation (OIDF) Relying Party tests first. Once that
gate works, extend it to FAPI 2.0, then add `oidc-provider` for
interoperability with a second full provider. Add another mock server
only when a remaining test case justifies its maintenance cost. The
ranking below reflects the gaps in this repository; it is an engineering
assessment, not a benchmark of the tools.

**Starting point.** Keep the existing test layers and their stated
limits.

| Existing layer | What it contributes | Limit relevant to this work |
|----|----|----|
| [`tests/testthat/`](https://lukakoning.github.io/tests/testthat/) and the browser runner | Local validation, parsers, state, callbacks, browser binding and regression tests | Package-owned fixtures share assumptions with the implementation. |
| [Keycloak](https://lukakoning.github.io/integration/keycloak/README.md) | Full provider and browser interoperability, including attack cases | Its documented rejection canaries and accepted invalid JAR claims leave gaps in successful advanced combinations. |
| [Independent Python fixture](https://lukakoning.github.io/integration/conformance/README.md) | Cross-language signatures, selected protocol exchanges, PKI client authentication and mTLS resource denial | The live AS fixture omits discovery, login, consent and ID tokens; resource checks cover only mTLS token binding. |
| [Retained connections](https://lukakoning.github.io/integration/connections/README.md) | Cross-session state, multiple providers, refresh, resource isolation and actual browsers/workers | Synthetic providers establish local behavior, not external conformance. |
| [Inferno](https://lukakoning.github.io/integration/smart/inferno.md) | Independent SMART client-request verification | The local simulator has documented corrections; its verdict is specific to SMART and that deployment. |
| [`check_oauth21()`](https://lukakoning.github.io/R/check_oauth21.R) | Versioned configuration assessment against OAuth 2.1 draft 16 | It does not test the running provider or establish protocol conformance. |

The existing integration workflow already installs this checkout for
child apps and mirai workers. Follow that pattern. `integration/` and
`.github/` already stay outside the source package through
`.Rbuildignore`; external test tools must remain development
dependencies.

**Tool choice after the initial OIDC gate.** Consider new independent
checks, coverage of supported features, automation effort and
duplication of existing tests. Feature support in a tool’s documentation
is a candidate for testing; only an actual successful exchange
establishes interoperability.

| Order | Tool or extension | Decision and expected additional value |
|----|----|----|
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
on 2026-11-09. These are research observations, not installed or
validated pins. PrOfESSOS’s build evidence comes from its
[`pom.xml`](https://github.com/RUB-NDS/PrOfESSOS/blob/4e89b3f1f63ad71d771f2191f6dd46a8620a0fb8/pom.xml).

**OIDF scope and implementation choices.** The suite acts as the
provider while the real Shiny app acts as the relying party. Use static
registration initially; the [RP testing
guide](https://openid.net/certification/connect_rp_testing/) supports
it. Start with authorization code, `client_secret_basic`, RS256, PKCE
S256 and nonce validation. `plain_http_request` in the suite’s
request-type selector means an ordinary authorization request; use HTTPS
for transport.

Inspect and initially target OIDF source commit
[`410812ef6bc72a84723c1685725edce3558e31e3`](https://gitlab.com/openid/conformance-suite/-/tree/410812ef6bc72a84723c1685725edce3558e31e3),
dated 2026-11-10. Freeze the actual image/build correspondence in C01. A
hosted deployment can run a different release; record its reported
version separately.

| Profile key in our runner | Upstream plan ID | Initial scope |
|----|----|----|
| `basic` | `oidcc-client-basic-certification-test-plan` | Full Basic RP plan; its source fixes authentication to `client_secret_basic`. |
| `config` | `oidcc-client-config-certification-test-plan` | Discovery, JWKS and both signing-key rotation modules. |
| `form-post` | `oidcc-client-formpost-basic-certification-test-plan` | Basic RP with real POST callbacks. |
| `refresh` | `oidcc-client-refreshtoken-test-plan` | Refresh plus invalid refreshed issuer/subject cases; outside certification. |
| `extended` | `oidcc-client-test-plan` | Explicit applicable module/variant selection for public clients, other authentication methods and optional supported features. |
| `fapi-dpop`, `fapi-mtls` | `fapi2-security-profile-final-client-test-plan` | Generic `plain_fapi` authorization-code profiles, with selected client authentication and sender constraint. |
| `fapi-message-signing` | `fapi2-message-signing-final-client-test-plan` | OIDC/private-key-JWT/DPoP with signed JAR through PAR and query JARM; other variants remain separate. |

The pinned [OIDC client plan
sources](https://gitlab.com/openid/conformance-suite/-/tree/410812ef6bc72a84723c1685725edce3558e31e3/src/main/java/net/openid/conformance/openid/client)
and [FAPI client plan
sources](https://gitlab.com/openid/conformance-suite/-/tree/410812ef6bc72a84723c1685725edce3558e31e3/src/main/java/net/openid/conformance/fapi2spfinal)
define the exact module lists and variants. Freeze the resolved
combinations; do not assume every combination of selector values is
valid. Implicit/hybrid, WebFinger, dynamic registration and provider
logout protocols stay outside the initial claim. Local app logout and
revocation do not establish OIDC logout protocol support. Keep national
FAPI ecosystems and unrelated grants separate.

Use an R driver with the existing `httr2`, `jsonlite`, `processx`,
`callr` and `chromote` dependencies. Implement the necessary suite API
operations in test helpers, using the pinned
[`conformance.py`](https://gitlab.com/openid/conformance-suite/-/blob/410812ef6bc72a84723c1685725edce3558e31e3/scripts/conformance.py)
as protocol documentation. This avoids adding another orchestration
runtime. Derive request/response contracts from the pinned server,
including plan creation, runner creation, exported values and results.
Preserve server result fields without guessing their meaning.

The upstream
[`run-test-plan.py`](https://gitlab.com/openid/conformance-suite/-/blob/410812ef6bc72a84723c1685725edce3558e31e3/scripts/run-test-plan.py)
contains client-specific launch code, excludes both key-rotation modules
by default, and disables Node TLS verification in its sample-client
path. Our driver must explicitly cover rotation and maintain certificate
verification. Use a local CA trusted by the browser, R and actual async
workers. The suite offers [prebuilt Compose
services](https://gitlab.com/openid/conformance-suite/-/blob/410812ef6bc72a84723c1685725edce3558e31e3/docker-compose-prebuilt.yml);
pin image digests or build the exact pinned source, including its
dependencies.

**Execution contract.** C00 is this planning change. C01-C09 establish
the first milestone: a reproducible OIDC client gate. C10-C12 extend the
same infrastructure to FAPI. C13-C16 add provider diversity and close
the remaining documented gaps. All future entries start pending; record
actual commit hashes and evidence as work finishes. Suggested subjects
below describe separate commits, not changes to make in this planning
task.

Keep commits reviewable and green for their declared scope. If an
external test finds a product defect, insert a separate `fix(oidc): ...`
or `fix(oauth): ...` commit with the smallest independent reproduction,
then rerun the affected external case and neighboring positive flow. Do
not hide a failure by reducing validation or relabeling a mandatory
requirement. A suite defect needs its own reproduction, exact
specification reference and tracked coverage limitation.

**C01: `test(oidc): pin conformance services and add preflight`.** Add
`integration/openid/README.md`, `scope.md`, `compose.yml`,
`suite-lock.json`, `run-preflight.R` and lifecycle helpers. Map
supported features to requirements and existing/external evidence in
`scope.md`. Extend `.gitignore` for generated keys, suite data and
`.artifacts/`. Map the source SHA to concrete OCI digests or an exact
source build; pin Compose dependencies and record the build provenance.
Use unique project names, bounded readiness checks and cleanup of owned
processes/volumes. Document and automate API access for the suite’s
local development profile; keep hosted API-token setup separate. Check
the suite API and verify the required plan IDs exist.

Acceptance: preflight starts and stops the local stack, rejects
unavailable services and mismatched versions, and proves verified TLS
access from R and Chrome. Run it twice to detect leftover ports or stale
state. Missing tools produce a failing preflight with an actionable
message. Linux CI is the primary execution target; document the
Windows/Docker path after actually exercising it.

**C02: `test(oidc): add a configurable Shiny relying party fixture`.**
Add `fixture-app.R` and app-launch helpers using
[`oauth_provider_oidc_discover()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_provider_oidc_discover.md),
[`oauth_ui()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_ui.md)
or
[`oauth_form_post_ui()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_form_post_ui.md),
and
[`oauth_module_server()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_module_server.md).
Restrict configuration inputs to the test process. Keep issuer and mode
fixed for each run; no public endpoint may change the app’s provider.
Publish only sanitized authentication state, structured error codes,
operation counters and a test run identifier through the test page.
Tokens stay in the R process.

Acceptance: the fixture starts with the installed checkout, reports
ready in Chrome, builds the normal login request and reports setup
failures clearly. Use a package-owned provider for fixture plumbing
checks if needed; label those checks as local. Confirm that neither its
DOM nor logs expose credentials or raw callbacks. Cross-provider login
acceptance arrives in C04.

**C03: `test(oidc): add suite API and result validation`.** Add
`helper-suite.R`, `helper-evidence.R`, `test-evidence.R`,
`profiles.json` and `run-tests.R`. Implement plan/module creation,
exported-value retrieval, bounded state waits, result collection and
owned-run cleanup. Use the generated module list plus a checked-in scope
manifest to detect unexpected upstream changes. Keep module identity,
variants and attempt IDs together. Handle authorization failure, unknown
IDs, server restarts and unfinished modules as explicit failures.

Acceptance: focused tests prove that absent, duplicated, unrelated,
stale, unfinished and failed results cannot pass. They also reject an
empty run, missing app evidence, unexpected exceptions and a
complete-looking subset. Exercise the API against the pinned local
suite. Result validation must work before adding a passing CI label.

**C04: `test(oidc): drive real browser conformance smoke flows`.** Add
browser helpers and a checked-in `smoke` selection containing a valid
code flow, invalid issuer and invalid nonce. Start each module before
discovery, read its exported issuer, launch the configured app and drive
login in a real browser context. Follow the module’s prescribed action
sequence; do not replay intercepted callbacks directly into R as a
replacement for browser navigation. Add an isolated `workflow_dispatch`
job in `.github/workflows/openid-conformance.yml`.

Acceptance: positive login reaches validated identity/UserInfo; each
negative case reaches the intended response and yields the expected
rejection category. A suite timeout without matching app evidence fails.
Stopping the app mid-flow must fail the driver. Run two complete smoke
passes and retain sanitized reports. The CI job uploads only the report
artifacts, not raw suite exports. Local pull-request runs need no
external account credentials and must work on forks. Hosted access
tokens belong only to explicitly selected hosted runs.

**C05: `test(oidc): cover the Basic RP profile`.** Resolve every Basic
module and required action into `profiles.json`/the scope manifest.
Handle missing `kid`, required claims, RS256, unsigned tokens, UserInfo
subject mismatch and scope-specific UserInfo requests as the upstream
plan requires. Preserve PKCE S256 and nonce checking. Include the Basic
module that requires HTTP Basic client authentication; other
authentication methods get separate variants.

Acceptance: every resolved Basic module has a recorded suite verdict and
the app evidence required for that module. Document legitimate optional
outcomes individually. Run the complete profile without unexplained
omissions. Enable the stable smoke selection on pull requests; measure
full-profile runtime before choosing its pull-request placement.

**C06: `test(oidc): cover discovery and signing key rotation`.**
Implement the Configuration plan’s discovery-only actions and
repeated-login actions. Keep the same running R process and key cache
across the rotation test’s successive logins; explicitly schedule both
rotation modules ignored by the upstream runner. Preserve the exact
discovered issuer and normal JWKS selection rules.

Acceptance: reject the discovery issuer mismatch; complete the
prescribed key fetches and repeated authentication with the rotated key.
Reports distinguish discovery-only success from authentication success.
A new app/cache for every login cannot satisfy the rotation scenario. If
a pinned suite issue prevents completion, record incomplete coverage and
keep the milestone claim partial.

**C07: `test(oidc): cover form post callbacks in Chrome`.** Implement
the Form Post Basic plan with the actual bridge page and the normal
callback handling. Treat response `form_post` independently from the
outgoing authorization request’s GET/POST method. Use the suite’s origin
for provider navigation and the configured HTTPS app origin for
callbacks; record the real origins and whether the browser regarded them
as cross-site.

Acceptance: the resolved profile completes in Chrome, including
rejection cases, and callback cleanup/binding stays enabled. Record the
deployment’s cookie/site limits; existing cross-site attack tests
continue to supply their separate evidence. A direct HTTP POST from the
runner cannot replace the browser.

**C08: `test(oidc): cover refresh token identity continuity`.** Add a
fixture action that explicitly refreshes through the package’s public
API and consumes the resulting validated identity/token where the
upstream scenario permits. Drive all refresh-plan modules, including
changed issuer and subject. Do not refresh a fresh app with a manually
injected token; retain the original grant and validated subject across
the scenario.

Acceptance: normal refresh succeeds and identity substitutions fail.
Observe the package’s declared failure/credential-retirement policy and
ensure no rejected replacement becomes usable. Keep token rotation,
concurrency and retained-connection tests in their existing layers.

**C09:
`test(oidc): exercise async transport and client auth variants`.** Run
the core profiles with synchronous transport and actual mirai workers;
add a small future-worker parity selection following the package’s
existing support. Verify the installed package revision and TLS trust in
child processes. Add applicable comprehensive-plan selections for public
S256 clients, `client_secret_post`, `client_secret_jwt` and
`private_key_jwt`, using metadata and signing algorithms supported by
the pinned suite. Do not pretend the fixed Basic profile covers those
methods.

Acceptance: each declared auth variant completes a positive flow and a
relevant negative case. Core sync/mirai results match their expected
application policy. Neither worker reuse nor the harness leaks
issuer-specific configuration or credentials into another scenario.
Record unsupported suite variants as gaps, with any existing
interoperability evidence linked separately.

**C10: `test(fapi): add private key JWT and DPoP client conformance`.**
Reuse the OIDF driver for the generic FAPI 2.0 Security Profile with
`private_key_jwt`, DPoP, PAR and S256. Configure exactly the selected
profile’s metadata, algorithms, assertion audience and lifetimes after
reviewing the [client
requirements](https://openid.net/specs/fapi-security-profile-2_0-final.html#section-5.3.3).
Use the exported resource endpoint through normal package request APIs;
a validated ID token alone does not establish protected-resource
behavior.

Acceptance: complete the resolved applicable module/variant set,
including resource proof use, nonce behavior and issuer/state rejection
cases. Record OIDC-enabled and OAuth-only variants separately when
supported by the suite and package. Keep any missing profile
requirements visible; individual feature support does not establish full
FAPI conformance.

**C11:
`test(fapi): cover mTLS client authentication and token binding`.** Add
temporary certificate registrations and the selected FAPI mTLS variants.
Cover `private_key_jwt` plus mTLS sender constraint first, then mTLS
client authentication plus mTLS sender constraint if supported. Keep the
registration and resource access bound to the actual TLS peer
certificate. Do not infer that binding from a forwarded header or a
decoded token claim alone.

Acceptance: complete required code/resource exchanges, endpoint aliases
and the suite’s applicable fallback cases using verified TLS. A
mismatched certificate cannot use a bound token where tested. Keep auth
method and token binding as separate report dimensions. Run the selected
variants in sync and mirai transport.

**C12: `test(fapi): cover message signing client profiles`.** Add
supported Message Signing variants for JAR and JARM, starting with
signed requests through PAR and signed query responses. Select legal
combinations from the pinned plan; do not generate an unverified
Cartesian product. Add alternate callback modes or encryption only where
both implementations and the selected profile support them. Retain
upstream assertions unchanged.

Acceptance: successful signed exchanges and the plan’s applicable
invalid JARM signature/issuer/audience/expiry cases pass their expected
verdicts. Verify authenticated resource use, not just a redirect.
Compare any new findings with the independent Python tests. A fixture
patch requires explicit provenance and a narrower claim, following the
existing Inferno precedent.

**C13: `test(interop): add a pinned oidc-provider environment`.** Create
`integration/oidc-provider/` with a lockfile, runtime/container pin,
temporary keys, provider configuration and a small deterministic
login/consent fixture. Start with the researched release `9.14.0` or
document why implementation selects another supported release. Use the
provider’s normal protocol handlers and enable required features
explicitly. Reuse browser/evidence helpers when the interfaces match;
avoid a large common-framework refactor.

Acceptance: the unmodified provider completes the code flow with S256, a
validated ID token, UserInfo and refresh for public and confidential
registrations. Both query and form POST callbacks work in Chrome with
sync/mirai transport. Record provider events and selected discovery
capabilities. A provider setup failure fails preflight rather than
becoming an unsupported-client result.

**C14: `test(interop): cover advanced flows against oidc-provider`.**
Prioritize the existing Keycloak gaps: successful JAR + DPoP, JAR +
mTLS, and JAR + JARM; include PAR and direct forms only where the
provider actually supports them. Add signed UserInfo, token
revocation/introspection and RFC 8707 resource indicators where they
close a recorded gap. Verify a real resource request with the issued
credential. Add a small retained-connection scenario using
[`oauth_connections_server()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_connections_server.md)
for lifecycle behavior across navigation.

Acceptance: each combination advertised as supported finishes its
positive exchange and a relevant rejection case. Document unsupported
combinations without treating their rejection as successful
interoperability. Keep provider configuration and version in the
evidence so upgrades can explain changes. The existing independent
fixture remains the separate strict protocol oracle.

**C15: `test(security): close remaining protocol rejection gaps`.**
Review the completed coverage map before adding a dependency. Prioritize
untested trust boundaries: two-issuer mix-up, metadata/JWKS rotation
failures, signed response substitution, refresh identity changes and
invalid-response handling across browser/worker boundaries. Reuse
existing tests when they already establish the same property. For each
new scenario define a valid control and the single changed property,
then require a specific app outcome.

Acceptance: add only scenarios with a named requirement or documented
package policy and a remaining coverage gap. Use existing
Python/webfakes fixtures where practical. If per-request signed-response
mutation needs a new server, add AXA in a separate
`test(security): add scripted OAuth response mutations` commit with
exact Node/package pins and one justified scenario first. Record a
decision to defer AXA if no such scenario remains. Do not add NAV as
well.

**C16: `ci: publish scoped protocol quality evidence`.** Finalize CI
tiers, release evidence and developer instructions using measured
runtime. Keep the OIDF and second-provider jobs separate from the
existing 60-minute integration job. Required pull-request checks use
stable selected scenarios; scheduled and release runs execute the
declared larger matrix. An absent required dependency or unavailable
local service fails the selected job. Hosted comparison runs remain
optional and use separate credentials and reported version metadata.

Acceptance: demonstrate that an intentional invalid report fails CI and
that the declared matrix produces complete scoped evidence. Publish a
table of tested profiles, versions, omissions and fixture modifications.
Add precise developer documentation and a NEWS entry; claim OpenID
certification only after the Foundation’s separate submission process.
Update this plan with commit hashes, actual commands and remaining gaps.

**Result rules to implement in C03 and extend with each profile.** A
passing gate requires the expected module/variant set and the expected
app outcomes. Keep lifecycle status separate from a suite verdict:
`FINISHED` alone proves neither correctness nor successful
authentication. Expected rejection counts as a successful test only
after the fixture proves the intended response reached the appropriate
validation boundary and the client produced the expected rejection
category. No callback, an unavailable server or a dead worker fails.

Some upstream cases allow `SKIPPED`, `REVIEW` or `WARNING`; some
signature tests permit code-flow behavior weaker than shinyOAuth’s
signature policy. The pinned [invalid-ID-token base
class](https://gitlab.com/openid/conformance-suite/-/blob/410812ef6bc72a84723c1685725edce3558e31e3/src/main/java/net/openid/conformance/openid/client/AbstractOIDCCClientTestExpectingNothingInvalidIdToken.java)
shows the timeout-based observation and signature exception. Record the
raw verdict and an independently checked app outcome. Require an exact
module/variant-specific explanation and evidence for every allowed
exception; never add a wildcard acceptance rule. An inapplicable
optional feature does not erase a required-profile failure. Keep our CI
acceptance policy separate from the Foundation’s certification criteria.

Default to fresh registrations, app/browser contexts and run IDs between
independent modules. Multi-step rotation/refresh tests deliberately
preserve the app, relevant cache and original transaction or grant.
Respect that state in the scenario manifest. Never cache a successful
verdict across suite or package revisions, and never keep retrying a
protocol failure until it passes. An infrastructure retry starts a new
recorded attempt without discarding the failed attempt.

The sanitized JSON report should contain `schema_version`, run/attempt
IDs, checkout SHA and dirty flag, installed package identity, suite
source/image identity, R/browser/dependency versions, selected profile
and variants, expected/observed modules, raw suite statuses/verdicts,
app outcome categories, operation evidence, exceptions,
`coverage_complete` and `gate_passed`. Keep configuration-checker
findings as their own evidence category. Write a partial failing report
when execution stops early. Never merge results from different commits
into a complete release claim.

Use synthetic accounts and ephemeral credentials. OIDF raw exports,
browser traces and callback screenshots can contain secrets; retain them
locally only as needed for diagnosis and never upload them by a broad
artifact glob. Generate an allowlisted report for CI. If formal
certification needs raw logs, prepare that bundle separately with the
required access and provenance.

**Planned command interface.** These commands describe the future
runners; they do not exist yet. Each implementing commit must add the
corresponding usage documentation and validate unknown flags instead of
silently falling back to a smaller test set.

``` sh
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
Rscript integration/oidc-provider/run-tests.R --transport sync
Rscript integration/oidc-provider/run-tests.R --transport mirai
Rscript integration/oidc-provider/run-advanced.R --transport sync
Rscript integration/oidc-provider/run-advanced.R --transport mirai
Rscript integration/oidc-provider/run-resources.R --transport sync
Rscript integration/oidc-provider/run-resources.R --transport mirai
Rscript integration/oidc-provider/run-retention.R --transport sync
Rscript integration/oidc-provider/run-retention.R --transport mirai
```

`core` expands to Basic, Configuration, Form Post Basic and refresh;
report the resolved selections. `smoke` always reports partial coverage.
Runtime measurements decide placement, not which required results count
as passed.

**Scope and maintenance.** Map baseline checks to OIDC Core/Discovery,
OAuth 2.0, bearer transport, PKCE and issuer identification, together
with [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html) and [RFC
8725](https://www.rfc-editor.org/rfc/rfc8725.html). Add RFC 7009, 7662,
8705, 8707, 9101, 9126, 9449 and JARM where the enabled operation uses
them. Keep the existing OAuth 2.1 assessment pinned to its declared
draft; assess future draft changes in a separate change. Preserve the
distinction between client duties, server duties, deployment duties and
stricter package policy.

Use dedicated dependency-update changes for suite images, provider
releases or test libraries. Re-resolve module lists and compare changed
expectations before updating pins. Existing Keycloak, SMART, independent
cryptographic and browser attack gates continue to carry their own
evidence; passing OIDF profiles does not establish every deployment
property or supported extension.

Testing with OIDF is free according to its [suite
overview](https://openid.net/certification/about-conformance-suite/).
Formal certification remains a later optional milestone, with possible
[open-source fee waiver
eligibility](https://openid.net/certification/open-source-project-certification-policy/).
No account creation, certification submission or deployment is required
to complete the local implementation path above.
