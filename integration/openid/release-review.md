**OIDF suite release review: 2026-11-18**

The previous server and proxy digests returned `not found` from the official
GitLab registry. Verified cached images supported the earlier local runs, while
fresh runners could not acquire them. This update selects available official
`release-v5.3.4` images explicitly by digest.

| Input | New identity |
| --- | --- |
| Suite source | `23353b36957d6466010de767c812d2c91ed37638` |
| Server index | `sha256:dcc4bd1fb7e9c00f048a67373fe2bec5ecf9feb45a6b5d55e237e5c30e5312c6` |
| Proxy index | `sha256:9a7850826fcc8690cd43373528f50e9551ba33bf8e4a40b67b13267b0aca3675` |
| Database | Existing MongoDB 6.0.13 digest in [suite-lock.json](suite-lock.json) |

Anonymous registry requests resolved the release tag to these indices; hashing
the returned manifest bytes reproduced each content digest. Both images were
then pulled explicitly by digest. Docker `RepoDigests` matched the requested
identities. The server jar's `git.properties` reports the exact source commit,
`git.dirty=false` and description `release-v5.3.4`. MongoDB's existing digest
remained available. These checks do not depend on the old cached images.

This is a move from the previously pinned development build
`410812ef6bc72a84723c1685725edce3558e31e3` to an earlier published release.
The upstream [source comparison](https://gitlab.com/openid/conformance-suite/-/compare/23353b36957d6466010de767c812d2c91ed37638...410812ef6bc72a84723c1685725edce3558e31e3)
contains 47 commits and 96 changed files, with no truncated or collapsed diffs
in the API response reviewed for this update. Relevant differences include:

- The release uses Spring Boot 4.0.7; the development build uses 4.0.9.
- The development build changes handling of unexpected HTTP/mTLS paths in the
  OIDC and FAPI simulated authorization servers. Selected normal endpoints and
  the client-validation conditions retain their identities. Browser runs must
  still demonstrate the expected application outcomes.
- The development build adds a non-alias token-endpoint holder-of-key test to
  server-testing plans. Those plans test authorization servers; this harness
  selects client-testing plans. No selected client module is removed here.
- Suite UI cache behavior, hosted-login setup and logout handling differ.
  The local stack uses the upstream dev profile with disposable data and no
  hosted account. JWKS cache policy and resource-certificate limitations retain
  their explicit checks and scope descriptions.

A disposable stack using the release server matched the complete module lists
and variants for all 17 declared client selections against the existing
manifest. This first comparison used the previously cached proxy. The subsequent
public preflight and API runs use both new locked images. The API runner now
checks all 15 declared plan configurations, including the public-client probe,
so future lock updates must resolve every module and variant difference.
One module per configuration verifies the live combined variant and issuer,
then is cancelled without attempting a client flow.
The selections, expected verdicts, application rejection checks and exception
allowlists are unchanged.

The [official prebuilt Compose file](https://gitlab.com/openid/conformance-suite/-/blob/23353b36957d6466010de767c812d2c91ed37638/docker-compose-prebuilt.yml)
uses the same registry and release-tag convention. Our Compose transport keeps
temporary certificates, loopback ports and local nginx configuration; upstream
test assertions remain unmodified. The [proxy Dockerfile](https://gitlab.com/openid/conformance-suite/-/blob/23353b36957d6466010de767c812d2c91ed37638/nginx/Dockerfile)
includes OpenSSL, as required by preflight.

Local API and client commands ran from clean harness source
`65fbdc8e49d70e85f99cbccc527428c91a785992`. Both client-flow reports record that
revision and clean flag. Preflight ran earlier during development with the new
image pins. Environment/API reports currently omit checkout-identity fields;
their execution context is documented here, without adding retrospective fields
to those reports. Source-identity enforcement remains SA02 work. Windows used
R 4.5.1; Linux used R 4.5.0 inside Docker Desktop.

| Check | Result | Local sanitized evidence directory |
| --- | --- | --- |
| Windows preflight | 26 environment assertions, source/revision checks, R/Chrome TLS, wrong-pin rejection and cleanup passed | `preflight-20261118-220843-c3f33ce78045` |
| Windows API | All 15 plan inventories and combined-variant probes passed, plus unknown-instance rejection and cancellation | `api-20261118-221249-7546c0e37383` |
| Windows/sync Configuration | All six cases passed; 61.21-second module loop | `config-20261118-221249-4d54304ba7df` |
| Linux/mirai Message Signing | All 29 modules passed; 265.24-second module loop | `fapi-message-signing-20261118-212334-16d39ccd0fc9` |

The evidence regression passed 6,808 assertions on both platforms, with zero
test warnings or skips. Windows R retained its existing startup locale warnings.
The complete API, Configuration and Message Signing commands took approximately
144, 236 and 413 seconds respectively. Loop timings exclude installation,
regression checks, startup and harness controls; local host resources were shared.
Serialized preflight, API-inventory and client-flow reports were independently
checked against the new lock, with altered metadata rejected. Configuration
retains `coverage_complete=false` because the suite's JWKS response forbids
storage. Message Signing reports completion for its exact selected plan/variant;
the requirement mapping and certification boundary remain separate.

The first Linux/mirai Message Signing attempt,
`fapi-message-signing-20261118-211749-1872924f5082`, passed four modules before
Chrome failed to open its debugging port within the existing 30-second limit.
That report remains failed and receives no coverage credit. Twenty standalone
Chrome startup/evaluation/cleanup cycles did not reproduce the failure. A fresh
full run then passed without changing checks or timeouts. Its failed-run
diagnostics remain private alongside the original report. An earlier scratch
metadata comparison also timed out before API readiness; the successful repeat
used the standard Windows OpenSSL backend setting. Neither diagnostic run
establishes client coverage.

Local acquisition checks retrieved both new images from the registry by digest;
the subsequent local preflight reused them through verified `RepoDigests`.
Fresh GitHub validation passed at
[smoke run 44399653873](https://github.com/lukakoning/shinyOAuth/actions/runs/44399653873),
for the same harness source above. Its preflight records all three images as
`pulled`; the API and browser commands then record verified cache reuse. All
15 API inventories, TLS controls, three browser cases and cleanup passed. The
browser report records a clean checkout and `coverage_complete=false` for smoke.
The downloaded ZIP matched GitHub artifact digest
`sha256:e233d62a72f57bc61566731b2ccf6e12636611a2d15c0518f868fdef28b3ae4b`.
The reports were independently revalidated against the lock and expected source.

| Hosted smoke phase | Seconds |
| --- | ---: |
| Queue before runner assignment | 550 |
| Complete job, excluding queue | 729 |
| Dependency setup | 422 |
| Preflight | 46 |
| API and evidence checks | 89 |
| Browser command, including regression checks and setup | 122 |
| Three-case browser loop inside that command | 19.85 |

The first-run dependency setup dominates this measurement. Hosted Basic/sync
[44403591230](https://github.com/lukakoning/shinyOAuth/actions/runs/44403591230)
and Message Signing/mirai
[44403727783](https://github.com/lukakoning/shinyOAuth/actions/runs/44403727783)
also passed at the same clean source on separate fresh runners. Their preflights
each record all three images as `pulled`; subsequent commands record verified
cache reuse. Both API reports cover all 15 plan configurations. Basic completed
fourteen cases: thirteen suite `PASSED` verdicts and the documented `SKIPPED`
unsigned-token outcome after the client rejected `alg=none`. All 29 Message
Signing modules returned suite `PASSED`. Both selections record cleanup and
completion for their exact plan/variant. Their downloaded artifacts matched
GitHub's published hashes and the serialized reports passed independent checks.

| Larger hosted selection | Job seconds | Dependencies | Preflight | API | Browser command | Module loop |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Basic / sync | 412 | 50 | 45 | 85 | 180 | 81.44 |
| Message Signing / mirai | 581 | 49 | 44 | 90 | 345 | 245.08 |

Each larger job queued for four seconds before assignment. Table values are
seconds; job time excludes queueing, and module loops sit inside the browser
command. These are individual observations on GitHub-hosted `ubuntu-latest`
runners with R 4.5.1. Reports and job timing
metadata are retained locally under `integration/openid/.artifacts/hosted-RUN_ID/`.

| Larger-job artifact | Verified SHA-256 |
| --- | --- |
| Basic | `764c997c33ca274d65839d47c5e358125a61b943a3afedb719631e61b8b6581b` |
| Message Signing | `a2c4701ade844bbf33b6e6557a2e1b44959b5ce7ade0de4d975d47f2d6f25782` |

SA01 is complete for image reproducibility, fresh preflight/API/browser smoke
and the selected larger-job timings. Keep the existing PR smoke and manual
larger selections while the final tiering is reviewed in C16. SA02's source
identity and SA08's complete release matrix and durable evidence retention
remain pending. Earlier reports remain evidence for their recorded revisions.
Only sanitized evidence JSON is eligible for workflow upload; private
keys, registrations, libraries and raw diagnostics remain ignored locally.

Follow-up: [schema-4 source identity](source-identity.md) adds checkout snapshots,
archived installation input and release-source enforcement for subsequent runs.
The reports in this release review retain their original schemas and fields;
the source-identity follow-up records its own implementation and validation.

**Message Signing configuration follow-up: 2026-11-19**

The selected configuration assessment at
`f9056d9b12fd8f11e24eacfcb2c1317ac9b8261b` passed fresh hosted
[Message Signing / sync run 44568024103](https://github.com/lukakoning/shinyOAuth/actions/runs/44568024103).
All 29 modules returned suite `PASSED`; the application checks, exact
module/variant gate, cleanup and workflow release-source check also passed.
The fixture ran its configuration guard before authorization, including its
independent signed-UserInfo policy and DPoP-only selection boundary.

Preflight acquired all three locked images by verified digest. The API report
checked all fifteen declared plan inventories and variant probes without
claiming a client flow. All three sanitized reports record the same clean
checkout/tree and matching before/after source snapshots. The schema-4 client
report also records unchanged installed-package files and canonical archive
SHA-256 `c84d5ba168ba8c5b0392a231c78f583556570a212b598d8c2f14115ed5c809c6`.
The downloaded artifact matched GitHub's digest
`sha256:476fd0e930f0f270ce3d600008cc4e590d952949f80d88f6eaf8a33d2eb739d1`.
Independent local revalidation required exactly one preflight, API and client
report, checked the locked acquisition and inventories, revalidated all module
evidence and regenerated the selected commit's archive for the source CLI.

| Hosted Message Signing / sync phase | Seconds |
| --- | ---: |
| Queue before runner assignment | 979 |
| Complete job, excluding queue | 610 |
| R setup | 53 |
| Dependency setup | 54 |
| Preflight | 48 |
| API/evidence command | 98 |
| Browser command, including regressions and setup | 337 |
| 29-module loop within that command | 222.62 |
| Release-source command | 1 |

The runner used Ubuntu and R 4.5.1. The original sanitized JSON and ZIP remain
under ignored `.artifacts/hosted-44568024103/`. Workflow artifact retention is
still seven days. This is evidence for the exact selection and source above;
the later regression-namespace correction has its own validation. These
records do not establish the complete final release matrix or certification.

## Rejected-callback cleanup acceptance: 2026-11-19

The cleanup implementation and approved-diagnosis correction at
`8cd6d16698f89b443df5751806cb7c38d56e2aa1` passed fresh hosted
[Message Signing / mirai run 44590006270](https://github.com/lukakoning/shinyOAuth/actions/runs/44590006270).
All 29 modules returned suite `PASSED`; the application, exact module/variant,
worker, cleanup and release-source gates passed. Ten selected malformed HTTP
callbacks provide the current
[schema-2 cleanup proof](assessment.md#rejected-callback-cleanup): a browser
303-to-400 transition to an opaque continuation, both-hop privacy checks,
long-credential nonreflection, actual terminal-request Referer absence and unchanged
nonempty pending state. Their expected rejection categories and zero
token/UserInfo/resource traffic remain required.

Fresh preflight acquired all three locked images by digest, checked TLS and
wrong-pin rejection, then verified cleanup. The separate API report checked
all fifteen plan inventories and combined-variant probes; it explicitly earns
no client-flow credit. Independent artifact revalidation required one report
for each role and checked the reports against their selected clean source,
lock and current callback policy. Removing a required cleanup proof fails the
client gate. The source CLI independently regenerated the selected commit's
canonical archive and passed without claiming matrix completeness.

All three hosted reports identify the same clean source/tree and matching
before/after snapshots. The client also records unchanged private installation
records and canonical archive SHA-256
`af55366316f3cba279a89fbbec965c203b1e8cbe9c7573bc56d62c555a8fde3b`.
The downloaded ZIP matched GitHub artifact digest
`sha256:dcc1214f2e2280d025a2a05a7f405cd013c8cc3dcada2d46ca0009ef273f6361`.
The hosted artifact contains sanitized JSON reports; physical installed-file
checks are supplied separately by the local runs, rather than inferred from
the hosted artifact.

| Hosted Message Signing / mirai phase | Seconds |
| --- | ---: |
| Queue before runner assignment | 4 |
| Complete job, excluding queue | 582 |
| R setup | 30 |
| Dependency setup | 45 |
| Preflight | 47 |
| API/evidence command | 108 |
| Browser command, including regressions and setup | 339 |
| 29-module loop within that command | 236.61 |

The same revision passed all eleven Windows OAuth/reference/sync modules,
including four selected cleanup cases, in a 99.10-second module loop. Windows
and a separate canonical Linux private installation each passed all 7,904
evidence assertions. Local independent review compared the actual 39-file
installations with their recorded identities and the selected commit archive;
source and installation records stayed unchanged. The diagnosis correction
also passed 1,600 targeted package assertions on each OS. All these regression
checks had zero failures, errors, test warnings or skips; Windows retained its
documented R startup locale warnings. Earlier 3,803-assertion package runs
belong to the preceding implementation revision and are recorded separately
in the [implementation plan](../../.github/protocol-quality-implementation-plan.md).

The failed pre-correction Message Signing attempt remains failed and receives
no passing-run credit. Its stricter application gate exposed the nested
missing-reference-state diagnosis; the fix preserved that gate and added real
GET/POST JARM regressions. Its queued hosted attempt was cancelled before
validation. The original sanitized reports, failed attempts, ZIP and private
verification receipts remain ignored locally. Hosted reports are under
`.artifacts/hosted-44590006270/`; workflow retention remains seven days.

This acceptance covers the exact selected variants above. Initial callback
history, operator/proxy logs, cross-site HTTPS browser acceptance, the final
aggregate release matrix and durable release retention remain separate work.
No certification claim follows.

## Cross-site Form Post and warm-cache acceptance: 2026-11-20

The new cross-site selection passed clean Windows sync and mirai entrypoints
at `d532cba3f4df7ce8c4cf9fa85211bf894899060f`. Each ran all 8,274 evidence
assertions across 107 tests, with zero failures, errors, test warnings or skips,
then passed both selected browser modules. Their two-of-thirty Comprehensive
scope, app checks and loopback/Chrome limits remain in the
[selection guide](cross-site-form-post.md).

The actual HTTPS POSTs crossed from the localhost provider to the 127.0.0.1
app with the expected Origin, observed cross-site category and no Strict
binding cookie on the POST. The browser marker is Secure/Strict and deliberately
JavaScript-readable; this is not an HttpOnly-cookie claim. Normal login
validated identity and made one token and one UserInfo request. Valid
`login_required` denial consumed its own state exactly once, left no pending
record or identity, made no token/UserInfo request and dispatched no protocol
worker. Mirai's successful exchange used the verified worker. Both cases
passed CA readiness, wrong-SPKI and cleanup controls.

| Clean Windows selection at d532cba3 | Modules | Module-loop seconds | Complete command seconds |
| --- | ---: | ---: | ---: |
| Cross-site Form Post / sync | 2 passed | 20.07 | 242.79 |
| Cross-site Form Post / mirai | 2 passed | 19.22 | 198.42 |
| Shared pool / mirai | 8 passed | 50.50 | Not recorded here |

Shared-pool execution at the same revision passed all 8,274 regressions and
eight alternating modules. Its parent and four child reports now retain the
verified post-regression installation record. Independent checks compared
each actual 39-file package and private receipt with initial/regression/final
records, checked unchanged source inventories and regenerated the selected
commit's canonical archive:
`6255f8b2e419ca33988d3a4758b35eaae230c524319e026ce9c18609fd622ab4`.
The existing source CLI passed for the client reports; their scoped coverage
and upstream-plan flags remain false where required.

Fresh hosted Linux [cross-site/mirai run 44640739188](https://github.com/lukakoning/shinyOAuth/actions/runs/44640739188)
passed preflight, all sixteen declared API plan inventories/variants, both
browser modules and the source gate at d532cba3. Preflight pulled all three
locked images and verified TLS/wrong-pin rejection. Independent revalidation
required exactly one preflight, API and client report, checked all 1,000 LF
source-file hashes per role against the selected archive, and matched each
extracted JSON with its ZIP bytes. The artifact matched GitHub digest
`sha256:138d75fa91698cb5de72cfff059fc08c13cccd6b8d402b2b3a6bf5a7111a80ec`.
Hosted JSON records agree before/after; no physical hosted-library claim is
inferred from the download.

The hosted job took 348 seconds after a three-second queue: R setup 27,
dependencies 37, preflight 41, API/evidence 105 and browser command 118 seconds.
The two-module browser loop took 9.92 seconds. Its original ZIP, JSON and
independent receipts remain under ignored `.artifacts/hosted-44640739188/`.
The numeric 8,274 assertion count above comes from the captured Windows
entrypoints; the hosted job passed its required regression checks without
publishing a separate count CSV.

The separate native-provider cache selection passed a clean local entrypoint
at `4f0708fb1d85f23ce0d55ff6fa634e2609d58364`, after two preserved driver/export
failures documented in the implementation plan. Its 246 regressions passed
with zero failures, errors, test warnings or skips. Three real native
PAR/code/S256 logins established population, reuse of the same usable entry
without another JWKS request, then one forced unknown-key refresh after an
owned provider restart at the same issuer. Both rogue signatures failed
without another endpoint fetch. Native endpoint/process/key events corroborate
the client-side pass-through trace and actual pending-reference consumption.

Independent review checked the native schema-1 report, all 1,000 source-file
hashes, actual 39-file private installation, initial/regression/final records,
cleanup and selected canonical archive:
`5f290fa6ac64322436d6f9798b6980c4a42f31b3a551195d7c9f7d6c0da6666f`.
The native response's freshness headers are absent; the test uses the
unchanged default one-hour backend, without a header or cache override. It
establishes the selected sync warm-cache property, not positive origin
max-age, browser-cookie or shared-worker behavior. See the
[native selection guide](../oidc-provider/jwks-rotation.md).

Fresh hosted Linux [native rotation run 44642151147](https://github.com/lukakoning/shinyOAuth/actions/runs/44642151147)
also passed at 4f0708fb. Its one sanitized schema-1 report revalidated with all
246 regressions recorded, the full rotation proof, matching source and
installation records, pinned provider 9.14.0/Node v24.22.3 and cleanup.
Independent review matched all 1,000 LF source hashes and nine provider-source
hashes with the selected archive. The downloaded ZIP matched GitHub digest
`sha256:e4130dd40041d90a9b002fe7624d3a59c534550ade00abfc8051a6a4089ce272`;
its extracted JSON byte-matched the ZIP member. Physical libraries and a
regression CSV are not in that hosted download, so those checks remain local.
The job took 115 seconds after a 250-second queue: R setup 27, dependencies 38
and the selected native command 32 seconds. Original sanitized evidence and
independent receipts remain in ignored `.artifacts/hosted-44642151147/`.

The declared 39-row OIDF matrix remains incomplete. Its CLI rejects the actual
shared-only report set for 38 missing rows and records the requested source
and exact input hash in a failed summary. A separately named diagnostic
subset revalidated the three actual Windows reports and rejected a mutated
denial witness; it earns no 39-row completion credit. Native schema-1 reports
cannot fill OIDF matrix entries. These source-qualified results belong to
their respective revisions and are not combined into a complete release.
Private receipts remain ignored under `codex/cross-site-acceptance/`,
`codex/shared-quality-acceptance/` and `codex/warm-jwks-par/`.
Durable retention, other release/provider/platform selections and certification
remain separate work. These individual workflow artifacts had seven days of
retention.

## Matrix artifact verification and FAPI initiation, 2026-11-21

The [first hosted matrix attempt](https://github.com/lukakoning/shinyOAuth/actions/runs/44907373886)
stopped during R dependency setup. The
[second attempt](https://github.com/lukakoning/shinyOAuth/actions/runs/44907547397)
passed preparation and expanded its 39-selection matrix at `681992ad`.
The aggregate remains pending. Individual artifacts request seven days and
the aggregate requests 90 days, subject to repository policy.

The [offline verifier](release-matrix.md#verify-and-retain-a-completed-attempt)
matches the ZIP to the run-attempt and artifact metadata, checks its GitHub
SHA-256, and reruns the revision-bound release checker. Five verifier tests
passed, and the full replay accepted a ZIP containing 39 synthetic client
reports. A real standalone selection ZIP downloaded through the GitHub API
matched its advertised digest. Verification of the complete hosted matrix
requires its finished attempt and aggregate ZIP.

At `b5e9c7cf`, the Windows sync and mirai `fapi-dpop` runs passed all three
selected modules. Both reports passed the release-source check. For each run,
the normal nonce case recorded a visible login control and one discovery
request, with zero PAR, authorization and token requests in the suite log
before the driver invoked the login control. The same browser completed the
code flow, UserInfo and the accounts request. The outcome measures the
fixture's network activity at that point. Transaction queuing, trusted user
activation and production consent remain outside this browser observation.
R emitted startup locale warnings and Chrome logged websocket EOF messages.
Both runner commands exited successfully.
The two sanitized reports stay under the ignored `.artifacts/` directories
`fapi-dpop-20261121-142800-0006b08948a5` and
`fapi-dpop-20261121-142923-222d158d8ed6`.

## Direct FAPI query configuration, 2026-11-21

The manifest at `25bc1c74ebe965b5a874ef8d19268cc063054eca` requires the
[direct query configuration assessment](configuration.md#direct-fapi-query-callback)
for the normal DPoP nonce case. The live discovery metadata advertised RFC
9207 issuer identification. The constructed client required the issuer and
compared it to the expected issuer. The other assessment fields cover the
selected HTTPS, S256, PAR, JWT algorithm and DPoP policies.

On Windows, `Rscript integration/openid/run-tests.R --profile fapi-dpop --transport sync`
and the same command for `mirai` both ran from a clean checkout. All three
selected suite modules passed per transport. The nonce case passed all 26
configuration checks in each run. Both serialized reports passed release
revalidation and the release-source check. The reports stay under
`.artifacts/fapi-dpop-20261121-144021-1e2ab0beb7f1` (sync) and
`.artifacts/fapi-dpop-20261121-144021-d264bf9f3d29` (mirai).

The focused configuration suite passed 269 assertions. Four representative
Message Signing configuration outputs matched their pre-refactor versions.
A 39-report synthetic artifact from an older committed policy also replayed
successfully. These checks cover the recorded configuration and report
compatibility. Broader profiles and deployment controls retain their own
acceptance requirements.

## Preflight and API evidence and Chrome startup, 2026-11-21

At `0da2fb4`, the offline artifact verifier requires one preflight and one
API report alongside each client report. It checks their association with
the same checkout, the locked suite and TLS evidence, the API installation
identity, and each committed plan's modules, variants and cancelled probe.
The receipt records both reports' original SHA-256 digests per selection.
Seven regression tests and a replay with 39 synthetic client reports and
78 companion reports passed. The verifier also checked the untouched
companion reports from 13 published selection ZIPs against the 16 pinned
plan definitions in each ZIP. One of those ZIPs contains the failed client
run described below.

The [first failed matrix selection](https://github.com/lukakoning/shinyOAuth/actions/runs/44907547397/job/136863926219)
was `fapi-dpop-full/sync` at `681992ad`. Preflight and API checks passed.
The client runner recorded 16 completed module results before Chrome failed
to open its debugging port within 30 seconds on the next module. The
original sanitized artifact and its GitHub metadata are retained under the
ignored directory
`.artifacts/hosted-44907547397-fapi-dpop-full-sync/`.

At `70fa6991`, only that Chrome debugging-port timeout allows one fresh
startup before browser navigation. The 46 environment assertions passed.
They covered profile isolation, cleanup, unchanged startup options and
failure propagation for a second timeout or an executable error.

The clean Windows run `Rscript integration/openid/run-tests.R --profile fapi-dpop-full --transport sync`
passed all 23 selected modules in 247.92 seconds of module runtime. Its
report passed the release-source check and stays in
`.artifacts/fapi-dpop-full-20261121-145739-5c70993507b2/`.
The [targeted GitHub run](https://github.com/lukakoning/shinyOAuth/actions/runs/44911471869)
passed all 23 modules at the same revision in 176.99 seconds of module
runtime. It did not encounter the startup timeout. The original ZIP
matched GitHub's digest. Independent checks also accepted its preflight,
16 API plan inventories and client release-source record. The ZIP and
metadata are under `.artifacts/hosted-44911471869/`. These results qualify
the targeted selection. The ongoing matrix attempt retains its original
failure and continues to collect evidence for the remaining selections.

## Matrix CI and trusted FAPI login, 2026-11-21

`3e4a793` adds the preflight and API report check to the matrix workflow
after the client aggregate. The workflow uses the same report validator as
offline ZIP replay and checks every declared selection for the chosen
revision and attempt. Nine verifier tests passed. The exact command accepted
39 synthetic client reports and their 78 accompanying reports on Windows and
Linux. With all 39 client reports present, removing an API report or changing
its cancelled-probe evidence failed the gate. A downloaded, genuine passing
`fapi-dpop-full/sync` selection reached the expected matrix-incomplete error.
The full hosted execution of the new aggregate step remains open.

`cda9f80` requires the manual DPoP nonce case to use Chrome DevTools pointer
input. The login button must observe a trusted click with transient user
activation after the runner records zero pre-click PAR, authorization and
token requests. The manifest requires this field only for the selected case.
See the [HTML activation rules](https://html.spec.whatwg.org/multipage/interaction.html#tracking-user-activation).

Clean Windows `fapi-dpop` runs passed all three modules with `sync` and
`mirai`. Both original JSON reports recorded the activation field and
passed independent release revalidation and the release-source check at
`cda9f80f5a381605dc77459f88b018ad2e5f4a62`. The reports stay under
`.artifacts/fapi-dpop-20261121-152003-ffc30462d679/` (sync) and
`.artifacts/fapi-dpop-20261121-152003-1d062055fd07/` (mirai).
Production consent and cross-site initiation remain application concerns.

## Failed matrix selection diagnostics, 2026-11-21

`6a893c0` adds per-selection diagnostics to failed client aggregate receipts.
The checker identifies missing and duplicate reports, validates individual
submitted reports against the selected source and policy, and retains an
input SHA-256 for each assigned report. An invocation with no client inputs
produced all 39 missing rows and returned a failing exit status.

A snapshot of 27 original client reports from the
[running GitHub matrix](https://github.com/lukakoning/shinyOAuth/actions/runs/44907547397)
was replayed against `681992ad`. Every input ZIP matched GitHub's digest. The
failed receipt recorded 26 independently passing selections, the reported
`fapi-dpop-full/sync` failure and 12 missing selections. It stays under
`.artifacts/hosted-44907547397-diagnostics-27.json`.

The successful 39-row synthetic summary matched the previous checker's
bytes, and its full offline artifact replay passed. The clean
`Rscript integration/openid/run-tests.R --check-api` run at
`6a893c0152a6f6333f0b923966010ab698174e31` passed the evidence regressions
and all 16 pinned suite-plan inventories. The API report records verified
source and cleanup under `.artifacts/api-20261121-153136-b5f8db0c1cfd/`.

## Pre-login state and fresh matrix, 2026-11-21

At `44471599157e75642147ea86c323a69d6bed7809`, the manual DPoP nonce case
checks the same Shiny session immediately before the trusted click. The
fixture reports the login and callback queue flags and a state-store count.
Each flag must be false and the count must be zero. The manifest requires
the sampled state alongside the existing browser activation and pre-click
provider request checks.

Clean Windows `fapi-dpop` runs passed all three modules on `sync` and
`mirai`. Both JSON reports recorded the clear session state and passed
independent release revalidation and the release-source check. The reports
stay under `.artifacts/fapi-dpop-20261121-153943-f1d1d7d54544/` (sync) and
`.artifacts/fapi-dpop-20261121-153943-878ed456b9a6/` (mirai). An earlier
39-row synthetic artifact also replayed successfully under its own policy.
Application consent and cross-site initiation still need deployment evidence.

The [fresh GitHub matrix](https://github.com/lukakoning/shinyOAuth/actions/runs/44915531642)
was dispatched at that exact revision. Preparation passed and the first three
selection jobs started. The earlier matrix retains its original results.
Release qualification awaits the fresh run's selection verdicts, companion
checks and aggregate receipt.

## Refresh module validation, 2026-11-21

The matrix at `681992adec92693adeaf320b2e9717279eeeb5c4` stopped both
`refresh/sync` and `refresh/mirai` in **Run real browser client selection**.
The suite had returned `FINISHED/PASSED` for `oidcc-client-test-refresh-token`.
The runner applied the login evidence check to the terminal refresh state.
The saved `sync` ZIP matches the GitHub artifact digest. Its module result
passes the refresh evidence check. The ZIP and artifact metadata stay under
`.artifacts/hosted-44907547397-refresh-sync/`. [Sync job](https://github.com/lukakoning/shinyOAuth/actions/runs/44907547397/job/136878190964),
[mirai job](https://github.com/lukakoning/shinyOAuth/actions/runs/44907547397/job/136879294272).

At `98362fcd703ecdfc98ea38d16eee5301612d01a2`, the runner and release checker
share the application evidence check. The refresh check requires the initial
login and the state before and after the refresh. Its regression covers all
three expected outcomes and rejects each one with missing pre-refresh state.

Clean Windows runs passed `oidcc-client-test-refresh-token`,
`oidcc-client-test-refresh-token-invalid-issuer` and
`oidcc-client-test-refresh-token-invalid-sub` on each declared transport.
All three original reports passed the release-source check and independent
release protocol validation. They stay under
`.artifacts/refresh-20261121-155028-bd793cae0e54/` (`sync`),
`.artifacts/refresh-20261121-155028-f5ed8ca926db/` (`mirai`) and
`.artifacts/refresh-20261121-155028-454cb55f0126/` (`future`).

The targeted GitHub `refresh/sync` run completed successfully at the same
revision. ZIP `14712351325` matched the GitHub SHA-256 digest. The retained
preflight report and all 16 API plan inventories passed verification. The
three-module client report passed independent protocol and release-source
checks. The original ZIP and artifact metadata stay under
`.artifacts/hosted-44916080514/`. [Targeted GitHub run](https://github.com/lukakoning/shinyOAuth/actions/runs/44916080514).

The matrix at `4447159` was dispatched before the refresh correction. Its
reports identify that revision. A new 39-selection attempt is running at
`98362fcd703ecdfc98ea38d16eee5301612d01a2`. Release qualification requires its
selection verdicts, companion checks and aggregate receipt.
[Corrected matrix attempt](https://github.com/lukakoning/shinyOAuth/actions/runs/44916619030).

## Matrix retention and failed aggregate, 2026-11-21

The matrix at `681992adec92693adeaf320b2e9717279eeeb5c4` completed with a
failed aggregate. The `refresh/future` job recorded the same early validation
error as the other refresh transports after the suite returned
`FINISHED/PASSED` for its first module. [Future job](https://github.com/lukakoning/shinyOAuth/actions/runs/44907547397/job/136882135471).

Aggregate ZIP `14711338830` matched the SHA-256 from GitHub. Its 39 original
client reports had the same digests as the stored summary. Independent replay
against `681992ad` recorded 35 passing selections and four reported failures.
The four were `fapi-dpop-full/sync` and all three `refresh` transports. The
original ZIP, API metadata and replay diagnostics stay under
`.artifacts/hosted-44907547397-aggregate/`.
[Failed aggregate](https://github.com/lukakoning/shinyOAuth/actions/runs/44907547397/job/136884166588).

`5b50f5f6` adds `--retain` to the archive verifier. It accepts a repository,
revision, run and attempt and saves the originals with the independently
computed receipt in a new directory. The Windows synthetic test produced
identical receipts from offline replay and retention of all 39 client and 78
companion reports. Live probes against a running GitHub attempt and the
completed failed attempt both exited unsuccessfully and left no bundle. A
verified successful hosted bundle and permanent storage remain open.
[Retention instructions](release-matrix.md#verify-and-retain-a-completed-attempt).

## Configuration rotation snapshots, 2026-11-22

The matrix at `98362fcd703ecdfc98ea38d16eee5301612d01a2` completed with 37
passing selections, including all three refresh transports and both full
FAPI DPoP selections. `config/sync` and `config/mirai` reached their expected
suite verdicts and failed the final app snapshot check during **Run real
browser client selection**. The release checker independently reproduced all
39 diagnostic rows from digest-verified aggregate ZIP `14715958089`. It and
the replay receipt stay under `.artifacts/hosted-44916619030-aggregate/`.
[Failed aggregate](https://github.com/lukakoning/shinyOAuth/actions/runs/44916619030/job/136915595212).

The earlier matrix at `4447159` reported the same two Configuration failures
alongside the three refresh runner failures. Its aggregate ZIP `14715443641`
matched the GitHub digest and stays under
`.artifacts/hosted-44915531642-aggregate/`.
[Earlier matrix](https://github.com/lukakoning/shinyOAuth/actions/runs/44915531642).

In both rotation cases, the final login snapshot and the last step differed
only by a null `pre_login_state` field. The browser snapshot reader now
returns that field only for the explicit pre-click FAPI observation. The
rotation gate still compares the whole terminal snapshot with the last
login step and requires the same app and cache objects, distinct signing
keys and the expected session and exchange counts.

Clean Windows runs at `92bedf1d7c6dc87996232289acd39b89b9c554ae` passed the
Configuration selection on `sync` and `mirai`. Both rotation modules passed
on each transport. The unsigned-token module retained the expected suite
`SKIPPED` verdict with app-side rejection evidence. The suite's JWKS
`no-store` response still leaves cached-key refresh coverage incomplete.
The selected `fapi-dpop/sync` profile passed all three modules and preserved
its separate pre-click state and trusted-activation proof. All three reports
passed independent protocol and release-source checks. The originals stay
under `.artifacts/config-20261122-122428-84c3aba3a26d/` (`sync`),
`.artifacts/config-20261122-122428-3b23ab40770a/` (`mirai`) and
`.artifacts/fapi-dpop-20261122-122428-b3b8c9f0003f/`.

The targeted GitHub selections passed on the same revision. ZIPs
`14751813421` (`sync`) and `14752297251` (`mirai`) matched their GitHub
digests. The preflight and 16 API inventories in each ZIP also passed
verification. Independent client report checks confirmed both rotations and
the scoped Configuration verdicts. The originals and metadata stay under
`.artifacts/hosted-45017231485/` and `.artifacts/hosted-45017233716/`.
[Sync run](https://github.com/lukakoning/shinyOAuth/actions/runs/45017231485),
[mirai run](https://github.com/lukakoning/shinyOAuth/actions/runs/45017233716).

A new 39-selection matrix was dispatched at `92bedf1d7c6dc87996232289acd39b89b9c554ae`.
Release qualification awaits the selection verdicts, companion checks and
aggregate replay for this revision.
[Matrix with configuration correction](https://github.com/lukakoning/shinyOAuth/actions/runs/45017983714).
