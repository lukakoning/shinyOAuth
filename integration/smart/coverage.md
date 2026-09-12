# Coverage of the implemented SMART and connection roadmap

Install the current checkout, then run the full coverage entry point from the
repository root:

```sh
Rscript integration/smart/run-coverage.R
```

This runs the complete package suite with browser tests enabled, independent
Python conformance checks, the retained-connection and account-login browser gates, GET and POST
SMART registration/launch matrices, concurrent EHR launches, the pinned Docker
sandbox, and the [independent Inferno client gate](inferno.md). Inferno requires
32 two-site scenarios and 320 applicable upstream test results. Its simulator
has two documented compatibility corrections; upstream verification tests are
unchanged. Suites run in fresh R processes, and browser suites run sequentially.
The runner continues after a failed suite to collect the remaining results, then
fails if any suite failed. `--integration-only` omits the package suite when it
has already been run for the same checkout.

Prerequisites: Chrome/Chromium, Node.js for the browser fixture servers, Docker
Engine with Linux containers and Compose v2, the R dependencies listed by the
individual runners, and Python with
`integration/conformance/requirements.txt` installed. Set `R_LIBS` to select an
isolated package library and `SHINYOAUTH_TEST_PYTHON` when Python is not on PATH.
The Shiny parent and mirai workers must load the current installed checkout.

The combined runner includes `integration/connections/run-account.R`. On
2026-09-12 that gate passed all 80 browser assertions without skips against a
fresh installation, covering query/form POST and synchronous/mirai transports.
The runner parsed successfully and the regenerated API help was checked. This
focused validation did not rerun the other combined suites or establish external
SMART interoperability.

## Which implementation each suite verifies

| Implemented component | Package tests | Integration evidence |
| --- | --- | --- |
| Initial/latest token extension snapshots | `test-token-extra-fields.R`, `test-smart-contracts.R` | SMART profile matrix preserves Patient and validated user context when refresh omits context/ID token. |
| RS384 client assertions, JAR and DPoP signing | `test-rs384.R` and signing/claim tests | `integration/conformance/run-tests.R` independently verifies signatures and protocol exchanges in Python. The SMART profile matrix also exercises RS384 client authentication during code exchange and refresh. |
| Optional client settings, connections and approved resource bases | `test-client-resources.R`, `test-oauth-connections.R`, `test-resource-binding.R` | Retention/shared-callback suites and two-site SMART Patient/user requests. |
| Encrypted retention, ownership and atomic lifecycle | Connection credentials/store/owner/manager tests | Retention suite covers browser isolation, navigation and independent grants; EHR concurrency tests cover overlapping launches. |
| Account login and retained grants | Account owner and manager lifecycle tests | `integration/connections/run-account.R` covers real local login/logout, account switching, retained grants and refresh across query/form POST and sync/mirai. Synthetic providers; independent external SMART verification remains separate. |
| SMART discovery and endpoint policy | `test-smart-discovery.R` | Real HTTP positive/negative fixtures plus unmodified Docker metadata; the live positive gate is currently blocked. |
| Registration, S256, FHIR audience and scopes | `test-smart-client.R`, `test-smart-scopes.R` | Profile matrix validates the actual authorization and token requests for public, HTTP Basic, RS384 and ES384 registrations. |
| SMART context and validated `fhirUser` | `test-smart-context.R`, SMART identity tests | Profile matrix obtains a signed ID token over HTTP, fetches live fixture JWKS, reads the contextual Patient and a distinct Practitioner, and repeats after refresh/navigation. |
| EHR launch entry, owner-bound continuation | `test-smart-launch.R` | Both the profile matrix and dedicated concurrent two-tab/two-site EHR suite exercise registered launch routes. |
| P6 shared callback routing | `test-connection-router.R` and callback tests | One issuer, two registrations/resource paths, concurrent tabs and query/form POST, with sync/mirai. This is generic OAuth evidence. |
| P7a refresh scope narrowing | `test-refresh-scope-narrowing.R` | Generic scope gate plus SMART semantic `.rs` to `.r` narrowing; retained limit, required permissions, refresh rotation and another unaffected connection. |
| P7b authorization POST | `test-authorization-post.R`, Node form handler | SMART matrix with long granular scopes and fixed endpoint query; ordinary OAuth browser retention; independent Python RS256/RS384 protected combinations over TLS. See [commands and limits](authorization-post.md). |
| Independent SMART client requests and retained grants | Evidence-contract regressions reject incomplete results and stale post-refresh reads | `run-inferno.R`: public/Basic/RS384/ES384, standalone/EHR, sync/mirai and GET/POST against two pinned Inferno deployments; browser lifecycle and recorded-exchange checks supplement the unchanged upstream verifier. |

## SMART profile browser matrix

```sh
Rscript integration/smart/run-profiles.R
Rscript integration/smart/run-profiles.R --post
```

This requires **32 successful scenarios**: public, HTTP Basic, RS384 and ES384
registration profiles, two launch modes (standalone/EHR), two callback transports
(query/form POST), and synchronous
or real mirai transport. Every scenario authorizes two sites, fetches Patient and
validated Practitioner identity, narrows one grant, verifies loss of search
permission, retains that limit after navigation, refreshes both grants independently,
rejects widening, disconnects one connection and logs out.

The server deliberately retains the original refresh credential's grant, so a
later refresh that omits the narrowed scope would restore search permission and
fail the test. The app uses exported SMART and manager APIs. No scope evaluator,
token exchange, signature verification, context parser or resource helper is
mocked. The server is still our synthetic fixture; this is not independent SMART
conformance. The Python suite remains the independent cryptographic check.
The asymmetric rows generate temporary RSA or P-384 keys and verify the selected
algorithm and assertion signature during both code exchange and refresh.
Evidence records `assertion_alg` for each scenario.

`--quick` runs just the four synchronous standalone/query scenarios for fixture
development and records `complete_matrix: false`. It does not satisfy the full
matrix. `--es384` selects the eight ES384 scenarios for focused validation and
also records an incomplete matrix; it can be combined with `--post` or `--quick`.
Missing prerequisites, errors, failed assertions or skipped tests fail
the full runner. Sanitized scenario choices, versions and counts are written to
`.artifacts/profiles-<run>/evidence.json` and uploaded by `smart-ehr.yml`.
The POST run repeats all 32 cases with long granular scopes and verifies actual
method and form length at the provider. Outgoing method and callback transport
are independent. Ordinary OAuth POST is also exercised by
`Rscript integration/connections/run-tests.R --post`.

## What the Docker sandbox can currently establish

The official SMART Dev Sandbox uses an unmodified, digest-pinned Launcher v2.
Its discovery still advertises asymmetric authentication without the required
algorithm list. Strict `smart_discover()` rejects it before constructing a
client or sending app credentials. Its FHIR proxy also permits uncredentialed
reads. Therefore its 46 diagnostic checks establish metadata rejection,
connectivity and synthetic data availability; they establish neither a complete
SMART app flow nor resource authorization enforcement.

## Independent client verification and unmodified external interoperability

The combined runner now executes `integration/smart/run-inferno.R` and validates
its complete sanitized report. It records
`independent_client_verification: "passed_modified_inferno_simulator"` only when
all 32 distinct rows and both sites' exact applicable test sets pass. A quick
run, missing report, duplicate row, unfinished interaction or skipped verifier
test cannot satisfy the gate. The report is copied into the combined run as
`inferno-evidence.json`; the standalone copy is under `.artifacts/inferno-<run>/`.

The separate [CI job](../../.github/workflows/smart-inferno.yml) installs the
checkout, runs that full command, and uploads only `evidence.json`. Raw Inferno
databases, HTTP exchanges and private diagnostic logs are excluded. The runner
removes its own containers and database volumes.

`external_interoperability` retains the stricter meaning of a completed app run
against an **unmodified** external implementation. That evidence is still absent.
The optional requirement remains explicit:

```sh
Rscript integration/smart/run-coverage.R --require-external
```

This executes the implemented suites, then fails the named
`unmodified_external_app_interoperability` requirement with an `unverified`
result explaining the simulator corrections. The old unconditional
`external_app_interoperability: not_implemented` placeholder is removed.
It does not require every candidate sandbox to accept discovery: an unrelated
Launcher defect cannot invalidate Inferno's request-verification results.
Use `run-tests.R --require-compatible-discovery` for the separate strict Launcher
discovery requirement. Neither gate treats diagnostic connectivity as app proof.

| External scenario | Current status | What is still needed |
| --- | --- | --- |
| SMART discovery | Strictly accepted by corrected local Inferno; unmodified Launcher/hosted Inferno blockers remain | Compatible unmodified deployment and positive strict discovery. |
| Standalone, Patient/Practitioner and retained two-site connections | Implemented with actual Shiny actions and Inferno verification | Unmodified server/vendor qualification; the two Inferno instances use the same implementation. |
| EHR entry for public/symmetric/RS384/ES384 registrations | Implemented using Inferno-generated launch URLs and per-registration verification | Unmodified vendor EHR validation; account/session-only EHR entry remains outside current support. |
| SMART refresh narrowing | Inferno responses and retained client scope policy checked | Independent server permission enforcement and refresh-token rotation remain unverified by Inferno. |
| Long authorization POST | Inferno GET/POST matrix implemented, including recorded bodies over 8 KiB | Unmodified vendor qualification and granular-permission fulfillment. |
| Form-post callbacks | Existing local SMART browser matrix | The pinned Inferno simulator only returns query callbacks. |
| P6 shared issuer/resource topology | Generic strict fixture coverage | Separately configured external registrations and resource destinations. |
| Inferno STU2.2 client suite | Pinned deployment, actual client verifier and sanitized evidence implemented | Qualify an upstream release with the simulator corrections; no hosted or certification pass is claimed. |

On 2026-09-12 the strict sandbox gate was rerun against these pinned images:
all 46 diagnostic assertions passed, but `sandbox_discovery_accepted` remained
false and the required gate exited unsuccessfully. The unmodified launcher
still omits `token_endpoint_auth_signing_alg_values_supported`. No external app
flow was attempted after that discovery failure.

A read-only preflight of the hosted Inferno client-suite FHIR base,
`https://inferno.healthit.gov/suites/custom/smart_client_stu2_2/fhir`, also failed
strict discovery on 2026-09-12: its issuer lacks the `sso-openid-connect`
capability. This confirms a live discovery blocker, not a completed or failed
client conformance suite. The implemented local driver uses the documented
metadata and nonce corrections instead. It also explicitly configures a bounded
one-year ID-token lifetime policy for Inferno and uses unreserved Basic credentials
to accommodate its parser. See [the Inferno gate](inferno.md) for these limits.
The [optional Oracle registration path](oracle.md) records what a future account
would enable; Oracle's unauthenticated endpoint cannot test these grant flows.

The runner selects sandbox test files explicitly. Adding a browser test to this
directory no longer makes the smoke suite execute it without its browser setup.
The package test runner permits only the known Windows filesystem-concurrency
skip; missing browser prerequisites are failures. Linux CI remains responsible
for that filesystem test. Generic Keycloak integration remains in its separate
workflow and does not substitute for the external SMART rows above.

Protocol checks used during this audit:
[SMART discovery/capabilities](https://hl7.org/fhir/smart-app-launch/STU2.2/conformance.html),
[SMART asymmetric authentication](https://hl7.org/fhir/smart-app-launch/STU2.2/client-confidential-asymmetric.html),
[OAuth refresh scope rules](https://www.rfc-editor.org/rfc/rfc6749.html#section-6),
and the [upstream launcher metadata handler](https://github.com/smart-on-fhir/smart-launcher-v2/blob/64374254347fdfa9625f9112c77813aa75fa9f3e/backend/routes/fhir/.well-known/smart-configuration.ts).
Public clients select `client-public`; SMART's confidential authentication-method
list does not require a `none` entry. The public registration regression and the
profile fixture test that distinction without weakening confidential checks.

## Recorded independent-client validation, 2026-09-12

The complete Inferno matrix ran from clean checkout `9ee37c5`, with the current
package installed for the Shiny app and mirai workers. Its sanitized proof is
`.artifacts/coverage-20260912-175525/inferno-evidence.json`. The subsequent
documentation commit does not change the tested implementation.

| Gate | Result |
| --- | --- |
| Inferno application matrix | 32 two-site scenarios, 64 sessions and 320 applicable upstream tests passed; no skipped or unfinished tests. Both launch modes, public/Basic/RS384/ES384, GET/POST and sync/mirai. |
| Retention and recorded exchanges in that matrix | All checks passed: original connection IDs survive navigation, A's explicit narrowed scope survives refresh, B retains search permission, every issued access token is used for matching Patient/Practitioner reads, and owner isolation/disconnect/logout prevent further requests. |
| Long Inferno authorization POST | All 32 recorded POST bodies (two sites in 16 scenarios) exceeded 8 KiB; range 9,406–9,456 bytes. |
| Simulator and evidence checks | 19 simulator examples and 44 evidence-contract assertions passed. Seven altered/partial copies of the completed report were rejected by the full-report validator. |
| SMART fixture GET / POST | 32 scenarios and 576 assertions for GET; 32 scenarios and 640 assertions for POST. No failures or skips. |
| Concurrent EHR launch fixture | 88 assertions passed; no skips. |
| Ordinary OAuth GET / POST | 120 assertions for each method; no skips. |
| Shared callbacks / refresh narrowing | 68 and 64 assertions respectively; no skips. |
| Account retention, isolated final rerun | All 80 assertions passed; no skips. |
| Independent Python conformance, corrected interpreter | All 379 assertions passed; no skips. |
| Unmodified SMART sandbox | All 46 diagnostics passed; positive discovery remains rejected. |
| Focused package and static checks | SMART client/launch, resource-binding and connection regressions passed, including the host-allowlist launch-path fix. R parsing, CI YAML parsing, local Markdown links and Git whitespace checks passed. |

The **initial combined process exited unsuccessfully**: its selected Python
interpreter lacked `cryptography`, and one account-browser login timed out.
Selecting the existing interpreter with the required dependency resolved the
conformance run. The account suite passed its isolated rerun without code changes;
the timeout's cause was not established. The original combined report is retained
unchanged rather than relabeled as a clean all-suite pass.
`.artifacts/final-validation.json` links that report and the successful isolated
reruns. No complete package-suite rerun or GitHub Actions execution is claimed
for this follow-up; the focused regressions and local integration gates above ran.
Installed-dependency build-version warnings and Chrome teardown EOF messages
were separate from assertion failures.

Inferno used the documented simulator corrections and bounded one-year ID-token
lifetime policy. Its verifier remains independent upstream code. This materially
advances P2 but does not establish unmodified vendor interoperability, server-side
permission enforcement, Inferno form-post callbacks or refresh-token rotation.

## Recorded client/connection refactor validation, 2026-09-11

The fixtures now configure optional `resource_bases`, `required_scopes` and
`label` on `OAuthClient`, pass a named client list to the separate manager, and
use `OAuthConnection`. `smart_client()` returns the same client type. The old
target constructors have been removed before release.

Status polling reuses records already read instead of constructing temporary
connections and repeatedly decrypting the same credentials. Each credential
read still checks the current configuration against the manager's captured
policy and the encrypted binding. The two-tab tests retain their 500 ms polling
interval. Generic fixture actions also report completion revisions, so a browser
assertion cannot accept an earlier operation's identical result text.

| Gate | Result |
| --- | --- |
| Complete package suite with browser tests enabled | 12,519 assertions passed; zero failures/errors. Only the known Windows filesystem-concurrency test skipped. Three installed-dependency build-version warnings were reported. |
| Ordinary OAuth retention, outgoing GET and POST | Four scenarios / 120 assertions for each outgoing method; no skips. |
| Shared callback routing | 68 assertions passed; concurrent tabs and foreign-owner isolation. |
| Refresh scope narrowing | 64 assertions passed; synchronous and real async transport, query and form POST callbacks. |
| Concurrent SMART EHR launches | 88 assertions passed; both sites, callback transports and execution modes. |
| SMART GET and POST matrices | 24 scenarios / 432 assertions for GET; 24 scenarios / 480 assertions for POST. Both complete matrices passed against the final installed implementation. |
| Independent Python cryptographic/strict-AS suite | 379 assertions passed, including RS384 verification and protected protocol combinations. |
| Unmodified Docker sandbox | 46 diagnostic assertions passed; owned containers were cleaned up. Positive external discovery and SMART app conformance remain open. |
| Package build/check | `R CMD check --no-tests --no-manual --ignore-vignettes`: zero errors, warnings or notes. Tests run separately. |

Final browser/package suite exits are recorded in
`.artifacts/refactor-final-suites.json`; the individual runners retain their
sanitized evidence files. The scope runner records its own evidence under
`integration/connections/.artifacts/scopes-<run>/`. Earlier failed runs remain
diagnostic history and are not counted as passing results.

## Recorded P7b validation, 2026-09-11

| Gate | Result |
| --- | --- |
| Package regressions and opt-in browser checks | 12,473 assertions passed, zero failures/errors. Full package results were combined with final-source reruns of complete async/browser test files, replacing earlier results rather than double-counting them. Only the known Windows filesystem-concurrency test remains skipped. |
| SMART outgoing POST | 24 scenarios / 480 assertions passed, zero skips; every authorization body exceeded 8 KiB. |
| SMART GET default | 24 scenarios / 432 assertions passed, zero skips. |
| Ordinary OAuth outgoing POST | Four browser scenarios / 120 assertions passed, zero skips, against the final installed source. |
| Independent Python cryptographic/strict-AS suite | 379 assertions passed, zero skips, including both outgoing methods and the protected combinations. |
| Unmodified Docker sandbox | 46 diagnostic assertions passed. Strict discovery remains unaccepted; no external SMART app-flow result is claimed. Owned containers were cleaned up. |
| Package build/check | `R CMD check --no-tests --no-manual --ignore-vignettes`: zero errors, warnings or notes. Roxygen help, Markdown links/examples and CI YAML were also checked. |

Combined package evidence is in `.artifacts/p7b-<run>/evidence.json`; browser
matrix evidence records its outgoing method. Dependency build-version warnings
and normal Chromote teardown EOF messages are recorded separately from failures.

## Coverage follow-up baseline, 2026-09-11 (before P7b)

The combined integration run used R 4.5.1, Chrome 152.0.7977.83, Node 22.16.0,
Shiny 1.13.0, mirai 2.7.1 and Docker Engine 28.5.1. Results:

| Suite | Result |
| --- | --- |
| Complete package suite, browser tests enabled | 12,391 assertions passed; zero failures/errors. Only the known Windows filesystem-concurrency test skipped. All 25 browser tests skipped by the earlier browser-disabled run executed successfully. |
| Independent Python cryptographic/strict-AS suite | 195 assertions passed, zero skips. |
| Generic retained connections | 104 browser assertions passed, zero skips. |
| Shared callback routing | 68 browser assertions passed, zero skips. |
| Generic refresh narrowing | 64 browser assertions passed, zero skips. |
| SMART registrations, identity, launch and narrowing | All 24 scenarios / 336 assertions passed, zero skips. |
| Concurrent EHR launches | 88 browser assertions passed, zero skips. |
| Unmodified Docker sandbox | 46 diagnostic assertions passed; positive discovery failed and external app flows remain untested. Owned containers/data volume were cleaned up. |
| Package build/check | `R CMD check --no-tests --no-manual --ignore-vignettes`: zero errors, warnings or notes; tests ran separately. |

`run-coverage.R --integration-only --require-external` returned failure and
recorded only `sandbox` and `external_app_interoperability` as unmet gates.
Those results must remain visible when evaluating readiness for a SMART release.
Unit/conformance runs can report installed-dependency build-version warnings;
Chromote can report websocket EOF during normal browser teardown.
