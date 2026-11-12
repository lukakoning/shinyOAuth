**shinyOAuth protocol quality: implementation plan**

Prepared 2026-11-12 against shinyOAuth commit
`25318cc6488a2a98bfc83d484cbbdb3190854967` (version `0.7.0.9000`).
Status: researched and planned; implementation has not started. No conformance
suite, provider, or scanner was run during this investigation.

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
