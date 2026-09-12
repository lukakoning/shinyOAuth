# SMART integration baseline

The optional [Oracle Health registration path](oracle.md) records the accepted
discovery preflights, future vendor-validation scenarios, and why its open
unauthenticated sandbox cannot close the SMART authorization gap.

See [the implemented-roadmap coverage map](coverage.md) for the combined runner,
the 24-scenario SMART registration/launch/identity/refresh browser matrix, and
the distinction between local test results and the blocked external sandbox gate.

The [local Docker sandbox setup](sandbox.md) uses official SMART Dev Sandbox
components with SMART Launcher v2. Run `Rscript integration/smart/run-tests.R`
from the repository root after installing this checkout for infrastructure smoke
tests and P4a's SMART discovery tests. It also maps
the browser and application-flow suites to P3-P5. The generic P3
[retention browser gate](../connections/README.md) now passes. P5a adds a
[SMART EHR browser app and tests](ehr-launch.md), using strict synthetic servers.
The [Inferno client conformance gate](inferno.md) specifies the
independent STU2.2 Client suite, profile matrix and required P4/P5 evidence.

Protocol baseline: SMART App Launch STU 2.2 (2.2.0), checked 2026-09-11.
The synthetic response files live in `tests/testthat/fixtures/smart/` so package
tests can also consume them. They contain invented credentials and context.
They characterize generic OAuth behavior; they are not a SMART server or
independent interoperability evidence.

| Contract | Evidence / future gate |
| --- | --- |
| Token extension snapshots and literal OAuth scopes | `test-smart-contracts.R`, `test-token-extra-fields.R` |
| Distinct routes; issuer-identified shared routes | `test-callback-registry.R`, `test-callback-iss-validation.R` |
| New legacy sessions start without credentials | `test-smart-contracts.R`; this is not a browser retention test |
| EHR launch requires an explicit adapter | Legacy wrapper rejects `iss`/`launch`; P5a adds `smart_launch_route()` to the manager wrapper |
| Standalone metadata without SSO | `standalone-metadata.json` deliberately omits OIDC issuer/JWKS |
| SMART discovery API | P4a `smart_discover()` implemented; live Launcher v2 rejected because its asymmetric algorithm advertisement is missing. Positive external gate remains open. Unit and HTTP fixtures validate the reader. |
| SMART registration, scopes and context | P4b/P4c1/P4d1 implemented; `smart_client()` opts into explicit SMART checks and interpreted refresh context |
| EHR entry and retained Patient reads | P5a `run-ehr-browser.R`: concurrent two-site launch, query/form_post, sync/mirai, Patient binding, refresh, owner isolation and logout; fixture evidence only |
| Supported registrations, both launch modes, signed identity and narrowing | `run-profiles.R`: public/HTTP Basic/RS384 across standalone/EHR, query/form_post and sync/mirai; Patient and distinct validated Practitioner, retained narrowed scopes and independent grants; strict local fixture evidence. |
| A-to-B navigation retains both connections | P3 implemented: real Chrome navigation, new Shiny sessions, independent refresh, owner isolation and disconnect. Query/form_post, sync/mirai; 104 assertions. |
| Independent SMART compatibility | P4/P5: record sandbox/tool version, registration, capabilities, transport and outcome |

Fixtures use `https://api.site-a.example/fhir/R4` as the approved FHIR base.
Discovery belongs at its `/.well-known/smart-configuration` suffix. A second
base on the same host must remain a separate resource binding. SMART `.rs` is
semantically equivalent to separate `.r` and `.s` grants; generic OAuth clients
continue comparing the literal tokens. A refresh without context must preserve
raw initial extras while replacing latest extras. P4d1 separately preserves
interpreted context when omitted and exposes changes through its revision.

Sources checked online:

- [SMART discovery and capabilities](https://hl7.org/fhir/smart-app-launch/STU2.2/conformance.html)
- [SMART authorization](https://hl7.org/fhir/smart-app-launch/STU2.2/app-launch.html)
- [SMART scopes and context](https://hl7.org/fhir/smart-app-launch/STU2.2/scopes-and-launch-context.html)
- [Asymmetric client authentication](https://hl7.org/fhir/smart-app-launch/STU2.2/client-confidential-asymmetric.html)
- [OAuth mix-up defenses](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.4.2)
- [JWA RSA signatures](https://www.rfc-editor.org/rfc/rfc7518.html#section-3.3)
- [OAuth scope semantics](https://www.rfc-editor.org/rfc/rfc6749.html#section-3.3)
- [jose signing implementation](https://github.com/r-lib/jose/blob/main/R/jwt.R)

P1 adds RS384 using jose's explicit `size = 384`, verified independently with
OpenSSL for assertions, JAR and DPoP. RSA defaults stay RS256. Its internal
structured preparation exposes exact outgoing state even with PAR, and binds
data-only manager context to the pending transaction. Legacy callbacks cannot
consume managed context; P3 supplies owner/session lifecycle checks.
The scope evaluator defaults to versioned literal OAuth coverage; SMART
semantics are selected explicitly by `smart_client()` in P4b/P4c1.

P4a adds `smart_discover()` with a plain list result containing the exact FHIR
base, discovery URL, validated metadata, version baseline and host policy. It
does not add a new R6 configuration object. Required metadata and conditional
SSO/asymmetric fields are checked separately from OIDC discovery. Server
capabilities never choose the client's registration, and extension URLs never
expand resource trust. The implementation reuses the package HTTP bounds and
TLS policy; redirects remain disabled even under the generic redirect option.
No automatic cache means a later call cannot mutate an earlier snapshot.

The live Docker run exposed a missing asymmetric signing-algorithm advertisement
in Launcher v2. `run-tests.R` records diagnostic assertions separately from
`sandbox_discovery_accepted` and `discovery_release_gate`; add
`--require-compatible-discovery` to require a successful live discovery result.
That gate currently fails with the pinned image. See [sandbox.md](sandbox.md)
for the upstream source evidence and required follow-up. Synthetic positive
tests do not satisfy that external interoperability gate.

P4a validation on Windows / R 4.5.1 (2026-09-10): 816 affected regression
assertions passed, including 260 new discovery assertions, with no failures or
skips and one installed-Shiny build-version warning. The Docker run passed all
46 diagnostic assertions; `--require-compatible-discovery` then exited with
failure because live discovery was rejected, as required. The report records
`sandbox_discovery_accepted: false` and `discovery_release_gate: "not_met"`.
Roxygen help rendering/example parsing, formatting/lint checks, source
installation, and `R CMD check --no-tests --no-manual --ignore-vignettes` passed;
the package check reported zero errors, warnings and notes. The runner removed
its isolated containers and data volume on exit.

P4a protocol sources rechecked on 2026-09-10: the SMART 2.2 conformance page and
asymmetric authentication profile linked above. P4b, P4c1 and P4d1 subsequently
added scopes, the client and baseline context/resource helpers. Remaining P4
items cover optional transport combinations, richer context, standalone browser
flows and the Inferno client matrix. P5a's local EHR test does not satisfy those
external gates.

P2 adds optional resource policy to the existing client and per-session
`OAuthConnection` handles that read the module's current reactive token.
Resource IDs enforce exact origin and base
paths before attaching credentials; two APIs on one host remain separate.
Absolute references use the same policy. Generic applications declare their
operation scopes explicitly. There is no inferred opaque-token audience or
SMART permission mapping. Session end releases the reference's token source.
`test-oauth-connections.R` and `test-resource-binding.R` cover these contracts.
P3 now supplies the optional manager, encrypted memory store, owner validation,
coordinated refresh and [real-browser retention evidence](retention.md).

Validation for P0-P2 on Windows / R 4.5.1 (2026-09-10): the complete unit suite
passed 11,031 assertions, with 26 browser/platform skips and three installed
dependency build-version warnings. After formatting, 189 focused assertions
passed again. Source build and installation passed. `R CMD check --no-tests
--no-manual --ignore-vignettes` reported zero errors, zero warnings and one note
from curl announcing the selected OpenSSL backend. The unit suite was run
separately with the current checkout installed for async workers. Local check
processes used the `C` locale and OpenSSL curl backend; no package defaults were
changed for those environment settings.

The roadmap is in `playground/smart-fhir-roadmap.md`. Do not claim a completed
SMART or retained multi-site workflow until the corresponding integration gates
pass. Top-level Shiny deployment is the initial scope; embedding, account
stores, and shared-worker coordination need their own evidence.
