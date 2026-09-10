# SMART integration baseline

The [local Docker sandbox setup](sandbox.md) uses official SMART Dev Sandbox
components with SMART Launcher v2. Run `Rscript integration/smart/run-tests.R`
from the repository root for the current infrastructure smoke tests. It also maps
the planned browser and application-flow suites to P3-P5; those phases are not
implemented yet. The [Inferno client conformance gate](inferno.md) specifies the
independent STU2.2 Client suite, profile matrix and required P4/P5 evidence.

Protocol baseline: SMART App Launch STU 2.2 (2.2.0), checked 2026-09-10.
The synthetic response files live in `tests/testthat/fixtures/smart/` so package
tests can also consume them. They contain invented credentials and context.
They characterize generic OAuth behavior; they are not a SMART server or
independent interoperability evidence.

| Contract | Evidence / future gate |
| --- | --- |
| Token extension snapshots and literal OAuth scopes | `test-smart-contracts.R`, `test-token-extra-fields.R` |
| Distinct routes; issuer-identified shared routes | `test-callback-registry.R`, `test-callback-iss-validation.R` |
| New legacy sessions start without credentials | `test-smart-contracts.R`; this is not a browser retention test |
| EHR launch requires an explicit adapter | Legacy wrapper rejects `iss`/`launch`; P5 adds registered routes |
| Standalone metadata without SSO | `standalone-metadata.json` deliberately omits OIDC issuer/JWKS |
| A-to-B navigation retains both connections | P3: real browser, new Shiny session, refresh each, disconnect B |
| Independent SMART compatibility | P4/P5: record sandbox/tool version, registration, capabilities, transport and outcome |

Fixtures use `https://api.site-a.example/fhir/R4` as the approved FHIR base.
Discovery belongs at its `/.well-known/smart-configuration` suffix. A second
base on the same host must remain a separate resource binding. SMART `.rs` is
semantically equivalent to separate `.r` and `.s` grants; generic OAuth clients
continue comparing the literal tokens. A refresh without context must preserve
raw initial extras while replacing latest extras. Interpreted context is P4.

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
consume managed context; owner/session lifecycle is still a P3 requirement.
The scope evaluator defaults to versioned literal OAuth coverage; SMART
semantics remain P4.

P2 adds immutable generic targets and per-session references that read the
module's current reactive token. Resource IDs enforce exact origin and base
paths before attaching credentials; two APIs on one host remain separate.
Absolute references use the same policy. Generic applications declare their
operation scopes explicitly. There is no inferred opaque-token audience or
SMART permission mapping. Session end releases the reference's token source.
`test-oauth-connections.R` and `test-resource-binding.R` cover these contracts.
Retention, store coordination and a manager-owned callback lifecycle remain P3.

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
pass. Top-level Shiny deployment is the initial target; embedding, account
stores, and shared-worker coordination need their own evidence.
