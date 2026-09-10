# SMART integration baseline

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

The roadmap is in `playground/smart-fhir-roadmap.md`. Do not claim a completed
SMART or retained multi-site workflow until the corresponding integration gates
pass. Top-level Shiny deployment is the initial target; embedding, account
stores, and shared-worker coordination need their own evidence.
