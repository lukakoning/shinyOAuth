# Interpreting client evidence

Client reports keep the suite's raw verdicts and the existing local evidence
gate. Their completion fields answer different questions:

| Field | Meaning |
| --- | --- |
| `gate_passed` | Every selected scenario has the expected suite verdict, matching browser/application/protocol evidence, provenance and verified cleanup. |
| `selection_complete` | The declared selection passed that gate. A small selection can satisfy this field. |
| `upstream_plan_complete` | The gate passed and the selection executed every pinned upstream module for its exact plan and variant. This includes only the existing, specifically evidenced non-`PASSED` exceptions. It does not cover other variants or every specification requirement. |
| `coverage_complete` | The existing conservative coverage decision. Its behavior is retained for compatibility; it also accounts for selected policy, cache and mTLS fixture limits. Read the independent fields and categorized limits alongside it. |
| `assessment.status` | `validated` after the complete evidence gate; `unavailable` on failure or before client scenarios are checked. A successful API inventory alone has no validated client assessment. |
| `assessment.certification_status` | Always `not_assessed`. These local engineering reports do not establish an OIDF certification or an attestation. |

All completion and assessment values come from `openid_check_report()` or
`openid_check_shared_report()`. Revalidation recomputes them from the actual
evidence and trusted manifest; it does not trust stored summary fields. A
consumer should use that returned check. A failed check resets completion to
false and returns an unavailable assessment without passing counts.

## Counts and accepted verdicts

`assessment.module_counts` records `available`, `selected` and `finished`.
Available modules come from the pinned plan/variant specification; selected
modules come from the declared profile; finished modules are the matching,
validated results. `suite_verdict_counts` preserves the numbers of `PASSED`,
`WARNING` and `SKIPPED` results. A full module count alone cannot pass the gate.

`accepted_non_passed_results` identifies each exact module, suite instance, raw
verdict and policy. The current exceptions are:

- Basic/Configuration/Form Post's unsigned-ID-token case may finish `SKIPPED`
  only with the existing `reject_unsigned_id_token` rejection proof. This is a
  stricter package policy.
- The three encrypted-state OAuth happy paths finish `WARNING` only with the
  existing `state_length_over_128` advisory proof and otherwise successful
  protocol/application evidence. The advisory alone is not a determination of
  client nonconformance.

No generic `WARNING`, `REVIEW` or `SKIPPED` acceptance was added. Unexpected
verdicts, missing advisory/rejection proof, incomplete cases, stale provenance
and missing cleanup still fail the gate.

## Categorized limits

`assessment.limitations` gives the existing limitation codes distinct meanings:

| Category | Examples and interpretation |
| --- | --- |
| `selection_scope` | A subset of upstream modules, one authentication/sender-constraint pairing, unsigned metadata over verified TLS, resource requests in the main process or sequential shared-pool reuse. These describe tested scope. They do not each imply a specification violation. |
| `interoperability_advisories` | The verified encrypted-state length warning. Keep its evidence and explain its scope independently of module completion. |
| `provider_limitations` | The pinned suite's `no-store` JWKS, simulated resource server's missing certificate-misuse denial, exact certificate registration, incomplete mTLS authentication denial checks and comprehensive-plan public-client/PKCE limitations. These findings concern the test environment and the evidence it can supply. |
| `client_limitations` | Rejected HTTP callbacks retaining query material in the browser address bar. This remains a package improvement to implement. |

The checker adds `upstream_module_selection_only` when a successful selection
does not cover the whole pinned module list. Every emitted limitation must have
an explicit category; an unreviewed code fails assessment rather than silently
disappearing. Raw `coverage_limitations` remain unchanged for older consumers.

The shared-pool report recomputes every child selection before aggregating.
Its counts sum the four selected plan/variant instances, including repeated
plan names with different variants. Its `upstream_plan_complete` is true only
if every child covers its full plan; the current eight-case selection is false.
Child assessments and raw results remain available separately.

## Current examples

These describe a successful, fully validated selection with its declared
manifest; they are not new live execution results.

| Selection | Selection complete | Upstream plan complete | Legacy coverage complete | Independent finding |
| --- | --- | --- | --- | --- |
| `smoke` | true | false | false | Three Basic modules only. |
| `basic` / `form-post` | true | true | true | Thirteen `PASSED` results and the specifically evidenced unsigned-token `SKIPPED` result. |
| `config` | true | true | false | All six modules execute; the suite cannot establish a warm-key-cache refresh. |
| `fapi-oauth-dpop` | true | true | false | All eleven modules execute; three retain the exact state-length warning. |
| `fapi-oauth-dpop-reference` | true | true | true | All eleven modules pass; the declared configuration and browser limits remain visible. |
| The four full mTLS selections | true | true | false | All nine or twenty-one selected modules execute; independent server-enforcement and registration limits remain. |
| `auth-post`, `auth-secret-jwt`, `auth-private-jwt` | true | false | false | Each selects two modules from the larger comprehensive plan. |
| `shared-pool` | true | false | false | Eight sequential cases across four selections. |

The schema-4 wire format remains compatible. Older schema-3/4 reports can be
revalidated to obtain the new assessment without rewriting their retained
records. Source qualification, a complete release matrix and durable release
evidence retain their separate [source](source-identity.md) and SA08 checks.
Use the [requirement map](requirements.md) for normative duties and the
[scope map](scope.md) for scenario outcomes.
