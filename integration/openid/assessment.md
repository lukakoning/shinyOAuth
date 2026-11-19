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
| `client_limitations` | Historical HTTP callback rejections retaining query material. Legacy evidence keeps this limit; current cleanup evidence must establish the new policy before it is removed. |

The checker adds `upstream_module_selection_only` when a successful selection
does not cover the whole pinned module list. Every emitted limitation must have
an explicit category; an unreviewed code fails assessment rather than silently
disappearing. Historical `coverage_limitations` keep their original meaning.

## Rejected callback cleanup

New client contexts declare `callback_rejection_policy = "opaque_error_v1"`.
Each rejected HTTP callback then requires `callback_http.schema_version = 2`
and the same policy. The gate binds that policy to the trusted context and
requires the original rejection audit, zero exchange/resource traffic, an
unchanged nonempty pending state store, and a main-frame browser chain from
303 to the terminal 400. Both responses require privacy headers. The final
browser URL must match the observed network URL and contain only the expected
opaque error locator with an empty fragment. No callback values enter the report.

The fixture checks the original long credential values against both response
bodies and headers; it does not infer nonreflection from the locator-only
follow-up query. Separate package tests cover additional rejection and browser
inputs. The safe diagnostic is local to the serving UI/process; another worker,
expiry, eviction or unavailable cache returns a generic 400 without resuming
authorization. The original audit remains the source of the rejection reason.

Older reports remain valid only with their legacy proof and
`callback_cleaned = false`; they retain `http_callback_rejection_retains_query`.
They cannot acquire cleanup credit by changing the flag or retaining partial
new-proof fields. Consumers requiring cleanup must require the new policy in
their trusted context; report schema 4 alone does not establish it. The checker
removes the old query-retention limitation only after the selected callback
cases satisfy the new policy. A clean final address bar is not proof that the
original callback never entered browser history, server logs or synchronized
history.

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
