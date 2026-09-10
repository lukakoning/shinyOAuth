# How SMART permission checks work

This is the P4b implementation note. The evaluator and its login, refresh,
introspection and connection checks are implemented. Public SMART target
construction belongs to P4c; an ordinary `oauth_client()` or `oauth_target()`
still uses ordinary OAuth rules.

A scope is a permission requested from the server. In ordinary OAuth, it is a
name: `read` only matches `read`. SMART gives some scope names a defined meaning.
For example, `patient/Observation.rs` means reading and searching observations
for the patient selected by the server. The scope itself does not identify that
patient, and it does not guarantee that the server will return every record.

The implemented comparisons follow the
[SMART 2.2 scope specification](https://hl7.org/fhir/smart-app-launch/STU2.2/scopes-and-launch-context.html):

| Requested permission | Returned grant | Decision |
| --- | --- | --- |
| `patient/Observation.rs` | `patient/Observation.r patient/Observation.s` | Covered: the two grants combine. |
| `patient/Observation.r` | `patient/*.rs` | Covered by the resource wildcard. |
| `patient/*.r` | `patient/Patient.r patient/Observation.r` | Insufficient: enumerating known resources does not cover all future types. |
| `patient/Observation.r` | `user/*.cruds` | Insufficient: patient, user and system contexts stay separate. |
| `patient/Observation.r` | `patient/Observation.cud` | Insufficient: writing does not imply reading. |
| `launch/patient` | `launch` | Insufficient: context scopes match literally. |

An explicit compatibility policy can interpret v1 `.read`, `.write` and `.*`
as `.rs`, `.cud` and `.cruds`. Otherwise they remain unsupported. The evaluator
does not change request spelling. Invalid or unknown SMART resource syntax never
establishes permission merely because both sides contain the same text.

Simple granular constraints such as `?category=http://example.org|laboratory`
are compared byte for byte. An unconstrained grant covers a supported constrained
request; a constrained grant cannot establish unrestricted access. Different
queries yield an indeterminate comparison when their relationship is unknown.
Modifiers, chained parameters and `_filter` are currently unsupported, including
when their text matches. Checks that require coverage reject indeterminate
results. The package does not run a FHIR search engine to prove query equivalence.
Each side is limited to 256 distinct scopes and their combined text to 64 KiB.

The app distinguishes permissions it **requires** from permissions it would
**like**. A missing required permission rejects the SMART token result. Missing
optional permissions produce a `limited` connection, which can still perform
operations covered by its actual grant. Request-level checks use the same
evaluator. A local check cannot replace the FHIR server's access controls.

[SMART token responses](https://hl7.org/fhir/smart-app-launch/STU2.2/app-launch.html)
must explicitly return `scope`, both initially and after refresh. An explicit
empty string means no permissions. It is accepted only when no required
permission is missing; a missing field is rejected even with generic
`scope_validation = "none"`. Ordinary OAuth keeps its existing omission rules
and rejection of an explicit empty scope.

Refresh may narrow permissions. Our local continuity policy requires the new
grant to be provably covered by the immediately preceding grant, so a later
refresh cannot silently restore dropped permissions or acquire broader ones.
An enabled introspection scope check follows the same rule and can narrow the
effective grant. Rejected results do not update the previous token. SMART
connections require explicit grant evidence before becoming usable.

The policy is included in SMART client and target fingerprints, binding it to
pending authorization and retained credentials. The default generic fingerprint
format is unchanged. Tests in
[test-smart-scopes.R](../tests/testthat/test-smart-scopes.R) exercise comparisons,
strict parsing, actual callback/refresh paths, introspection, and request checks;
the existing generic scope tests remain regression gates. These are local
protocol tests, not an external SMART conformance result.
