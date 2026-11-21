# Declared OIDF client release matrix

The [matrix](release-matrix.json) declares 39 required profile/transport pairs.
This is the OIDF client-evidence part of SA08. Provider interoperability,
platform coverage, artifact authentication and durable publication need their
own release decisions and evidence.

| Profiles | Required transports | Entries |
| --- | --- | ---: |
| `smoke`, `basic`, `config`, `form-post`, `form-post-cross-site`, `refresh` | sync and mirai | 12 |
| `auth-post`, `auth-secret-jwt`, `auth-private-jwt` | sync and mirai | 6 |
| `fapi-dpop`, `fapi-dpop-full`, `fapi-oauth-dpop`, `fapi-oauth-dpop-reference` | sync and mirai | 8 |
| `fapi-oauth-mtls`, `fapi-oauth-mtls-auth`, `fapi-mtls`, `fapi-mtls-auth` | sync and mirai | 8 |
| `fapi-message-signing` | sync and mirai | 2 |
| `smoke`, `refresh` | future | 2 |
| `shared-pool` | mirai | 1 |

Every pair needs a separate top-level client report. Shared-pool child reports
do not substitute for the standalone authentication selections. Smoke cannot
substitute for Basic or a full FAPI selection. Do not combine prior revisions
to fill missing entries.

## Check a selected revision

Run from the repository root, supplying all 39 original sanitized client
reports and a new output path:

```sh
Rscript integration/openid/run-release-check.R --revision FULL_COMMIT_SHA --output integration/openid/.artifacts/release-summary.json path/to/client-1/evidence.json path/to/client-2/evidence.json
```

The example shows two input placeholders; a complete invocation needs every
declared pair. Inputs are explicit files, rather than a recursive artifacts
search. Preflight and API reports are not client reports and cannot fill a
matrix entry.

The command reads the matrix, profile manifest, suite lock and package version
from the selected commit's Git blobs. Editing a later working copy's matrix
does not reduce that revision's requirements. A revision without a committed
matrix cannot acquire one retrospectively through this command. The existing
[source-only check](source-identity.md) remains available for historical
schema-4 evidence.

The aggregate check rejects missing, duplicate and unexpected selections,
mixed revisions, dirty source, unknown callback policy, altered installations
and changed protocol outcomes. Each report must match the selected clean
revision/tree, package version and independently regenerated canonical LF
archive. Initial, post-regression and final installation records must agree
within each report, including shared-pool children. New shared-pool reports
retain the post-regression record; older reports without it remain historical.
Separate valid working-tree and installed-file fingerprints can differ across
systems; they are not required to match each other across reports.

The checker supplies the declared profile, transport and `opaque_error_v1`
policy to the existing protocol validators, recomputes each result and checks
the stored assessment against that result. JSON object-key order does not
change the meaning of evidence; ordered arrays remain ordered. A recorded
`gate_passed = true` alone is insufficient.

## Run the matrix on GitHub

The manual **OpenID declared release matrix** workflow reads the matrix from
the selected branch or tag revision and runs every declared pair, with at most
three selection jobs at once. It calls the existing OpenID workflow from the
same commit, so preflight, API inventories, regression tests, browser execution
and the release-source check stay part of each selection. GitHub documents
[same-commit local workflow calls](https://docs.github.com/en/actions/how-tos/reuse-automations/reuse-workflows).

```sh
gh workflow run openid-release-matrix.yml --ref BRANCH_OR_TAG
```

This dispatch starts all 39 selections; use `openid-conformance.yml` for a
single selection. The matrix does not stop other selections after one fails.
The aggregate job downloads matching artifacts from its own workflow run and
attempt, keeps their directories separate, and gives every client report to
the existing revision-bound checker. Preflight and API reports are retained
separately from client matrix inputs. A failed or cancelled selection job
fails the aggregate even if its client report passed. Artifact names
include the attempt number, preserving earlier attempts and avoiding upload
name conflicts. Retry the complete workflow with **Re-run all jobs** or start
a fresh dispatch. A partial rerun has an incomplete current-attempt report set
and cannot fill its missing rows with an earlier attempt's reports.

The aggregate upload includes only the original sanitized `evidence.json`
files and the summary, with a requested retention of 90 days. Repository and
organization artifact policies still apply. Durable release storage and
authenticated artifact provenance require separate release evidence.

## Interpret and retain the result

`matrix_complete = true` means all declared OIDF client selections passed their
existing scoped gates. Each entry retains its own upstream-plan, coverage and
limitation assessment. Configuration's suite no-store limitation, encrypted
OAuth state-length warnings, mTLS server-enforcement limits and deliberately
partial selections remain visible. Completing the matrix does not turn those
limits into full coverage or establish certification.

The summary contains the selected source/archive identity, hashes of the
committed policy files, each original input file's SHA-256 and recomputed
assessments. It contains no input paths, source contents, raw callback URLs,
credentials or private diagnostics. Existing output files are not overwritten.
A failed aggregate writes a failed summary when it has valid inputs/policy and
exits unsuccessfully; malformed inputs or missing committed policy fail before
aggregation. Both passing and failed summaries retain the requested source
and input-file hashes, so a failed receipt still identifies the exact bytes
that were checked.

Preserve the original sanitized reports and their provenance together with the
summary and policy hashes. File hashes detect changes relative to the retained
bytes; they do not authenticate who produced a JSON report. This command does
not verify workflow artifact digests, preflight/API inventories, operating-system
coverage or second-provider selections. Those remain separate release checks.

Individual selection workflows retain artifacts for seven days; the manual
matrix workflow requests 90 days for its aggregate. This command does not
publish a release asset or provide durable retention. SA08 remains
partial until the declared matrix actually runs against one selected revision
and its evidence has an approved durable home. Synthetic matrix-validator
tests and selected real client reports do not establish that execution.
