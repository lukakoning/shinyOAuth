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
the existing revision-bound checker. A second step verifies the downloaded
preflight and API reports for each declared selection against the same
attempt and commit. Both steps must pass. A failed or cancelled selection job
also fails the aggregate. Artifact names
include the attempt number, preserving earlier attempts and avoiding upload
name conflicts. Retry the complete workflow with **Re-run all jobs** or start
a fresh dispatch. A partial rerun has an incomplete current-attempt report set
and cannot fill its missing rows with an earlier attempt's reports.

The aggregate upload includes only the original sanitized `evidence.json`
files and the summary, with a requested retention of 90 days. Repository and
organization artifact policies still apply. Durable release storage and
authenticated artifact provenance require separate release evidence.

To recheck the preflight and API evidence from downloaded selection directories,
use the same command as the aggregate job. Keep the selection artifact names
as the directory names under the download path.

```sh
python3 integration/openid/verify-release-artifact.py \
  --revision FULL_COMMIT_SHA --attempt ATTEMPT_NUMBER \
  --downloaded-reports integration/openid/.artifacts/release-inputs
```

## Verify and retain a completed attempt

Run from the repository root with Python 3.11 or later, R, the report checker
dependencies and GitHub CLI access to the repository's Actions artifacts. The
selected Git commit must be available locally. Download the bundle before the
aggregate expires. Supply a new output directory on the storage you want to
use for retention.

```sh
python integration/openid/verify-release-artifact.py --repository OWNER/REPO --revision FULL_COMMIT_SHA --run-id RUN_ID --attempt ATTEMPT_NUMBER --retain "PATH_TO_NEW_BUNDLE"
```

The command selects the aggregate artifact by workflow run and attempt, then
verifies and saves the original `run.json`, `artifact.json` and `artifact.zip`
with `receipt.json`. It makes the directory available once verification passes
and refuses an existing destination. The download preserves the original ZIP
bytes on PowerShell and POSIX shells.

The three original input files can also be collected manually. To replay a
saved bundle offline, supply those files and the same run identifiers.

```sh
python integration/openid/verify-release-artifact.py --repository OWNER/REPO --revision FULL_COMMIT_SHA --run-id RUN_ID --attempt ATTEMPT_NUMBER "PATH_TO_BUNDLE/run.json" "PATH_TO_BUNDLE/artifact.json" "PATH_TO_BUNDLE/artifact.zip"
```

The verifier checks the repository, successful workflow attempt, revision and
artifact identity against the saved API responses. It compares the ZIP's
SHA-256 with the artifact digest, replays the release checker on the original
client reports, and compares its result with the summary in the ZIP. Each
selection must contain one client, one preflight and one API report. The
verifier checks that all three identify the source checked out by that job.
It also verifies preflight TLS and cleanup, the API installation identity,
and each API plan's module list, variants and cancelled probe against the
suite lock and profile manifest at the selected commit.

The offline receipt includes the original SHA-256 digests of the preflight
and API reports for each selection. The standalone R checker continues to
evaluate client protocol evidence. Keep the ZIP, API responses and receipt
together. The GitHub responses captured at download time are the offline
receipt's trust source.
See the [run-attempt API](https://docs.github.com/en/rest/actions/workflow-runs#get-a-workflow-run-attempt)
and [artifact API](https://docs.github.com/en/rest/actions/artifacts#get-an-artifact).

## Replay and retain a failed client aggregate

For a completed failed GitHub attempt whose aggregate contains a failed summary
with selection diagnostics, add `--failed-attempt` to the retention command.

```sh
python integration/openid/verify-release-artifact.py --repository OWNER/REPO --revision FULL_COMMIT_SHA --run-id RUN_ID --attempt ATTEMPT_NUMBER --failed-attempt --retain "PATH_TO_NEW_BUNDLE"
```

The verifier checks the original ZIP digest, matches the client reports to the
summary's input hashes, and restores their original order before replaying
the release checker. The saved receipt must match the replayed diagnostics,
including missing and duplicate selections. A successful diagnostic replay
records `gate_passed = false` and `matrix_complete = false`. The original ZIP
also retains any uploaded companion reports.

To recheck the saved bundle without GitHub access, use the offline replay
command with `--failed-attempt` and the bundle's three original inputs.

## Interpret the result

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
A failed aggregate writes a failed summary when it can read the inputs and
committed policy, and then exits unsuccessfully. Both passing and failed
summaries retain the requested source and input-file hashes. The failed
summary also records a diagnostic
row for each declared selection in matrix order. A row can be `missing`,
`duplicate`, `invalid_report`, `reported_failure`, `package_version_mismatch`,
`source_mismatch`, `evidence_failed` or `passed`. It contains the SHA-256
digests of the input reports assigned to that row. A passing row records an
independent check of that selection within the failed attempt. The aggregate
remains failed.

With zero client inputs, the checker writes a failed summary with every row
marked missing. Malformed JSON or an unavailable committed policy can fail
before aggregation. Earlier successful summary formats remain suitable for
offline replay.

Individual selection workflows retain artifacts for seven days; the manual
matrix workflow requests 90 days for its aggregate. Permanent release storage,
signed provenance, operating-system coverage and second-provider selections
remain separate SA08 work. Acceptance requires an actual completed matrix and
a verified receipt for its selected revision.
