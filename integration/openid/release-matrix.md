# Declared OIDF client release matrix

The [matrix](release-matrix.json) declares 39 required profile/transport pairs.
This is the OIDF client-evidence part of SA08. Provider interoperability,
platform coverage, artifact authentication and durable publication need their
own release decisions and evidence.

The [first verified hosted report](release-evidence/45017983714-attempt-1.md)
records all 39 selections at `92bedf1d` and the scope limits for that revision.

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

Every full run first tests the artifact verifier and reads the selection list
from the committed matrix policy. The tests run the same companion-verification
command used in the aggregate. A valid synthetic report set must exit zero. Changing
the API probe's cancellation result must produce exit code 1.

To run only these preparation checks on GitHub, use the same workflow with
`report_checks_only` enabled.

```sh
gh workflow run openid-release-matrix.yml --ref BRANCH_OR_TAG -f report_checks_only=true
```

The aggregate upload includes only the original sanitized `evidence.json`
files and the summary, with a requested retention of 90 days. Repository and
organization artifact policies still apply. The signing job attests the
original ZIP of a successful attempt. Retain a verified archive for storage
beyond the artifact's expiration.

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
with `receipt.json` and `release-report.md`. It makes the directory available
once verification passes and refuses an existing destination. The download
preserves the original ZIP bytes on PowerShell and POSIX shells.

`release-report.md` is the publication summary for that verified attempt. It
records the package and suite revisions, locked images, fixture configuration,
and every profile and transport's finished and available module counts,
verdicts, and coverage limits. It also lists accepted suite warnings and skips
with the policy checked by the verifier. Keep the summary with the original
bundle so the results can be checked against the artifact digest.

The three original input files can also be collected manually. To replay a
saved bundle offline, supply those files and the same run identifiers.

```sh
python integration/openid/verify-release-artifact.py --repository OWNER/REPO --revision FULL_COMMIT_SHA --run-id RUN_ID --attempt ATTEMPT_NUMBER "PATH_TO_BUNDLE/run.json" "PATH_TO_BUNDLE/artifact.json" "PATH_TO_BUNDLE/artifact.zip"
```

Add `--report-output "PATH_TO_NEW_REPORT.md"` to regenerate the Markdown from
the local bundle. The verifier writes the file after a successful replay, uses
LF line endings and requires a new output path.

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

## Verify signed provenance

The `attest` job signs the digest of the original aggregate ZIP after the
aggregate passes. Its signing permissions are scoped to that job. It checks
that the aggregate comes from the current workflow attempt before issuing the
attestation. [GitHub artifact attestations](https://docs.github.com/en/actions/concepts/security/artifact-attestations).

Add `--require-attestation` when retaining or replaying a signed attempt.
The verifier uses `gh` to check the signature, repository, GitHub-hosted
runner, signer workflow and source revision. It matches the expected run and
attempt against the signed certificate and compares the named subject and
digest with the original ZIP. The verification receipt retains its existing
format. The command reports the attestation result separately.
[GitHub CLI verification](https://cli.github.com/manual/gh_attestation_verify),
[Fulcio certificate fields](https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md#13614157264121--run-invocation-uri).

The default attestation check fetches the signature online. For offline
verification, save the signature and trusted roots while online. Run the
following commands in the directory where you will keep those files.

```sh
gh attestation download "PATH_TO_BUNDLE/artifact.zip" --repo OWNER/REPO --predicate-type https://slsa.dev/provenance/v1
python -c "import pathlib, subprocess; pathlib.Path('trusted_root.jsonl').write_bytes(subprocess.check_output(['gh', 'attestation', 'trusted-root']))"
```

For a release archive with a separate Sigstore JSONL, pass the downloaded
proof and your trusted root file explicitly. The packaging section below
shows how to carry the proof inside the archive.

```sh
python integration/openid/verify-release-artifact.py --repository OWNER/REPO --revision FULL_COMMIT_SHA --run-id RUN_ID --attempt ATTEMPT_NUMBER --bundle-input "PATH_TO_RELEASE.zip" --require-attestation --attestation-bundle "PATH_TO_ATTESTATION.jsonl" --attestation-root "PATH_TO_TRUSTED_ROOT.jsonl"
```

Use a trusted root obtained from the GitHub CLI and kept under your control.
The signature identifies the original GitHub ZIP inside the release archive.
The verifier checks the archive's derived receipt and Markdown by replaying
its original inputs. [Saving a Sigstore bundle](https://cli.github.com/manual/gh_attestation_download),
[saving trusted roots](https://cli.github.com/manual/gh_attestation_trusted-root).

## Run OIDF and provider companions at one revision

Enable `provider_companions` to run the 39 OIDF selections and the eight
`oidc-provider` browser selections from the same commit in one workflow.
The link job requires both aggregate uploads from the current attempt.
It records their names, IDs and original ZIP SHA-256 digests together with
the repository, commit, run and attempt. The signing job attests the OIDF
aggregate ZIP and the link ZIP after both matrices and the link succeed.
[Provider matrix scope](../oidc-provider/README.md#run-the-provider-release-matrix).

```sh
gh workflow run openid-release-matrix.yml --ref BRANCH_OR_TAG -f provider_companions=true
```

For a passing run, retain the original ZIP for
`openid-provider-release-link-attempt-ATTEMPT_NUMBER` and the two matrix ZIPs.
Keep the workflow attempt and OIDF aggregate metadata JSON as you would for
standalone OIDF replay. Run the paired verifier with the expected repository,
revision, run and attempt. [GitHub CLI verification](https://cli.github.com/manual/gh_attestation_verify).

```sh
python integration/openid/verify-release-artifact.py --repository OWNER/REPO --revision FULL_COMMIT_SHA --run-id RUN_ID --attempt ATTEMPT_NUMBER --paired-link "PATH_TO_LINK.zip" --provider-archive "PATH_TO_PROVIDER.zip" "PATH_TO_RUN.json" "PATH_TO_OIDF_ARTIFACT.json" "PATH_TO_OIDF.zip"
```

The verifier authenticates the link ZIP against the exact signer and
invocation, matches both original ZIP digests to the signed manifest, and
replays the OIDF evidence and provider summary. The JSON receipt includes the
link digest, both aggregate references and the provider report count.
[Provider scenario replay](../oidc-provider/README.md#run-the-provider-release-matrix).

For offline verification, save the Sigstore bundle for the link ZIP and
independently trusted roots as described above. Pass them with
`--attestation-bundle` and `--attestation-root` to the paired verifier.

### Retain a completed paired attempt

Run the collector from a checkout that contains the selected commit. Supply
a new destination directory on the storage where you want to keep the evidence.

```sh
python integration/openid/verify-release-artifact.py --repository OWNER/REPO --revision FULL_COMMIT_SHA --run-id RUN_ID --attempt ATTEMPT_NUMBER --retain-paired "PATH_TO_NEW_DIRECTORY"
```

The collector fetches the exact successful workflow attempt and verifies the
downloaded Sigstore proof for the link ZIP with GitHub CLI's trusted roots.
It fetches the two aggregate ZIPs by the artifact IDs in that signed link.
After replay succeeds, it publishes the evidence directory with the original
`link.zip`, `artifact.zip` and `provider.zip`, their GitHub metadata, the
workflow attempt JSON, `attestation.jsonl`, `receipt.json` and the OIDF
Markdown summary.
[GitHub artifact API](https://docs.github.com/en/rest/actions/artifacts#get-an-artifact).

For offline replay, use the paired verifier with these original files and
the retained `attestation.jsonl`. Supply your independently trusted root file
with `--attestation-root`.

## Package a verified attempt for release storage

From the repository root, pack the three original files of a passing attempt
into a new ZIP. The verifier replays the originals before creating the archive.

```sh
python integration/openid/verify-release-artifact.py --repository OWNER/REPO --revision FULL_COMMIT_SHA --run-id RUN_ID --attempt ATTEMPT_NUMBER --bundle-output "PATH_TO_NEW_RELEASE.zip" "PATH_TO_BUNDLE/run.json" "PATH_TO_BUNDLE/artifact.json" "PATH_TO_BUNDLE/artifact.zip"
```

The outer archive holds the unchanged metadata and GitHub ZIP, plus the
recomputed JSON receipt and Markdown summary. Its entries have fixed metadata
and the two generated files use LF line endings. Record the outer SHA-256
when placing it in shared storage.

Verify the archive offline from a checkout that contains the expected commit.
The check replays the original reports and compares both generated files with
the stored receipt and summary.

```sh
python integration/openid/verify-release-artifact.py --repository OWNER/REPO --revision FULL_COMMIT_SHA --run-id RUN_ID --attempt ATTEMPT_NUMBER --bundle-input "PATH_TO_RELEASE.zip"
```

### Include the attestation in the release archive

Use the downloaded Sigstore JSONL and your trusted roots when packaging a
signed attempt. The packer verifies the exact JSONL bytes it will save as
`attestation.jsonl` inside the ZIP. Keep your trusted root file separately.
[GitHub offline verification instructions](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/verify-attestations-offline).

```sh
python integration/openid/verify-release-artifact.py --repository OWNER/REPO --revision FULL_COMMIT_SHA --run-id RUN_ID --attempt ATTEMPT_NUMBER --bundle-output "PATH_TO_NEW_RELEASE.zip" --require-attestation --attestation-bundle "PATH_TO_ATTESTATION.jsonl" --attestation-root "PATH_TO_TRUSTED_ROOT.jsonl" "PATH_TO_BUNDLE/run.json" "PATH_TO_BUNDLE/artifact.json" "PATH_TO_BUNDLE/artifact.zip"
```

Replay an archive with embedded provenance using only your independently
trusted root file. The verifier checks the stored signature before replaying
the original reports and comparing the receipt and summary.

```sh
python integration/openid/verify-release-artifact.py --repository OWNER/REPO --revision FULL_COMMIT_SHA --run-id RUN_ID --attempt ATTEMPT_NUMBER --bundle-input "PATH_TO_RELEASE.zip" --require-attestation --attestation-root "PATH_TO_TRUSTED_ROOT.jsonl"
```

For a GitHub release asset, resolve the release tag to its commit with
`git rev-parse "TAG^{commit}"` and check that it equals the verified revision
before uploading. An asset attached to a release travels with that tag.
[GitHub releases](https://docs.github.com/en/repositories/releasing-projects-on-github/about-releases),
[release asset upload](https://cli.github.com/manual/gh_release_upload).

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
