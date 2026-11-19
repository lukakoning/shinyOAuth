**Source identity and release-source checks**

New OIDF client reports use schema 4. Preflight reports use schema 2. The
profile manifest remains schema 2. Reports record the harness checkout commit,
Git tree, development/clean status and SHA-256 hashes of tracked and untracked
source files, excluding ignored files. A combined fingerprint binds that file
inventory. Git `assume-unchanged` and `skip-worktree` flags classify a checkout
as development source. The inventory requires regular files.

The runners take a snapshot before private installation and regression checks,
then compare it again after those checks and after execution. Persistent changes
to source files, additions,
deletions, revision changes or cleanliness changes fail the command. Reports keep
the original and final source records and set `source_verified` only after the
comparison succeeds. Preflight and API reports now include checkout identity
as well as the suite's independently verified source revision.

A clean run installs from an uncompressed `git archive` of the exact commit,
with a fixed package prefix, `tar.umask` and LF line endings. This omits ignored files from the
installation input. Development runs build a private source package from the
working tree with vignettes disabled. Both paths record the actual installation
archive's SHA-256, package version and hashes of the installed package files.
A private `Meta/openid-source.json` marker links the installation to the source
snapshot. The marker itself is excluded from its file inventory.

API, client and shared-pool regression checks load that private installation
before exercising public package APIs. The runner verifies the namespace path
and compares the installation inventory before and after the checks; client
flows reuse the same installation. An unrelated namespace already loaded in
the caller causes a failure with fresh-Rscript guidance. It is not unloaded or
silently replaced. This prevents an older global installation from supplying
the APIs under test. API checks still receive no client-flow or protocol credit.

The runners verify the archive and installation before starting the suite and
again after all client apps/workers stop. Existing app and worker probes require
the expected private package namespace path. Together these checks link the
tested namespace, installed files, installation input and harness source.
Shared-pool reports carry the same proof in all four selections.

Client validation binds these records to the expected run context, just as it
binds image identities and suite instances. Missing records, changed hashes,
unverified end snapshots or an unrelated installation fail schema-4 validation.
Dirty development runs can pass their scenario gate while remaining ineligible
for release evidence. Their private source archive records the installation
input; the report does not publish uncommitted source contents.

Check one or more client reports against an independently selected commit:

```sh
Rscript integration/openid/run-release-source-check.R --revision FULL_COMMIT_SHA path/to/evidence.json
```

The command resolves that commit's tree and regenerates its canonical Git
archive. Every report must identify that same clean commit/tree, pass its client
gate, contain verified before/after source and installation records, and match
the independently regenerated archive hash. It rejects mixed revisions, dirty
runs, missing source proof and altered installation inputs. The GitHub workflow
runs this check against `GITHUB_SHA` after browser execution.

This command checks source policy. It does not check matrix completeness or
authenticate supplied JSON artifacts. Artifact provenance and profile-specific
revalidation still matter; SA08 retains complete release aggregation and durable
retention. The release checker accepts only schema-4 client reports. Schema-3
reports retain their historical scenario validation when their existing metadata
is valid; they are not upgraded or qualified by adding retrospective fields.

Raw source archives, private libraries and marker files stay under ignored
`.artifacts/` directories. The workflow uploads only the allowlisted sanitized
evidence JSON. Package runtime dependencies and the installed public API are
unchanged.

Validation at `8d2ec4d90e9645f546f2186f9bb6f0acd3fa2b6f` passed all 6,938
evidence assertions on Windows (R 4.5.1) and Linux (R 4.5.0 in Docker), including
130 source checks. Tests cover source edits while already dirty, additions and
deletions, masked Git index entries, ignored R files, altered installation inputs
and installed files, missing proof, malformed schema types, shared selections,
legacy reports and mixed source revisions. Test warnings and skips were zero;
Windows R retained its existing startup locale warnings.

| Local client selection | Case-loop seconds | Sanitized evidence directory |
| --- | ---: | --- |
| Windows / sync smoke | 37.88 | `smoke-20261118-232701-e4d98e650690` |
| Linux / mirai shared pool | 44.47 | `shared-pool-20261118-222901-b66c614e4459` |

Both scenario gates and release-source checks passed from the same clean commit.
The complete commands took approximately 223 and 297 seconds. Both installations
used canonical archive SHA-256
`06e468c86d227c9131b5a8d9bd1f0127e259eabd52fe3be8080027eb2c33dc63`.
The Windows checker independently verified both saved installations and their
serialized reports, then accepted their combined source records against the Git
commit/tree and regenerated archive. Missing or altered metadata and a mixed
revision were rejected. Schema-3 hosted reports from the earlier release review
still pass scenario revalidation and fail the new release-source check.

An initial implementation at `5ca6879bf03f21a218c1289c09ba0a18ddb046f7`
passed Windows smoke, while the Linux regression suite detected different archive
bytes after changing Git configuration. No Linux browser report was produced.
Archive inspection showed CRLF versus LF payloads with matching file modes.
The fixed producer explicitly sets `core.autocrlf=false` and `core.eol=lf`.
Those preliminary logs and the original Windows report remain development
records with their original fields; acceptance was rerun at the fixed commit.

Hosted smoke with the new workflow source gate passed:
[run 44412596895](https://github.com/lukakoning/shinyOAuth/actions/runs/44412596895).
Preflight, API and browser reports identify the same clean commit and identical
before/after source snapshots. The hosted installation uses the same canonical
archive hash as both local platforms. The downloaded ZIP matched GitHub artifact
digest `sha256:051c90de6469cdd42d63c5d336858baf7c9c605c7645b562d1ee38c0aa54b000`.
Independent revalidation passed, including the release-source CLI on Windows.
The GitHub job took 397 seconds: preflight 51, API/evidence checks 105 and the
browser command 143; its three-case loop took 20.91 seconds. The new source gate
completed successfully after browser execution. An independent implementation
review found no actionable defects in the tested source.
SA02's OIDF source and installation acceptance is complete.
Matrix completeness and durable release evidence remain SA08 work.
