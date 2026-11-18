**Source identity and release-source checks**

New OIDF client reports use schema 4. Preflight reports use schema 2. The
profile manifest remains schema 2. Reports record the harness checkout commit,
Git tree, development/clean status and SHA-256 hashes of tracked and untracked
source files, excluding ignored files. A combined fingerprint binds that file
inventory. Git `assume-unchanged` and `skip-worktree` flags classify a checkout
as development source. The inventory requires regular files.

The runners take a snapshot before regression checks and compare it again before
installation and after execution. Persistent changes to source files, additions,
deletions, revision changes or cleanliness changes fail the command. Reports keep
the original and final source records and set `source_verified` only after the
comparison succeeds. Preflight and API reports now include checkout identity
as well as the suite's independently verified source revision.

A clean run installs from an uncompressed `git archive` of the exact commit,
with a fixed package prefix and `tar.umask`. This omits ignored files from the
installation input. Development runs build a private source package from the
working tree with vignettes disabled. Both paths record the actual installation
archive's SHA-256, package version and hashes of the installed package files.
A private `Meta/openid-source.json` marker links the installation to the source
snapshot. The marker itself is excluded from its file inventory.

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
