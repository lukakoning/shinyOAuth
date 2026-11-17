# shinyOAuth 0.8.0 release checks

Prepared on 2026-11-17 using the
[R Packages release guide](https://r-pkgs.org/release.html).

- [x] Set DESCRIPTION and NEWS to 0.8.0 for the new public features and openssl fix.
- [x] Keep NEWS flat and compare its entries with CRAN 0.7.0.
- [x] Review the current CRAN results and open issues; this release addresses #26.
- [x] Rebuild documentation, add an example for OAuth-only discovery, and group
      the helper with generic provider configuration in the reference index.
- [x] Document the encryption-format upgrade and worker restart requirements.
- [x] Check all 77 URLs with urlchecker.
- [x] Build the PDF reference manual.
- [x] Run `R CMD check --as-cran --no-manual` on Windows R 4.6.2 and R 4.5.1:
      both return 0 errors, 0 warnings and 0 notes, including examples,
      vignettes and the 49-file CRAN regression suite.
- [x] Inspect the source archive for version consistency, test selection,
      documentation consistency and exclusion of local infrastructure.
- [x] Complete the full local test suite with current dependencies: no failures
      and 31 browser tests skipped by the explicit browser gate. Fix the two
      order-dependent warnings in a telemetry test double; the telemetry rerun
      passes all 1,194 assertions without warnings or skips.
- [x] Compare arcgisutils 0.6.1 checks using CRAN 0.7.0 and candidate 0.8.0:
      both return 0 errors, 0 warnings and 0 notes.
- [x] Review all eight jobs in the cross-platform
      [reference run for e32267f5](https://github.com/lukakoning/shinyOAuth/actions/runs/44157096691):
      Linux release/devel/oldrel, macOS release, Windows release,
      minimum testthat, openssl 2.6.0 and the CRAN test selection all pass.
- [ ] Complete cross-platform CI for the final candidate commit.
- [ ] Maintainer review of the final source archive and cran-comments.md.
- [ ] Submit to CRAN after maintainer approval.

The local checks use isolated libraries, including openssl 2.6.0, S7 0.2.2,
otel 0.3.0 and otelsdk 0.3.0. The R 4.6.2 library also uses current CRAN
versions of the other dependencies.

The manual is built separately because the check commands use `--no-manual`.
Browser and provider integration tests run in the repository's integration CI;
the full local suite disables browser tests explicitly.

The reference CI run predates the 0.8.0 version bump. Relative to that commit,
the candidate's R code differs only by the new discovery example in roxygen
comments, and NAMESPACE is unchanged. One telemetry unit test now mocks SDK
span completion and verifies cleanup for both success and error outcomes.
The complete 0.8.0 source archive is checked locally on both Windows R versions.

The reverse-dependency comparison uses the CRAN Windows binary of 0.7.0 and
the built 0.8.0 source candidate in separate libraries. Both runs use the same
dependency versions. The optional, non-CRAN arcgisbinding package is unavailable
in both environments.

The existing deprecated request aliases continue to point users to their
replacements; no further deprecation stage is advanced in this release.

The test additions since 0.7.0 were reviewed again for CRAN portability.
Five of the six new test files are outside the CRAN selection. The remaining
file keeps small independent-decryption, forged-state rejection and legacy-state
rejection checks. Its exhaustive mutations, exact-byte checks and diagnostic
output checks run only in the full suite. New subprocess, exact 1 MiB boundary,
backend-error and serialization-dependent callback checks also skip on CRAN.
The crypto fixture is static data and does not require Python.

Fresh CRAN-mode checks on both Windows R versions pass 2,972 assertions with
nine deliberate skips and no failures or warnings. A separate check explicitly
including the backend file confirms its file-level CRAN skip. The affected
tests still pass all 900 assertions in full mode without warnings or skips.

Checked source archive SHA-256:
`aab739c697a18f9c41267831b1ae36ee2d8bdef1b730024c311fa9e247563088`.
