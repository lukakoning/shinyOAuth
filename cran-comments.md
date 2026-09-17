## Resubmission

* Replaced "integrations" with "providers" in DESCRIPTION to avoid the
  incoming spell-check NOTE.
* Reduced CRAN test work to 48 representative regression-test files selected
  in tests/testthat.R. The extended suite runs when NOT_CRAN=true, which is
  explicitly set in the local runner and all existing GitHub Actions check
  jobs. No tests have been removed. A separate Ubuntu CI job checks the CRAN
  subset with NOT_CRAN=false.
* The selected suite completed in 52.4 seconds on Ubuntu 24.04 with R 4.3.3:
  2,553 expectations passed, no failures or warnings, and one existing timing
  test was skipped on CRAN. OIDC refresh fixtures now explicitly request
  openid, so their warnings do not depend on which tests ran earlier.
* A source-tarball R CMD check --as-cran --no-manual --timings passed with
  0 errors, 0 warnings, and 0 notes, including examples and vignette rebuilds.
  CRAN incoming and system-clock checks were disabled in this local check.

The checks below describe the original 0.6.0 submission.

## Test environments

* Local Windows 11, R 4.5.1, using a source tarball outside the checkout.
* GitHub Actions: Windows and macOS with R 4.6.1; Ubuntu with R 4.6.1,
  R 4.5.3, and R-devel (2026-09-15 r90540).
* Ubuntu with R 4.5.3, testthat 3.2.2, and shinytest2 0.4.1.

## R CMD check results

0 errors | 0 warnings | 0 notes.

## URL checks

urlchecker found no problems among the final source tarball's 98 distinct
URLs, using the CRAN URL database for package sources, including rendered
vignettes.

## Reverse dependency checks

Compared the sole optional reverse dependency, arcgisutils 0.6.1, against
CRAN shinyOAuth 0.5.0 and shinyOAuth 0.6.0 on Windows with R 4.5.1.

Used the CRAN Windows binary of arcgisutils with R CMD check --install=skip
--no-manual. Its examples, tests (52 assertions), and an additional OAuth
client-construction check passed with both shinyOAuth versions.

There were no new problems. Both checks reported the same existing warning
about a missing httr2::httr2_translate help link. The optional non-CRAN
arcgisbinding package was unavailable in both checks.
