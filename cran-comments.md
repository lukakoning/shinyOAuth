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
