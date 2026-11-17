## R CMD check results

0 errors | 0 warnings | 0 notes

Checked on Windows 11 x64 with R 4.6.2 and R 4.5.1, using openssl 2.6.0.
Examples and vignettes pass, and the PDF reference manual builds successfully.

## Reverse dependencies

Checked arcgisutils 0.6.1 with CRAN shinyOAuth 0.7.0 and candidate 0.8.0.
Both checks return 0 errors, 0 warnings and 0 notes; there are no new problems.

## Current CRAN failures

This update fixes the encrypted-state decryption failures on CRAN's Fedora
R-devel checks following the release of openssl 2.6.0. It now requires
openssl >= 2.6.0 to verify authentication tags correctly.
