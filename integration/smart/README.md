# SMART on FHIR integration tests

This directory contains test fixtures, runners and implementation notes for
SMART App Launch STU 2.2 (2.2.0). For application setup, start with the
[SMART on FHIR guide](../../vignettes/smart-on-fhir.Rmd) and
[multiple-authorizations guide](../../vignettes/multiple-authorizations.Rmd).
`playground/` contains runnable provider experiments.

The [SMART on FHIR CI job](../../.github/workflows/smart-fhir.yml) runs all the
SMART suites below with one R and Chrome setup. Generic retained OAuth browser
tests live in [integration/connections](../connections/README.md) and run with
the package browser, strict conformance and Keycloak suites in the
[OAuth integration job](../../.github/workflows/integration-tests.yml).

Run commands from the repository root after installing this checkout:

```sh
R CMD INSTALL .
Rscript integration/smart/run-ehr-browser.R
Rscript integration/smart/run-profiles.R
```

The browser runners require Chrome, `chromote`, `callr`, `webfakes`, `testthat`,
`withr`, `mirai`, `promises` and the package dependencies. HTTPS fixtures also
require Python 3; Inferno, permissions and sandbox runners require Docker
Compose. Apps and background workers must load the same installed checkout.
Failures, missing prerequisites and skipped scenarios fail the full runners.

| Coverage | Command after `Rscript integration/smart/` | Details |
| --- | --- | --- |
| Public EHR launch, concurrent grants and context | `run-ehr-browser.R` | [EHR launch](ehr-launch.md) |
| Four registrations, standalone/EHR launch, identity and retained refresh scopes | `run-profiles.R` | [Coverage map](coverage.md) |
| Long outgoing authorization POST | `run-profiles.R --post` | [Authorization POST](authorization-post.md) |
| Cross-site HTTPS callbacks | `run-profiles.R --cross-site` | [Extended coverage](extended-coverage.md) |
| Ordinary OIDC alongside SMART | `run-mixed.R` | [Mixed OIDC and SMART](mixed-oidc.md) |
| Independent client verification over two retained grants | `run-inferno.R` | [Pinned Inferno suite](inferno.md) |
| Patient and RelatedPerson identity | `run-inferno-extensions.R identity` | [Extended coverage](extended-coverage.md) |
| Account retention with Inferno grants | `run-inferno-extensions.R account` | [Extended coverage](extended-coverage.md) |
| Expiry, context changes, interrupted refresh/logout and consent | `run-lifecycle.R expiry`, `context`, `interrupted`, `consent` (separate runs) | [Extended coverage](extended-coverage.md) |
| Resource permission enforcement | `run-permissions.R` | [Microsoft FHIR Server fixture](permissions/README.md) |
| Official sandbox infrastructure and discovery | `run-tests.R` | [Docker sandbox](sandbox.md) |

The [coverage map](coverage.md) also documents `run-coverage.R`, which combines
package, cryptographic and browser checks for local verification. The
[scope evaluator note](scopes.md) explains semantic permissions and refresh
limits; the [retention notes](retention.md) describe ownership and storage.
Synthetic protocol response files are in `tests/testthat/fixtures/smart/`.

Runners write sanitized status, versions and assertion counts to
`.artifacts/<run>/evidence.json`. CI uploads those reports. Raw HTTP exchanges,
credentials, patient records and private fixture logs are excluded. Each Docker
runner cleans up its own containers and data volumes.

The strict local fixtures exercise package behavior. Inferno independently
verifies client requests, but its two documented simulator corrections mean
this is not an unmodified external or vendor interoperability result. The
official SMART Launcher's missing asymmetric signing-algorithm advertisement
still prevents strict discovery; passing its diagnostic rejection checks does
not establish an application flow. Use `run-tests.R --require-compatible-discovery`
to require a positive external discovery result. See [sandbox.md](sandbox.md),
[inferno.md](inferno.md) and the optional [Oracle validation path](oracle.md)
for evidence and remaining gaps.
