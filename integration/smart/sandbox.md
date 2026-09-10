# Local SMART Dev Sandbox

This is an R4-only setup using the official
[SMART Dev Sandbox](https://github.com/smart-on-fhir/smart-dev-sandbox)
components: HAPI FHIR with Synthea sample data and the patient browser, with the
official [SMART Launcher v2](https://github.com/smart-on-fhir/smart-launcher-v2).
It provides an external implementation for the SMART roadmap's
integration tests. The current tests establish discovery, FHIR connectivity,
sample data, required SMART 2.2 discovery fields, public signing keys and launcher
configuration. The generic [P3 browser-retention gate](../connections/README.md)
now passes with synthetic OAuth providers. SMART application authorization,
the two-site sandbox repeat, and EHR launch remain the P4/P5 gates below.

## Run the smoke suite

From the repository root, with Docker Engine running in Linux-container mode,
Compose v2, and the package's R development dependencies installed:

```sh
Rscript integration/smart/run-tests.R
```

The runner starts a uniquely named Compose project, waits up to five minutes
for readiness, checks the running images against their pins, runs the tests
with zero skips, and removes its own containers and data volume on exit.
The first download is substantial; reserve at least 2 GB for the R4 service
plus capacity for Docker and the launcher. HAPI and the patient browser are
amd64 images; ARM hosts require Docker's amd64 emulation.

Only one copy can use the fixed loopback ports at a time. Stop a manually
started copy before using the automatic runner. No existing Keycloak stack is
changed. The dedicated `SMART sandbox smoke tests` workflow runs on changes to
this directory and can also be dispatched manually.

## Explore the sandbox manually

```sh
docker compose -f integration/smart/docker-compose.yml -p shinyoauth-smart-dev up -d
Rscript integration/smart/run-tests.R --existing
```

`--existing` validates the manual project's image pins and services, leaves it
running, and preserves its data. Open the launcher after readiness succeeds:

| Purpose | Local URL |
| --- | --- |
| Launcher UI | `http://localhost:18413` |
| SMART FHIR base (`iss` / authorization `aud`) | `http://localhost:18413/v/r4/fhir` |
| SMART discovery | `http://localhost:18413/v/r4/fhir/.well-known/smart-configuration` |
| Patient browser | `http://localhost:18412` |
| Direct HAPI R4 base, for fixture data and diagnostics | `http://localhost:18404/hapi-fhir-jpaserver/fhir` |

Use the **SMART FHIR base** in the future app target, not the direct HAPI URL.
FHIR traffic inside Docker goes from the launcher to `r4:8080`; browser URLs
remain on `localhost`. The patient picker uses only the local Synthea dataset.
R2/R3 are disabled with empty upstream URLs. Launcher v2 uses `PORT` and binds
to `0.0.0.0` inside its container; Docker publishes it only on host loopback.
The picker opens with `config=r4`, so the local configuration is mounted at
`/config/r4.json5`. Backend-service controls remain available in v2, but their
flows are not exercised by this smoke suite.

Stop the manual stack with:

```sh
docker compose -f integration/smart/docker-compose.yml -p shinyoauth-smart-dev down
```

Add `--volumes` only to discard that manual stack's synthetic data changes.
The launcher runs independently of a Shiny app. P4 will supply a runnable app
with distinct registered callback routes, followed by the P5 EHR launch route;
there is no `smart_target()` example to run against the current P0-P2 package.

## Evidence and current compatibility limits

Each ready test run writes `integration/smart/.artifacts/<project>/evidence.json`:
image references and actual IDs, time, R/Docker/launcher/HAPI versions, exact SMART
metadata, and test counts. CI uploads this file. It contains no token responses,
authorization codes, launch handles or patient resources. The report explicitly
marks application flows as untested at this checkpoint.

The image pins were resolved on 2026-09-10. The reviewed upstream revisions are
`smart-dev-sandbox@081def5427765661d49ec85aec1849f444f58618` and
`smart-launcher-v2@64374254347fdfa9625f9112c77813aa75fa9f3e`. Those source revisions
are review references; the deployed binary identities are the Compose digests.
The launcher image is `smartonfhir/smart-launcher-2`, pinned by digest in Compose;
it reports package version 2.0.1. HAPI reports 5.0.2 with FHIR 4.0.1.

The observed v2 metadata includes `grant_types_supported` with
`authorization_code` and `client_credentials`, and
`code_challenge_methods_supported: ["S256"]`, as required by
[SMART 2.2 discovery](https://hl7.org/fhir/smart-app-launch/STU2.2/conformance.html).
The smoke suite requires authorization-code support and S256 without `plain`.
It also checks the advertised `sso-openid-connect`, `permission-v2` and
`client-confidential-asymmetric` capabilities, `private_key_jwt`, the local
issuer/JWKS URLs, and a nonempty public RSA JWKS. These checks establish
discovery and key availability; they do not verify ID tokens or RS384 client
assertion exchanges. The `/env.js` simulator UI token is never saved in evidence.

This simulator permits uncredentialed FHIR reads. The smoke read checks data
and proxy connectivity; authorization enforcement requires the strict fixture
and suitable external server evidence. The stack uses loopback HTTP and
synthetic records; production TLS and real-browser ownership remain separate
release gates. Sandbox success is not SMART certification.

The previous `smartonfhir/smart-launcher` image (package 2.0.0) omitted the two
mandatory discovery fields; upgrading to `smart-launcher-2` resolves that gap.
P4 must still test the adapter against live v2 discovery and synthetic negative
fixtures that omit mandatory fields, plus actual authorization and refresh flows.
Do not inject missing capabilities or disable PKCE, signature, issuer, or
browser checks to make a full-flow test pass. Any supported legacy profile
needs its own explicit policy and evidence.

## Where the roadmap uses this stack

The future filenames below describe planned tests, not currently skipped tests.

| Checkpoint | Tests / extension | Required evidence |
| --- | --- | --- |
| P0 supplement, now | `test-sandbox-smoke.R` and `run-tests.R` | Pinned v2 launcher and services start; required discovery fields, local public keys, R4 metadata, sample Patient data, proxy and picker work; image/capability report saved. |
| P1 signing | Existing `../conformance/test-rs384-interop.R` and strict AS matrix | Independent RS384 verification stays required; advertised asymmetric authentication alone does not establish successful RS384 exchanges. |
| P3 generic retention / P4 sandbox repeat | P3 implemented in `integration/connections/`; add a two-site Compose profile with P4's SMART targets | The generic Chrome gate passes query/form_post and sync/mirai. P4 adds two isolated launcher/FHIR datasets and repeats A-to-B navigation, independent refresh and disconnect with SMART registration, scopes and context. |
| P4 discovery | Add `test-smart-discovery.R` | Exercise the adapter against live Launcher v2 metadata at the full FHIR base; reject missing mandatory SMART 2.2 fields in negative fixtures. |
| P4 standalone | Add a real app fixture and `test-browser-standalone.R` | Browser consent/selection, S256 and FHIR `aud`, matching Patient retrieval, supported scopes, refresh/context continuity; identity and clinician tests require advertised SSO support. |
| P5 EHR launch | Add `test-browser-ehr-launch.R` | Launch from the real launcher with `iss` and `launch`; clean continuation, selected patient/encounter, concurrent launch isolation, and mixed callback rejection. |
| P4/P5 independent conformance | Add the [Inferno STU2.2 Client gate](inferno.md) and real-app driver | Separate public, symmetric and RS384 asymmetric runs, followed by EHR runs; require Inferno's request-verification results as well as browser/resource evidence. |
| P6 and P7c | Extend site topology and browser matrix | Same-issuer resource binding and iframe/navigation/cookie behavior, with separate evidence per supported mode. |

The generic P3 gate has its own `connection-retention.yml` workflow watching R
APIs and browser fixtures. Its fixtures make no SMART conformance claim. The
two-site sandbox repeat is scheduled with P4 so it tests the actual SMART adapter
and its launch parameters, rather than treating generic retention as SMART support.
At P4/P5, expand the sandbox CI path triggers to the implemented R APIs and app fixtures,
install the browser dependencies, and make the relevant browser suites required.
Do not replace the existing unit, strict conformance, or Keycloak suites.
Inferno's client suite provides independent request checks; its planned setup,
version reference, registration procedure and coverage gaps are in [inferno.md](inferno.md).
Simulation controls and absent features are recorded as limitations, not
alternative passing outcomes for a required feature.

To upgrade images, inspect the upstream changes, resolve new digests with
`docker buildx imagetools inspect`, update Compose, and rerun the smoke suite
and every implemented application-flow gate. Review the metadata diff and
record the new versions and capabilities alongside the results.
