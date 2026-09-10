# Local SMART Dev Sandbox

This is an R4-only setup using the official
[SMART Dev Sandbox](https://github.com/smart-on-fhir/smart-dev-sandbox)
components: SMART Launcher, HAPI FHIR with Synthea sample data, and the patient
browser. It provides an external implementation for the SMART roadmap's
integration tests. The current tests establish discovery, FHIR connectivity,
sample data and launcher configuration. Application authorization, retention,
and EHR launch remain the P3-P5 gates below.

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
R2/R3 and backend-service UI are disabled in this initial profile.

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
`smart-launcher@688c7e2e0527c16e8d4fc63ad3e294029e1d6480`. Those source revisions
are review references; the deployed binary identities are the Compose digests.
The launcher reports package version 2.0.0 and HAPI reports 5.0.2 with FHIR 4.0.1.

The observed SMART metadata advertises standalone/EHR launch, public and
symmetric clients, patient/encounter context, and offline access. It omits
`grant_types_supported` and `code_challenge_methods_supported`, both required
by [SMART 2.2 discovery](https://hl7.org/fhir/smart-app-launch/STU2.2/conformance.html).
It does not advertise `sso-openid-connect`, `permission-v2`, or asymmetric
client authentication. Listing `openid`/`fhirUser` scopes is not proof of an
SSO capability. Record actual behavior separately from advertised features.

This simulator permits uncredentialed FHIR reads. The smoke read checks data
and proxy connectivity; authorization enforcement requires the strict fixture
and suitable external server evidence. The stack uses loopback HTTP and
synthetic records; production TLS and real-browser ownership remain separate
release gates. Sandbox success is not SMART certification.

Before claiming SMART 2.2 interoperability, P4 must resolve the metadata gaps
through an upgraded upstream build or another conforming reference server.
Preserve a test of the strict adapter's rejection of this older metadata.
Do not inject missing capabilities or disable PKCE, signature, issuer, or
browser checks to make a full-flow test pass. Any supported legacy profile
needs its own explicit policy and evidence.

## Where the roadmap uses this stack

The future filenames below describe planned tests, not currently skipped tests.

| Checkpoint | Tests / extension | Required evidence |
| --- | --- | --- |
| P0 supplement, now | `test-sandbox-smoke.R` and `run-tests.R` | Pinned services start; local discovery, R4 metadata, sample Patient data, proxy and picker work; image/capability report saved. |
| P1 signing | Existing `../conformance/test-rs384-interop.R` and strict AS matrix | Independent RS384 verification stays required; this sandbox's metadata does not establish asymmetric client authentication support. |
| P3 retained connections | Add a two-site Compose profile and `test-browser-retention.R` | Two isolated launcher/FHIR datasets; generic manager A-to-B navigation creates new Shiny sessions, retains both grants, refreshes each, and disconnects B only. Repeat using SMART targets after P4. |
| P4 discovery | Add `test-smart-discovery.R` | Discover at the full FHIR base; record capabilities; reject missing mandatory SMART 2.2 metadata; resolve fixture gaps before a positive 2.2 release gate. |
| P4 standalone | Add a real app fixture and `test-browser-standalone.R` | Browser consent/selection, S256 and FHIR `aud`, matching Patient retrieval, supported scopes, refresh/context continuity; identity and clinician tests require advertised SSO support. |
| P5 EHR launch | Add `test-browser-ehr-launch.R` | Launch from the real launcher with `iss` and `launch`; clean continuation, selected patient/encounter, concurrent launch isolation, and mixed callback rejection. |
| P6 and P7c | Extend site topology and browser matrix | Same-issuer resource binding and iframe/navigation/cookie behavior, with separate evidence per supported mode. |

At P3-P5, expand CI path triggers to the implemented R APIs and app fixtures,
install the browser dependencies, and make the relevant browser suites required.
Do not replace the existing unit, strict conformance, or Keycloak suites.
Simulation controls and absent features are recorded as limitations, not
alternative passing outcomes for a required feature.

To upgrade images, inspect the upstream changes, resolve new digests with
`docker buildx imagetools inspect`, update Compose, and rerun the smoke suite
and every implemented application-flow gate. Review the metadata diff and
record the new versions and capabilities alongside the results.
