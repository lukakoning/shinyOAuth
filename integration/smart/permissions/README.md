# Independent FHIR permission enforcement

Run `Rscript integration/smart/run-permissions.R` from the repository root after
installing this checkout. Requires Linux containers, the existing R/browser
integration dependencies, and enough Docker resources for SQL Server and the
Microsoft FHIR server. No vendor registration is needed. The runner builds the
small authorization fixture, generates disposable TLS/signing keys, creates an
isolated Compose project and removes its containers and database on exit.
SQL uses its Developer edition for this local test environment.

The published **Microsoft FHIR Server 5.0.58** image is pinned by digest, with no
server code modifications. Its release tag points to
[`522833614e7935a7ab4591b13dab2fa027319721`](https://github.com/microsoft/fhir-server/tree/522833614e7935a7ab4591b13dab2fa027319721).
JWT authentication, role authorization and SMART clinical scope enforcement
are enabled. SQL Server and the Python base image are also pinned by digest.

The Python fixture is **our synthetic authorization server**, not an independent
SMART verifier. It implements the narrow public/standalone profile needed here,
using PKCE S256, signed identity, short-lived signed access tokens and rotating
refresh credentials. It transparently forwards resource requests and bearer
headers to Microsoft's server. It does not decide resource permissions or
generate Patient/search/error responses. Microsoft validates JWTs and enforces
the `smartUser` role's clinical scopes and patient compartment.

Two Patients and one Observation are seeded using a fixture-only administrative
credential. The public Shiny client authorizes `patient/Patient.rs` for one of
those Patients. In both synchronous and mirai modes it must:

- Read the authorized Patient and matching signed Patient identity.
- Search successfully and receive only the authorized Patient.
- Receive a FHIR `OperationOutcome` with 404 for the other, seeded Patient.
- Receive a FHIR `OperationOutcome` with 403 for the ungranted Observation.
- Narrow to `.r` through refresh, continue reading, and receive 403 for search.
- Restore the same retained connection in a new Shiny session and read again.

The denial probes intentionally use the general connection request API without
declaring an operation-specific scope requirement. This allows the requests to
reach the resource server; the existing SMART helper/client scope checks are
unchanged. Nine recorded resource exchanges per scenario must have the exact
expected paths/statuses and use the current issued token generation. The fixture's
administrative credential never enters the Shiny app.

The app and authorization server are exposed only on random loopback HTTPS
ports. SQL and the FHIR server remain within the Compose network. The server
fetches issuer metadata/JWKS through the internal `auth` service name and trusts
the generated test CA; the issuer and token audience remain the public FHIR
base. R validates the generated CA; only the isolated test browser ignores
fixture certificate trust errors, as in the other browser harnesses.

Only `evidence.json` is uploaded in CI. Runtime keys, SQL passwords, raw logs and
resource bodies remain in ignored local artifacts. This proves interoperability
with an independent FHIR authorization implementation for these cases. It does
not establish interoperability with an unmodified external SMART authorization
server or an EHR vendor, and does not cover granular query scopes or writes.
