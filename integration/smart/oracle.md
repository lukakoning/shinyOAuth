# Optional Oracle Health interoperability validation

Oracle registration is not available for the current validation work. No Oracle
authorization, token exchange or retained-connection scenario has been executed.
The local Inferno work has no dependency on an Oracle account.

## What the open sandbox can establish

The [Oracle service-root documentation](https://docs.oracle.com/en/industries/health/millennium-platform-apis/mfrap/srv_root_url.html)
publishes this unauthenticated, read-only FHIR R4 base:

`https://fhir-open.cerner.com/r4/ec2458f2-1e24-41c8-b71b-0e701af7583d`

It is useful for experimenting with FHIR responses and reference resolution.
It cannot establish SMART authorization, token refresh, identity validation or
retained grants: successful reads require no authorization. These are the gaps
being addressed here, so adding an open-endpoint smoke test would not advance
the external SMART gate. The existing SMART sandbox already supplies independent
FHIR connectivity/data diagnostics. Continue with Inferno for client validation.

## What registration would enable

Oracle's [application testing instructions](https://docs.oracle.com/en/industries/health/millennium-platform-apis/build-smart-on-fhir-apps/)
describe creating a CernerCare account, registering an application in code Console,
selecting synthetic patients, and launching the app against the secure sandbox.
Its [SMART developer overview](https://docs.oracle.com/en/industries/health/millennium-platform-apis/smart-developer-overview/)
documents a 15-minute propagation delay for application configuration changes.
Console browser launch and embedded PowerChart testing are separate environments;
the latter requires developer-program access. Start with top-level browser launch.

Secure FHIR bases:

| Persona | Base |
| --- | --- |
| Provider | `https://fhir-ehr-code.cerner.com/r4/ec2458f2-1e24-41c8-b71b-0e701af7583d` |
| Patient/proxy | `https://fhir-myrecord.cerner.com/r4/ec2458f2-1e24-41c8-b71b-0e701af7583d` |

Read-only research on 2026-09-12 loaded the current checkout and called
`smart_discover()` against both secure bases. Both were accepted with explicit
endpoint-host allowlists containing the FHIR host and `authorization.cerner.com`.
Their metadata advertised public, symmetric and asymmetric clients, HTTP Basic,
RS384/ES384, S256, offline access, SMART v2 permissions and authorization POST.
The patient base advertised `context-standalone-patient`; the provider base did
not. Public and HTTP Basic standalone patient configurations were constructed
locally with unused placeholder registration values. No authorization was sent.
Advertisements and configuration acceptance are not proof of runnable registrations.

Once an account becomes available:

1. Register the actual application redirect and EHR launch URLs, then keep the
   client ID, secret or private key outside Git. Confirm which sandbox client
   profiles can actually be registered; metadata alone is insufficient.
2. Start with standalone patient access at the patient base and provider EHR
   launch at the provider base. Use synthetic context chosen in the console.
   A standalone clinician flow must use a supported scope/context combination.
3. Complete code exchange with S256, read the contextual Patient, validate and
   read `fhirUser` when requested, then explicitly refresh and read again.
   Patient identity may itself be a Patient; clinician identity is a separate case.
4. Expand to public, HTTP Basic, RS384 and ES384 across supported launch modes.
   Qualify authorization POST and form-post callbacks independently.
5. Exercise navigation into a fresh Shiny session, retained connections,
   independent refresh, disconnect and local account switching. Qualify narrowed
   refresh grants and preserve any provider limitation as an unverified row.

Request `offline_access` only for scenarios that need it. Oracle documents
different [online/offline refresh lifetimes](https://docs.oracle.com/en/industries/health/millennium-platform-apis/fhir-authorization-framework/).
App-local logout and remote EHR logout are distinct lifecycle events.

The two secure URLs above share a tenant and issuer. They can exercise separate
resource bindings but do not constitute two independent EHR systems. A two-site
portability result needs separately configured sites/datasets; cross-vendor
evidence needs another implementation.

Run hosted vendor scenarios on demand or before release, recording the checkout,
date, persona, registration profile, launch mode and sanitized outcomes. Never
turn an unavailable account, service outage or unexecuted row into a passing
interoperability result. Avoid exporting tokens, secrets, launch handles or
patient payloads in ordinary CI artifacts.
