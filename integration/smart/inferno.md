# Inferno SMART client conformance gate

Use the [Inferno SMART App Launch test kit](https://inferno.healthit.gov/test-kits/smart-app-launch/)
alongside the [Launcher v2 sandbox](sandbox.md). Inferno evaluates requests from
our runnable Shiny app; the launcher supplies the separate browser and FHIR
integration environment. This document schedules the Inferno gate for P4/P5.
No shinyOAuth SMART flow has been run against Inferno yet, and the current
`run-tests.R` command runs only the sandbox smoke tests.

## Suite and version

Select **SMART App Launch STU2.2 Client**, suite ID `smart_client_stu2_2`.
The similarly named `smart_stu2_2` suite tests a server and does not establish
conformance of shinyOAuth as a client.

Reviewed on 2026-09-10: test kit 1.0.3 (updated 2026-08-26), source commit
[`980e54e4ed632b28267d797013399a8588772174`](https://github.com/inferno-framework/smart-app-launch-test-kit/tree/980e54e4ed632b28267d797013399a8588772174).
The [suite definition](https://github.com/inferno-framework/smart-app-launch-test-kit/blob/980e54e4ed632b28267d797013399a8588772174/lib/smart_app_launch/client_stu2_2_suite.rb)
defines the client profiles; the
[client guide](https://github.com/inferno-framework/smart-app-launch-test-kit/blob/980e54e4ed632b28267d797013399a8588772174/lib/smart_app_launch/docs/smart_stu2_2_client_suite_description.md)
describes registration, test execution, and limitations. Pin the kit and its
Docker dependencies when building the local CI fixture; record the deployed
version separately for hosted runs.

## Required roadmap runs

| Phase | Client profile and scenario | Evidence required |
| --- | --- | --- |
| P4 | Public client, standalone launch | Real app sends S256 and the discovered FHIR `aud`, completes the code exchange, reads the supplied Patient using the issued token, and refreshes. |
| P4 | Confidential symmetric client, standalone launch | Same scenario with the registered secret and supported authentication method. |
| P4 | Confidential asymmetric client, standalone launch | Same scenario with a temporary RS384 key and registered public JWKS; both code and refresh requests exercise client assertions. Keep the existing independent Python signature tests. |
| P5 | EHR launch for each supported App Launch client profile | Inferno initiates the real app's registered launch route. Browser evidence proves `iss`/`launch` entry and the correct context; finish Inferno's request-verification tests too. |
| Future explicit backend-services work | Backend Services Confidential Asymmetric Client | Add a separate client-credentials scenario only when that SMART profile is implemented. It cannot substitute for the App Launch RS384 run. |

The P4 implementation adds a real app fixture and an Inferno driver under
`integration/smart/`, with separate sessions/results per matrix row. P5 extends
that driver for EHR entry. These are implementation tasks, not skipped tests
already present in this repository.

## Procedure for each app run

1. Start the pinned local Inferno deployment and app, or use the hosted suite
   for a manual run. Follow the kit's setup instructions for the chosen version.
   For Docker CI, configure an origin reachable by both the browser and the R
   process; container `localhost` is not the host app. Record the actual transport.
2. Create a fresh client-suite session and select the matrix row's profile.
   Register the app's exact redirect URI(s), a unique client ID, and either the
   symmetric secret or public JWKS as applicable. P5 also registers the app's
   launch URL. Use temporary test credentials.
3. Supply synthetic launch context, a Patient in **Available Resources**, and,
   for identity tests, a matching **FHIR User Relative Reference** and resource.
   Use a read of that resource; a generic echoed response is insufficient evidence
   of selecting the intended Patient.
4. Use the FHIR base displayed by the client suite as the app target. Discover
   endpoints from that base; do not reuse the SMART launcher's URLs or Inferno's
   separate demonstration/reference server. Run the registration and client-access
   groups, complete the real app flow, read the resource, and explicitly refresh.
5. Resume Inferno after the interactions and collect its authorization-request,
   token-request and token-use verification results. An issued token or HTTP 200
   alone does not establish a pass. For EHR runs, retain browser evidence of the
   launch entry, since the client suite can accept either launch mode.

## CI and evidence contract

At P4, add a separate Inferno job with the pinned deployment, browser dependencies,
app fixture, driver, readiness checks and cleanup of its own project. Expand CI
path filters to the SMART/authentication R APIs, fixtures, driver and workflow.
The current sandbox smoke job remains a fast prerequisite. P5 adds the EHR rows
to the same release gate.

Every applicable verification test must pass. Failures, errors, unfinished
interactions or unexpected skips block that scenario. Record suite ID, kit
version/source and image digests, shinyOAuth revision, client profile, launch mode,
RS384 selection where applicable, transport, browser version and per-test results.
Record which scenarios actually ran; a standalone pass cannot fill an EHR row.

Inferno stores request/response details, which can contain credentials and
context. Keep raw exports out of Git and ordinary CI artifacts. Publish only a
sanitized result summary under the ignored `.artifacts/` tree, excluding tokens,
codes, launch handles, secrets, private keys and patient/context payloads.

## Coverage limits

The reviewed client suite is described upstream as draft; the hosted test kit
has medium maturity. Its simulated server can respond successfully to requests
that its later verification tests reject. Its scope checks do not establish
scope syntax, continuity, fulfillment of context scopes or resource authorization.
Its FHIR simulation serves supplied resources or static responses.

Keep our own SMART scope/context tests, ID-token validation, callback defenses,
refresh continuity and resource-binding checks, plus the P3/P5 browser ownership
and retention tests. Keep the independent RS384/strict-AS and Keycloak suites.
An Inferno result covers the selected tests and version, not full certification
or proof of server-side authorization enforcement. Resolve tool compatibility
issues explicitly without weakening the client's protocol validation.
