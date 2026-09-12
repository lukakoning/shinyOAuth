# Inferno SMART client conformance gate

Use the [Inferno SMART App Launch test kit](https://inferno.healthit.gov/test-kits/smart-app-launch/)
to evaluate requests from the real Shiny app. The [pinned local environment](inferno/README.md)
builds and passes strict discovery plus simulator regressions using
`Rscript integration/smart/run-inferno-preflight.R`. It explicitly patches two
simulator compatibility defects while keeping upstream verification tests intact.
The application driver is `Rscript integration/smart/run-inferno.R`; the preflight
alone does not run an app. The existing
`run-tests.R` command remains the separate [Launcher sandbox](sandbox.md) smoke gate.

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

Source review on 2026-09-11 found a preflight concern in the pinned
[mock server metadata](https://github.com/inferno-framework/smart-app-launch-test-kit/blob/980e54e4ed632b28267d797013399a8588772174/lib/smart_app_launch/endpoints/mock_smart_server.rb):
its SMART document includes `issuer` but omits `sso-openid-connect` and `jwks_uri`;
key information is in a separate OIDC document. Our strict SMART reader rejects
that combination. A read-only hosted preflight on 2026-09-12 against
`https://inferno.healthit.gov/suites/custom/smart_client_stu2_2/fhir` also failed
strict discovery because the issuer lacks `sso-openid-connect`. No client
conformance scenario was run against that hosted deployment. On 2026-09-12 the
local environment added explicit server-side metadata and initial ID-token nonce
corrections, with patch/source provenance in evidence. This advances testing
against independent upstream assertions but cannot be described as an unmodified
upstream or hosted Inferno pass. Discovery, signatures, issuer, audience, nonce
and expiry remain validated. See the
[patch rationale and limits](inferno/README.md).

## Required roadmap runs

| Phase | Client profile and scenario | Evidence required |
| --- | --- | --- |
| P4 | Public client, standalone launch | Real app sends S256 and the discovered FHIR `aud`, completes the code exchange, reads the supplied Patient using the issued token, and refreshes. |
| P4 | Confidential symmetric client, standalone launch | Same scenario with the registered secret and supported authentication method. |
| P4 | Confidential asymmetric client, standalone launch | Same scenario with temporary RS384 and ES384 keys and registered public JWKS; both code and refresh requests exercise client assertions. Keep the existing independent Python signature tests. |
| P5 | EHR launch for each supported App Launch client profile | Inferno initiates the real app's registered launch route. Browser evidence proves `iss`/`launch` entry and the correct context; finish Inferno's request-verification tests too. |
| Future explicit backend-services work | Backend Services Confidential Asymmetric Client | Add a separate client-credentials scenario only when that SMART profile is implemented. It cannot substitute for the App Launch RS384 run. |

The driver runs eight scenarios: public, HTTP Basic, RS384 and ES384, each with
standalone and Inferno-initiated EHR launch. Each uses a fresh Shiny process,
browser context and two Inferno test sessions on separate deployments. The app
authorizes both sites, reads each supplied Patient and distinct validated
Practitioner, and retains the same connection IDs in a new Shiny session.
It narrows site A from `.rs` to `.r`, blocks subsequent searches and widening,
refreshes both grants independently, disconnects B while A still works, and
logs out. A separate browser context cannot access either connection. Query callbacks and
synchronous token transport are covered in this initial matrix.

`--quick` runs only public standalone and records `complete_matrix: false`.
Install the current checkout before either command; the child app and mirai
workers use the selected R library. Chrome, Python 3, Docker Linux containers
and Compose v2 are required in addition to the runner's R dependencies.

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

The driver builds the pinned deployment, checks discovery, runs 19 simulator
specs, performs the browser matrix and cleans up its own stack. Its result-gate
regressions reject missing, duplicated, skipped, unfinished and unrelated tests.
The sandbox smoke gate is separate: Launcher discovery failure cannot determine
the outcome of a successful Inferno client-verification run.

Every applicable verification test must pass. Failures, errors, unfinished
interactions or unexpected skips block that scenario. Record suite ID, kit
version/source and image digests, shinyOAuth revision, client profile, launch mode,
RS384 selection where applicable, transport, browser version and per-test results.
Record which scenarios actually ran; a standalone pass cannot fill an EHR row.
The result gate requires the exact five applicable upstream test IDs per
registration, rather than counting arbitrary passing tests.
Additional driver checks read the owned session's exchanges in memory. They
require one code exchange per site, two refreshes for A and one for B, exact
resource paths and request counts, explicit returned narrowed scopes, and
Patient/Practitioner reads using the current token after every token response.
No additional requests may escape after a locally rejected search, widening,
foreign-owner read, disconnect or logout. Only counts and booleans are exported.

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

Inferno issues one-year ID tokens. The app explicitly selects a 366-day maximum
lifetime, recorded as `max_id_token_lifetime_seconds`, instead of the package's
one-day default. This deployment policy does not disable signature or claim
validation. Basic registrations use random unreserved credentials because the
pinned upstream Basic parser does not form-decode credential components. It
does not verify interoperability for secrets containing reserved characters.
Those cases retain their independent strict-AS coverage.

The two deployments use the same independent upstream implementation, with
separate issuers, registrations, databases and synthetic data. This verifies
multi-connection behavior; it is not evidence from two different EHR vendors.
The search response is an explicitly supplied empty Bundle. Scope narrowing
is checked in returned scopes and client behavior, because Inferno does not
enforce resource authorization. Its refresh token does not rotate; rotation
remains covered by the strict local fixtures.

Validation on 2026-09-12: all eight core application scenarios passed against
the installed checkout, with 40 applicable upstream tests passing, 19 simulator
examples passing and 39 result-gate assertions passing. This is evidence from
the locally modified simulator and unchanged upstream verifier. Two-site retained
connections and the wider transport matrix were separate extensions to that run.
The subsequent two-site run passed all eight scenarios with 80 upstream tests,
19 simulator examples and 44 evidence-contract assertions. Every scenario also
passed the additional recorded-exchange, narrowing and browser-lifecycle checks.

Keep our own SMART scope/context tests, ID-token validation, callback defenses,
refresh continuity and resource-binding checks, plus the P3/P5 browser ownership
and retention tests. Keep the independent RS384/strict-AS and Keycloak suites.
An Inferno result covers the selected tests and version, not full certification
or proof of server-side authorization enforcement. Resolve tool compatibility
issues explicitly without weakening the client's protocol validation.
