# Pinned Inferno client-test environment

`Rscript integration/smart/run-inferno-preflight.R` builds the pinned image,
checks provenance, starts a private Compose project, verifies discovery over
loopback HTTPS, runs the simulator regression specs, and removes its containers
and data volume. It does not run an
application flow. Install this checkout first. Docker Linux containers, Compose
v2, Python 3 and the R dependencies named in the runner are required.

The test kit is 1.0.3 at `980e54e4ed632b28267d797013399a8588772174`; its unchanged
Gemfile.lock selects Inferno Core 1.4.3. Ruby and Redis images are digest-pinned.
The build applies `simulator.patch` to two upstream endpoint implementation
files. The helper checks the changed-file set and source revision. Client-suite
verification assertions and the suite definition remain upstream originals.

## Simulator corrections and evidence limits

The unmodified kit cannot currently exercise this client's strict discovery and
optional identity profile. The local patch:

1. Advertises the already implemented OIDC support through `sso-openid-connect`
   and `jwks_uri` in SMART metadata.
2. Includes the authorization request's nonce in the signed initial ID token.
   Refresh ID tokens continue to omit nonce, as permitted by OIDC.

These are explicit local simulator changes, not an upstream release or hosted
Inferno pass. Every result must record `simulator_modified: true`, the source
revision, image ID and patch digest. The changes should be proposed upstream
separately; no issue or pull request has been submitted by this work. Remove the
patch only after qualifying an upstream release with the fixes.

No shinyOAuth discovery or identity check is relaxed. No verification test,
expected result or scope assertion is altered. The simulator still does not
establish server-side scope enforcement or complete refresh-scope conformance.

Sources: [SMART discovery](https://hl7.org/fhir/smart-app-launch/STU2.2/conformance.html),
[OIDC ID-token validation](https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation),
[OIDC refresh](https://openid.net/specs/openid-connect-core-1_0.html#RefreshTokenResponse),
and the [upstream client-suite limitations](https://github.com/inferno-framework/smart-app-launch-test-kit/blob/980e54e4ed632b28267d797013399a8588772174/lib/smart_app_launch/docs/smart_stu2_2_client_suite_description.md).

## Transport and local data

The host uses the existing loopback TLS proxy and repository test certificate.
R verifies its chain against the repository test CA. The internal container hop
is plain HTTP. This is local TLS integration evidence, not deployment certificate
validation. A new loopback port and private database are allocated per instance;
Redis is not published. Only the runner's own Compose project is removed.

The client suite needs Inferno, its worker, SQLite and Redis. It does not perform
FHIR profile validation, so no Java resource-validator container is started.
Only sanitized `evidence.json` belongs in ordinary CI artifacts. Other files in
the ignored run directory can contain private local diagnostics and must not be
uploaded or committed.

Validation on 2026-09-12: the pinned image built with its frozen dependency lock;
the two compatibility specs and 17 upstream simulator specs passed (19 examples,
zero failures). Strict discovery passed over verified HTTPS and the owned stack
was cleaned up. This establishes environment readiness, not application conformance.
