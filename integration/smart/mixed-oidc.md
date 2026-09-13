# Ordinary OIDC and SMART in the same browser app

Install the current checkout and run:

```sh
Rscript integration/smart/run-mixed.R
```

The combined coverage runner and SMART browser CI job include this gate.
It requires eight completed scenarios: managed OIDC or an ordinary OIDC module,
query or form-post callbacks, and synchronous or actual mirai transport.
The application and providers use different HTTPS loopback hosts. Browser TLS
trust is relaxed only for the fixture certificate; R requests verify against
the fixture CA, including the SMART request-local TLS minimum.

The OIDC client is constructed with `oauth_client()`, literal OIDC scopes and
UserInfo. It has no SMART scope policy or launch context. Its provider rejects
a SMART `aud` parameter. The other client uses `smart_discover()` and
`smart_client()` with Patient context and validated `fhirUser`.

Each scenario verifies both callback paths, validated OIDC identity/UserInfo,
resource reads, refresh, SMART retention across an OIDC redirect, local SMART
disconnect, and continued OIDC use followed by OIDC logout. Managed OIDC is
retained alongside SMART. The ordinary module retains its existing session
lifecycle: leaving the page to authorize SMART ends the old OIDC session, so
the test signs in again before checking simultaneous access. Ordinary-module
proactive refresh is explicitly enabled; this test does not change its default.

The ordinary module uses the same `oauth_connections_ui()` wrapper through
`additional_clients`; it never enters the manager's retained store. All app
operations use exported APIs. Only synthetic values and outcome booleans are
shown in the test UI. Sanitized scenario/version/count evidence is written to
`.artifacts/mixed-<run>/evidence.json`. A missing, failing or skipped scenario
fails the runner.

On 2026-09-13 all eight scenarios passed against a fresh installation of the
checkout: 60 assertions, no failures or skips, Chrome 152, Shiny 1.13.0 and
mirai 2.7.1. The run's sanitized evidence is
`.artifacts/mixed-20260913-162104/evidence.json` (local artifact, excluded from Git).

## Remaining external qualification

These are package-owned fixtures. They establish composition coverage, not an
unmodified external SMART implementation's interoperability or certification.

On 2026-09-13 a fresh installation of this checkout ran strict `smart_discover()`
against both public candidates, without changing their metadata:

| Candidate | Strict preflight result |
| --- | --- |
| [SMART Health IT Launcher](https://launch.smarthealthit.org/v/r4/fhir/.well-known/smart-configuration) | Rejected: advertises asymmetric authentication but omits `token_endpoint_auth_signing_alg_values_supported`. |
| [Hosted Inferno STU2.2](https://inferno.healthit.gov/suites/custom/smart_client_stu2_2/fhir/.well-known/smart-configuration) | Rejected: supplies an issuer without the required `sso-openid-connect` capability. |

Neither candidate proceeded to an authorization or token exchange. The
`--require-external` coverage requirement therefore remains unsatisfied.
A compatible registered sandbox is still needed for an unmodified end-to-end
run; see the existing [Oracle registration path](oracle.md). The corrected
Inferno simulator and independently enforced Microsoft FHIR permissions remain
useful, separately identified evidence.
