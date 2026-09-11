# EHR launch implementation and browser tests

The [coverage map](coverage.md) adds a 24-scenario matrix for public, HTTP Basic
and RS384 registrations in standalone and EHR modes, including signed identity
and retained refresh narrowing. The concurrent-launch suite below remains a
separate required check. Both use local fixtures; external SMART gates remain open.

P5a adds top-level EHR launch to the browser-retained manager. A registered
launch route accepts the EHR's `iss` and opaque `launch` parameters. It matches
the exact FHIR base to an approved EHR client **before any network request**.
Discovery and registration happen during application setup, not from incoming
URLs. The [SMART 2.2 launch specification](https://hl7.org/fhir/smart-app-launch/STU2.2/app-launch.html#launch-app-ehr-launch)
defines these two entry parameters and their authorization-request role.

The package encrypts a short-lived launch record bound to the current browser
owner, client fingerprint and exact FHIR base. It redirects to the application
with an opaque continuation ticket. The initial handle is absent from the
application HTML. Before Shiny connects, a script removes the ticket from the
address bar and hands it to the manager. Possession of the ticket alone is
insufficient: the server also checks the owner's HttpOnly cookie and generation.

The manager consumes that ticket once. A fresh OAuth state and S256 PKCE bind
the selected client and launch digest to authorization. The launch handle is a
per-transaction request parameter; shared provider settings never contain it.
Returning callbacks still need the ordinary callback-route, state and browser
proofs. Only an accepted token response can establish patient/encounter context
or validated identity. Another launch in another tab gets a separate record and
transaction. Reconnecting an EHR-only client requires a fresh EHR launch.

## Application setup

The following is a setup fragment; `app_ui` is the app's existing UI and the
server must call `oauth_connections_server("health", manager)` as usual.
Register both the callback URL and the distinct launch URL with the EHR.

```r
site <- smart_discover("https://ehr.example/fhir/R4")
hospital <- smart_client(
  site, client_id = "registered-app",
  redirect_uri = "https://app.example/callback",
  scopes = "patient/Patient.r", launch = "ehr",
  token_auth_style = "public"
)
manager <- oauth_connections(
  list(hospital = hospital), app_origin = "https://app.example",
  retention = "browser", owner = oauth_browser_owner(),
  store = oauth_connection_store_memory(),
  keys = deployment_keys # Protected 32-byte credentials and owner keys.
)
ui <- oauth_connections_ui(
  app_ui, "health", manager,
  launch_routes = list(smart_launch_route("/launch", "hospital"))
)
```

Here the launch URL is `https://app.example/launch`. The route can name several
clients when their FHIR bases differ. Two registrations sharing one exact base
need separate launch routes. Multiple clients also require distinct callback
URLs and the complete callback set in each client's configuration.

Read context with `smart_context(connection)` and fetch the selected Patient
with `smart_patient(connection)`. Scope checks and approved-base checks apply.
Bind patient-dependent UI data to the connection ID and context revision;
refresh can change context without creating a new connection. General connection
summaries deliberately omit patient and identity data.

## Run the local browser gate

Install the current checkout and Chrome/Chromium, then run from the repository
root:

```sh
Rscript integration/smart/run-ehr-browser.R
```

The runner uses Chromote, callr, webfakes, testthat and mirai. It exercises the
actual exported SMART/manager APIs in isolated R app processes. Two strict
synthetic authorization servers verify EHR handles, FHIR `aud`, S256, one-use
codes and rotating refresh tokens. Their FHIR endpoints enforce the issued
token's synthetic patient binding. This fixture is maintained with our code;
passing it is local integration evidence, not independent SMART conformance.

The fixture explicitly requests and grants `online_access` for refresh, following
the [SMART refresh scopes](https://hl7.org/fhir/smart-app-launch/STU2.2/scopes-and-launch-context.html#scopes-for-requesting-a-refresh-token).
The matrix covers public registrations with query and form POST callbacks,
using both synchronous and mirai token work. It starts two EHR launches in
separate tabs before either is approved, retains both connections across new
Shiny sessions, reads the corresponding Patients, refreshes one without losing
context, rejects handle reuse for reconnect, checks a separate browser owner,
and logs out locally. Unit tests separately cover unknown bases, duplicate or
mixed messages, expiry, wrong-owner attempts, ciphertext storage and exact
transaction binding.

The [SMART EHR workflow](../../.github/workflows/smart-ehr.yml) runs this gate on
relevant PRs. Artifacts contain counts, versions and the tested profile, never
tokens, launch handles, raw HTTP logs or patient context. Loopback HTTP is an
explicit development exception, not production TLS evidence.

Validation on 2026-09-11, Windows / R 4.5.1 / Chrome 152.0.7977.83:
the complete EHR matrix passed **88 assertions**, and the generic retained
connection matrix passed **104 assertions**, with no failures or skips. The
SMART/storage suite passed 680 assertions; the focused launch/manager/hook suite
passed 306. Unit runs emitted installed dependency build-version warnings.
Roxygen generation, Markdown links/example parsing, CI YAML parsing and source
installation passed. `R CMD check --no-tests --no-manual --ignore-vignettes`
reported **zero errors, warnings and notes**; tests were run separately.
Chromote 0.5.1 logged WebSocket EOF messages during shutdown on this machine;
the harness confirms process exit and handles shutdown acknowledgements separately.
The full browser evidence records `external_conformance: false` under the
ignored `.artifacts/ehr-20260911-092838/` directory.

## Remaining release gates

The current EHR implementation requires browser retention, a Lax owner cookie,
one R process and top-level navigation. Account/session-only EHR entry and
optional transport combinations need their own implementation and tests.
Iframe behavior remains deferred. Configure access logs to omit launch query
strings; HTTP no-store/no-referrer policy does not redact reverse-proxy logs.

P5b must run every supported registration profile against the pinned
[Inferno client suite](inferno.md), and repeat the applicable EHR scenarios in
the [official sandbox](sandbox.md). P4's standalone application/conformance
gates remain open. The pinned Launcher advertises asymmetric support without
required algorithm metadata; strict discovery still rejects it. The local
fixture does not repair that server or substitute for its acceptance gate.
Preflight Inferno metadata too before calling its deployment compatible.
