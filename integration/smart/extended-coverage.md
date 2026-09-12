# Additional SMART application scenarios

Run these commands from the repository root after installing the checkout. Each
gate fails on missing dependencies, failed assertions or skipped scenarios and
writes sanitized evidence under `.artifacts/`. Synthetic resources are used
throughout. These gates supplement the independently maintained Inferno client
verifier; they do not establish vendor certification.

## 1. Cross-site HTTPS callbacks

`Rscript integration/smart/run-profiles.R --cross-site`

Eight public-client scenarios cover standalone/EHR launch, query/form-post
callbacks and synchronous/mirai token transport. Both sides use HTTPS: the app
is at `127.0.0.1`, and providers are at `localhost`. These are distinct browser
sites, without changing the machine's DNS or hosts file. The browser checks the
provider origin, Secure cookies and the HttpOnly/Lax owner cookie, then completes
the existing two-grant retention, narrowing, refresh, disconnect and logout flow.
Only the isolated browser/readiness probe ignores the fixture certificate's
trust errors; R provider requests validate the existing test CA. The provider
is our synthetic SMART implementation, which supports incoming form-post
callbacks; the pinned Inferno simulator supports query callbacks only.

This gate currently runs Chrome. Firefox/WebKit coverage remains future work.
Validation on 2026-09-13: eight scenarios, 240 passing assertions, no skips.

## 2. Expired retained grants and automatic refresh

`Rscript integration/smart/run-lifecycle.R expiry`

Four HTTPS browser scenarios cross synchronous/mirai refresh with usable/revoked
refresh grants. The provider issues a ten-second access token; the browser leaves
the app so its Shiny session ends, waits past the recorded expiry, and verifies
that no refresh occurred while closed. Returning to a new Shiny session must
automatically refresh the retained connection and read Patient/user data with
the replacement grant. A revoked grant must instead become unavailable without
affecting site B. The provider rejects expired access tokens and records attempted
expired reads. No package clock or token exchange is mocked. This is synthetic
SMART lifecycle evidence; Inferno's fixed token lifetime is unchanged.
Validation on 2026-09-13: four scenarios, 30 passing assertions, no skips.

## 3. Patient/representative identity and refresh context

`Rscript integration/smart/run-inferno-extensions.R identity`

Eight public-client scenarios cross Patient/RelatedPerson identity, standalone/EHR
launch and synchronous/mirai transport. Inferno signs identity tokens and supplies
Patient, representative and encounter context. The actual Shiny app validates and
reads each identity before/after refresh and after restoring the connection in a
new session. Recorded exchanges must contain exactly one code exchange, one
refresh and six successful resource reads, each using the current issued token.
Each scenario requires all five applicable upstream verifier tests. The pinned
simulator corrections are unchanged; these are additional driver scenarios.

`Rscript integration/smart/run-lifecycle.R context`

Four additional synthetic-browser scenarios test omitted refresh context and a
changed patient with an omitted encounter. The former must preserve context; the
latter must clear the dependent encounter, advance context revision and read the
new Patient while preserving clinician identity. Both outcomes must survive a new
Shiny session. The unchanged Inferno simulator repeats configured context on
refresh, so omission/change evidence is explicitly attributed to our fixture.
Validation on 2026-09-13: eight Inferno scenarios with 40 upstream test passes;
four context scenarios with 16 passing assertions; no skips.

## 4. Account retention with independent SMART grants

`Rscript integration/smart/run-inferno-extensions.R account`

Two scenarios use the existing local Alice/Bob login boundary with public
standalone registrations on two Inferno deployments, over sync/mirai transport.
Alice authorizes A; Bob must not inherit A and authorizes B. Alice's old tab must
lose access both after switching accounts and after Alice logs in again. Alice's
new login restores the same A connection and refreshes it. Disconnecting Alice's
grants must leave Bob's B grant usable after his next login. Each site must pass
its five upstream tests; recorded requests must contain the expected code/refresh
exchanges and exactly four Patient/Practitioner reads using current credentials.
Rejected account operations must produce no resource requests. Local account
authentication is still synthetic; SMART grants and verification come from the
documented modified Inferno deployment. Account-owned EHR launch remains outside
the package's current support.
Validation on 2026-09-13: both scenarios passed, including 20 upstream test passes
and the recorded account/token-use checks.

## 5. Interrupted refresh, competing tabs and logout

`Rscript integration/smart/run-lifecycle.R interrupted`

Five real-browser scenarios exercise an owned HTTPS SMART fixture with rotating
refresh credentials: disconnect/logout before a delayed response, two tabs
competing for the same refresh, and a socket closed after credential consumption
in both synchronous/mirai modes. The fixture delays responses without blocking
its metrics endpoint. Delayed-success scenarios explicitly select a 20-second
HTTP timeout; package defaults remain unchanged. A competing tab must send no
second refresh request. Both tabs must subsequently read with the rotated grant.
A lost response must leave the grant uncertain, reject further use/refresh and
leave B usable. The socket-loss cases stop only their own provider process after
its consumption counter advances; they do not contact external systems.

Validation on 2026-09-13: five scenarios, 18 passing assertions, no skips.
