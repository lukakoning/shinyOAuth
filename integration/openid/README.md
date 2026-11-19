**OpenID Foundation client conformance environment**

The [requirement-to-evidence maps](requirements.md) relate FAPI, OIDC, OAuth and
JWT/Message Signing client clauses to package behavior, tests and remaining
limits, including the [PAR/JWT-authentication map](requirements-par-auth.md).
The [sender-constraints/resource map](requirements-sender-constraints.md) covers
the direct mTLS, DPoP and resource-indicator client clauses. The
[OAuth security map](requirements-security.md) accounts for RFC 9700 sections
2–4, with explicit implementation, AS/RS, browser and deployment limits.
Inherited-security and configuration/coverage gaps remain explicit; the [scope map](scope.md)
records the separate suite-module outcomes.

See [interpreting client evidence](assessment.md) for the independent
`selection_complete`, `upstream_plan_complete` and legacy `coverage_complete`
decisions, exact accepted non-passing verdicts and categorized limitations.

The Message Signing fixture also performs a
[local configuration assessment](configuration.md) before authorization,
including explicit `nbf`, Request Object lifetime, effective authentication
audiences and the separate JWT-purpose policies for its named selection.

Run from the repository root with Docker Engine using Linux containers,
Compose v2, Git, Chrome/Chromium, and R packages `httr2`, `jsonlite`, `processx`,
`openssl`, `withr`, `chromote`, `httpuv`, `callr` and `testthat` installed:

```sh
Rscript integration/openid/run-preflight.R
```

Preflight reuses a cached image only when Docker's `RepoDigests` contains the
locked content digest, and pulls missing images by that digest. It checks the
full source revision embedded in the server jar, starts a disposable suite,
verifies the reported revision and required client plans, and checks HTTPS from
R and Chrome. It removes its
own containers, network and database volume before recording a pass. Missing
prerequisites, changed versions and unavailable services fail the command.
It does not perform client login or establish conformance.

The lock now selects the official `release-v5.3.4` server and proxy images by
content digest. Both previous GitLab image digests had become unavailable to
fresh machines. The [release review](release-review.md) records source and image
identities, differences from the previous build and validation results. The
runner never substitutes a tag or another digest. Reports record whether each
image came from the verified cache or a pull.

Exercise the suite API and evidence validator:

```sh
Rscript integration/openid/run-tests.R --check-api
```

This checks the pinned Basic plan's complete module/variant list, creates a
private static registration, waits for a live module, checks its exported
issuer, rejects an unknown instance and confirms cancellation. The command
also creates every declared plan configuration and checks its exact complete
module list and per-module variants, including the public-client capability
probe. Its sanitized `plan_inventory` records these module and variant identities.
For each configuration it also starts one module, verifies the live combined
variant and exported issuer, then requires cancellation. These interrupted
inventory probes receive no client-coverage credit.
The command also runs the evidence validator's regression checks with zero skips. Its report keeps
`gate_passed = false` and `coverage_complete = false`: API readiness does not
establish client conformance. Unknown command flags fail.

Run the three-case browser smoke selection:

```sh
Rscript integration/openid/run-tests.R --profile smoke --transport sync
```

This also needs `shiny`, `callr`, the package's development dependencies, and
Python 3 (`py` on Windows or `python3` elsewhere). It installs this checkout
into a private R library and uses a fresh Shiny app and Chrome process per case.
The suite acts as the provider. The normal login button drives a successful code
flow with validated ID token/UserInfo, then separate invalid-issuer and
invalid-nonce cases. Rejections require the expected typed error and claim name
from the privacy-preserving audit hook. Tokens, identities and claim values
stay out of the report. Every case must finish with the suite's `PASSED` verdict
and matching app evidence, with the callback query removed from the browser URL.

Run every module in the pinned Basic RP plan:

```sh
Rscript integration/openid/run-tests.R --profile basic --transport sync
```

This selection executes all fourteen modules, including missing required claims,
single/multiple signing keys without `kid`, RS256, invalid signatures, UserInfo
subject mismatch, scoped UserInfo claims and HTTP Basic client authentication.
The [scope record](scope.md) maps every module to its expected app outcome.
The unsigned-token module must finish `SKIPPED` with the app's
`disallowed_algorithm` rejection and no UserInfo request. That exact outcome
implements the pinned suite's documented optional support for `alg=none`;
the report retains the original verdict. Every other module must finish
`PASSED`. A waiting module or an unrelated app error cannot satisfy this policy.

Run the Form Post Basic selection:

```sh
Rscript integration/openid/run-tests.R --profile form-post --transport sync
```

The pinned plan runs the same fourteen modules with `response_mode=form_post`.
The app installs `oauth_form_post_ui()` and uses normal browser navigation for
every login. Chrome network events must show an outgoing GET authorization
request, a POST to the callback and the bridge's 303 redirect back to GET.
The fixture separately records the POST method, form content type, expected
Origin match and allowlisted `Sec-Fetch-Site` value. No callback body, query
parameters, cookie values or full network events enter the report.

Every case also requires a Secure `SameSite=Strict` browser-binding cookie,
a secure browser context, a completed state/browser-binding validation audit,
the expected identity or typed rejection, and a clean final callback URL.
Outgoing authorization-request method and callback response mode are checked
separately. Successful runs report complete coverage for this pinned Form Post
Basic plan and deployment, retaining the unsigned-token optional skip policy.

The local provider and app use HTTPS `localhost` on different ports. Chrome
reports `Sec-Fetch-Site: same-site`: the requests cross origins, while remaining
within one site. Reports retain the actual origins and observed site category;
different ports never earn a cross-site coverage label. Cross-site attack
fixtures remain a separate test layer.

Run the Configuration module selection:

```sh
Rscript integration/openid/run-tests.R --profile config --transport sync
```

This resolves all six modules in that plan, explicitly including both rotation
modules excluded by the upstream runner. Discovery and issuer-mismatch cases
stop after setup, with no token exchange or authenticated identity credited.
The randomized `jwks_uri` case uses the installed package's internal
`fetch_client_jwks()` helper because no public prefetch API exists. That call
retains the library's endpoint, TLS, parsing and cache policy. It is a component
probe, not a public JWKS-prefetch feature.

The before-signing rotation case prefetches keys before login, then requires a
validated token whose signing-key ID differs from the prefetched key IDs.
The repeated-login case logs out locally and logs in again with the same R app
and cache object. Both identities must validate with different signing-key IDs.
Reports contain only digests of those public key IDs, opaque app/cache instance
IDs and operation counters. The browser driver waits for a new callback session
on every login, so a logged-out state or the preceding login cannot satisfy it.

The pinned suite sends `Cache-Control: no-cache, no-store, max-age=0,
must-revalidate` on JWKS responses. A separate disposable module probes that
header policy without adding traffic to any client test. The fixture keeps the
same cache object and verifies that the keys remain unstored. These runs prove
key changes and successful validation; they cannot prove refresh from a warm
cache. A passing Configuration selection therefore reports
`selection_complete = true`, `coverage_complete = false` and
`cached_key_refresh_tested = false`, with an explicit coverage limitation.
Closing that gap needs a cacheable independent provider or a reviewed suite
configuration/version change. The existing cache regression tests remain a
separate layer of evidence.

Run all three modules in the client refresh plan:

```sh
Rscript integration/openid/run-tests.R --profile refresh --transport sync
```

Each module first completes a normal login with validated ID token, UserInfo
and a refresh grant. The driver then clicks Refresh in that same Shiny session.
The fixture calls the public `auth$connection()$refresh()` method and consumes
the resulting access token through `$access_token()`. Normal refresh must
preserve the original ID token, issuer, subject and connection, replace the
access token, and complete the library's required UserInfo request.

Changed issuer and subject responses must produce the matching typed audit
error and clear the session under the module's default failure policy. The
retained connection must become unusable and refuse access-token export. No
UserInfo request may follow either rejected refresh. Evidence records private
value comparisons as booleans, operation counts and before/after checkpoints;
it includes no identity or credential values. All three modules must finish
`PASSED`. This upstream refresh plan is outside OpenID certification.

Each run first stops a real app after clicking login and requires the driver to
fail for that exact reason. This control uses a separate suite plan; its
interrupted module is never counted as a conformance pass. A passing report also
requires this control and verified cleanup of the apps, browsers, TLS proxy and
owned Docker resources.

Run the core selections through actual mirai workers with `--transport mirai`:

```sh
Rscript integration/openid/run-tests.R --profile basic --transport mirai
Rscript integration/openid/run-tests.R --profile config --transport mirai
Rscript integration/openid/run-tests.R --profile form-post --transport mirai
Rscript integration/openid/run-tests.R --profile refresh --transport mirai
```

These runs also need `mirai`, `promises`, `later` and `ps`. Each app starts two
private daemons. Both must load this checkout's private namespace, accept a
verified HTTPS request using the temporary CA, and reject a deliberately wrong
hostname. Every protocol audit event records its process ID and confirms the
package installation and CA setting. The gate requires token/UserInfo work and
typed validation failures in those verified workers. Setting `async = TRUE`
without worker execution cannot pass. Refresh awaits its promise before
checking identity, credential export and the module's failure policy.

Future multisession has smaller smoke and refresh parity selections:

```sh
Rscript integration/openid/run-tests.R --profile smoke --transport future
Rscript integration/openid/run-tests.R --profile refresh --transport future
```

The future fixture disables mirai daemons, starts two multisession workers and
checks the selected backend. A barrier makes both workers participate in the
package/TLS probes. Other future profile selections fail explicitly.

Workers send only allowlisted audit metadata through atomic JSON files in a
private per-app directory. Snapshots aggregate main-process and worker counters
without serializing a Shiny session into the audit hook. No raw audit event,
token, identity, error message, file path or CA value enters those files.
Only the sanitized `evidence.json` report is uploaded. App termination verifies
that its child processes and the specifically observed worker PIDs stop.
Linux apps first receive an interrupt so their exit handlers can stop the
worker pools; forced termination remains a fallback. A driver running inside a
container needs an init process (for example, Docker's `--init`) to reap exited
workers. Zombie entries fail the cleanup check. Chrome's close-command promise
is observed, and its process must stop even if it never acknowledges the command.
Every browser gets a separate temporary profile and a 30-second startup budget.

The core selections keep pools private to each module case and reuse them
within that case. A separate shared-pool selection checks reuse across issuers.
Async Configuration runs preserve the main
app's cache template; workers receive serialized copies per dispatch. Reports
record that scope. The suite's no-store policy still prevents a warm-cache
claim, and Configuration coverage remains incomplete in both transports.

Client-authentication selections use the pinned Comprehensive plan:

```sh
Rscript integration/openid/run-tests.R --profile auth-post --transport sync
Rscript integration/openid/run-tests.R --profile auth-secret-jwt --transport mirai
Rscript integration/openid/run-tests.R --profile auth-private-jwt --transport mirai
```

All three support `sync` and `mirai`. Each runs the normal login module and an
invalid-issuer module. Both must finish `PASSED`, with a validated login or the
expected typed issuer rejection in the app. These are two-case selections from
a larger, non-certifiable plan, so they retain `coverage_complete = false`.

| Profile | Authentication | Credential setup |
| --- | --- | --- |
| `auth-post` | `client_secret_post` | Fresh shared secret in the token request body |
| `auth-secret-jwt` | `client_secret_jwt` | Fresh shared secret, registered HS256 assertion algorithm |
| `auth-private-jwt` | `private_key_jwt` | Fresh RSA key, registered RS256 algorithm and public JWKS |

The suite receives only the public RSA key. The runner keeps the private PEM
out of suite registration and evidence. The evidence helper reads recorded requests and
condition results, then retains comparison booleans and allowlisted labels.
It verifies the chosen authentication method, absence of mixed credentials,
matching client IDs, and JWT algorithm, identity, audience, key ID and lifetime
where applicable. The suite must also report its relevant authentication checks
as successful. Raw logs, secrets, assertions, keys, authorization codes and
claim values never enter the report.

These selections also reproduce two limitations in the pinned suite. Its public
variant omits `none` from discovery metadata, so normal shinyOAuth discovery
rejects the requested public authentication method. A separate disposable
capability probe records that rejection, then cancels its module. It earns no
conformance credit, and `public_client_authentication_tested` stays false.
The harness leaves discovery policy and provider metadata unchanged.

The pinned client plan checks that an S256 challenge is present but skips its
verifier-matching condition. The companion helper independently computes S256
from the actual token request's verifier and compares it with the authorization
request's challenge. That comparison must pass for every auth case. Reports
retain `suite_pkce_verifier_checked = false` and the explicit coverage limitation;
this establishes correct client requests without claiming suite enforcement
of a bad verifier. The [scope record](scope.md) links the relevant source.

Check worker reuse across issuers:

```sh
Rscript integration/openid/run-shared-pool.R
```

This mirai-only selection keeps one R process and two verified workers alive
across eight browser flows. It alternates POST and private-key-JWT clients,
requiring both normal logins and typed issuer rejections, then repeats with new
registrations, secrets and signing keys. Each plan has a distinct discovered
issuer, shared by its positive and negative modules. The app and client cache
are recreated for each case; the worker pool stays alive. At least one observed
worker must perform protocol work for both
authentication methods.

Each case uses a different audit hook and one of two timeout settings. Audit
records require the expected setting inside protocol work. Inspections of both
workers before and after every case require restored options and empty async
session context. Earlier cases' audit files must remain unchanged after later
flows. All four nested authentication selections must also pass their existing
suite, request, app and cleanup gates. Worker termination is credited only after
the shared process and both workers stop.

This tests sequential pool reuse, including new credentials after rejected
logins. It does not establish simultaneous multi-issuer execution, shared-cache
behavior or every authentication pairing. Its report retains partial coverage
and the existing public-client and PKCE suite limitations. Private handoff files
and raw logs stay under `.artifacts/`; only the sanitized root `evidence.json`
is eligible for upload.

Run the first FAPI 2.0 Security Profile selection:

```sh
Rscript integration/openid/run-tests.R --profile fapi-dpop --transport sync
Rscript integration/openid/run-tests.R --profile fapi-dpop --transport mirai
```

The pinned generic OIDC variant resolves twenty-three modules. This selection
runs three: the normal DPoP nonce flow, the happy path without DPoP nonces,
and an invalid ID-token issuer. It uses authenticated PAR, private-key JWT,
S256 and DPoP, with ES256 keys and query callbacks. Each suite instance must
finish `PASSED` with matching app and request evidence. Coverage stays partial.

The fixture selects `id_token_profile = "fapi2"`, DPoP token types and the
existing `minimal` front-channel mode. Browser authorization requests contain
only `client_id` and `request_uri`; state, nonce, scope and S256 go through PAR.
Client assertions use the discovered issuer as a string audience. The suite's
normal server-key configuration receives a separate ephemeral ES256 signing key.
Client registration contains only its public signing key; client private keys,
proofs, assertions and credential values stay out of the report.

Both positive cases must read the suite's exported accounts endpoint through
`auth$connection()$request()`, check HTTP 200 and consume its completion marker.
UserInfo alone cannot complete the gate. The evidence helper checks actual PAR,
token, UserInfo and accounts requests, signature/nonce condition results, S256,
DPoP method/URI binding, consistent proof keys, distinct JTIs and resource-token
hashes. Nonce cases require observed retries with changed nonces. The no-nonce
case requires one request per endpoint and no proof nonce. The issuer rejection
must retain no identity and send no UserInfo or accounts request.

Login uses the chosen sync/mirai transport. The connection's imperative resource
request runs in the Shiny process in both modes, and the report records that
scope. The selections below cover the resolved OIDC and OAuth-only modules.
Refresh and mTLS remain separate work. This selection does not establish
full FAPI conformance or certification. The [scope record](scope.md) links the
profile requirements and pinned suite source.

Run all twenty-three modules in that resolved OIDC variant:

```sh
Rscript integration/openid/run-tests.R --profile fapi-dpop-full --transport sync
Rscript integration/openid/run-tests.R --profile fapi-dpop-full --transport mirai
```

The full selection adds discovery issuer rejection, ID-token audience, expiry,
algorithm and nonce mutations, callback issuer/state rejections and the positive
audience-array, token-type, DPoP scheme-case and endpoint-alias cases. Every
module must finish `PASSED`. Discovery and callback rejections have separate
evidence stages and must send no token or resource request. Callback evidence
keeps allowlisted labels, without callback values. These stages earn no token
exchange or resource-access credit.

All seven positive cases use the public connection request API and require a
usable connection with finite expiry. When the response omits `expires_in`,
shinyOAuth applies its documented 3600-second fallback lifetime. The fixture
uses that normal behavior without supplying an expiry or changing token state.

The four malformed callbacks take an opaque, single-use error continuation
before returning HTTP 400, without starting a callback Shiny session. Current
evidence binds the browser's actual 303-to-400 chain, final credential-free URL,
body and privacy headers to the public UI handler and original audit label.
The pending OAuth state must remain present and unchanged; neither hop may
reflect the original long credentials. The
[cleanup assessment](assessment.md#rejected-callback-cleanup) explains its
strict policy, historical-report compatibility, process-local diagnostic limit
and separate browser-history/deployment boundaries. Successful callbacks and
ID-token rejections also require a cleaned callback URL.

`coverage_complete = true` for this selection means every module in the pinned
OIDC/private-key-JWT/DPoP variant passed. Other FAPI variants and certification
remain separate. Resource requests still execute in the Shiny process.

Run the eleven modules resolved for the OAuth-only variant:

```sh
Rscript integration/openid/run-tests.R --profile fapi-oauth-dpop --transport sync
Rscript integration/openid/run-tests.R --profile fapi-oauth-dpop --transport mirai
```

This variant uses `fapi_client_type=plain_oauth` with the same ES256 private-key
JWT, DPoP, PAR and S256 configuration. The fixture calls the public
`oauth_provider_oauth_discover()` helper against the suite's [RFC 8414](https://www.rfc-editor.org/rfc/rfc8414.html#section-3) metadata
endpoint. It requests only `accounts`, with no `openid` scope or OIDC nonce.
OIDC behavior is disabled by that helper's normal provider configuration;
the standard OIDC discovery helper retains its defaults and metadata rules.

Six positive flows must return an access token without an ID token, make no
UserInfo request and complete the accounts request through the public connection
API. Reports label these outcomes `authorized`. The module's `authenticated`
signal records grant acceptance here; it does not establish an OIDC identity.
The gate verifies the actual PAR scope and nonce fields, token-response field
presence, DPoP proofs and retries, usable connection and resource completion.
The discovery and four callback rejection cases retain their separate stages.
All eleven modules are required; missing results and skips fail.

The three happy-path modules report the upstream
[`CheckStateLength`](https://gitlab.com/openid/conformance-suite/-/blob/23353b36957d6466010de767c812d2c91ed37638/src/main/java/net/openid/conformance/condition/as/CheckStateLength.java) advisory:
the library's encrypted state exceeds 128 characters. Their retained verdict
is `WARNING`. The gate requires that exact condition and fixed message, a
measured state length above 128, and no other warning, failure or review event.
Every other module must finish `PASSED`. This records the completed exchanges
while keeping `coverage_complete = false`, including if the manifest's complete
flag is changed. The original encrypted state and its binding checks remain
in use. Reference mode has a separate selection below.

Run the same eleven OAuth modules with compact state references:

```sh
Rscript integration/openid/run-tests.R --profile fapi-oauth-dpop-reference --transport sync
Rscript integration/openid/run-tests.R --profile fapi-oauth-dpop-reference --transport mirai
```

This fixture selects the public `oauth_client(state_transport = "reference")`
option. The default encrypted transport remains available in the original
profile. The reference profile requires every module to finish `PASSED`;
warnings receive no credit. For each flow reaching PAR, the gate checks the
actual client property and independently measures every PAR state value:
22-128 URL-safe characters, identical across retries. Reports retain only the
length and validity result. The encrypted payload stays in the pending record,
with browser, client/provider/policy, freshness and atomic single-use checks.

`coverage_complete = true` here refers to all eleven modules in this pinned
OAuth/private-key-JWT/DPoP variant with reference state. The encrypted-state
profile retains its warnings and incomplete coverage status.

Run the nine modules resolved for OAuth-only private-key-JWT authentication
with mTLS sender constraint:

```sh
Rscript integration/openid/run-tests.R --profile fapi-oauth-mtls --transport sync
Rscript integration/openid/run-tests.R --profile fapi-oauth-mtls --transport mirai
```

The fixture generates a temporary client certificate, registers its public
certificate and `use_mtls_endpoint_aliases = true`, and uses the normal package
connection for resource access. It selects reference state. Because the suite
issues opaque access tokens, the fixture explicitly sets
`mtls_require_observed_cnf = FALSE`; certificate presentation and server-side
checks provide the binding evidence. The package's default remains unchanged.
This separates JWT client authentication from the mTLS sender constraint, as
described in [RFC 8705](https://www.rfc-editor.org/rfc/rfc8705.html#section-3).

Each normal module requires `PASSED`. The gate correlates the suite's incoming
request IDs with TLS-listener logs, checking the actual peer certificate for
PAR, token and resource calls. The no-alias case uses the advertised mTLS token
URL and ordinary PAR URL. Reports contain comparison results without tokens,
certificate contents, keys or TLS fingerprints.

Three isolated controls present a bound token with a wrong certificate, a wrong
certificate plus a forged certificate header, or no certificate. They require
the actual unexpected TLS peer and the suite's certificate-failure verdict.
The missing-certificate request returns HTTP 400. In this pinned suite, both
wrong-certificate requests return HTTP 200 and the resource marker even though
their module verdict is `FAILED`: its
[`checkMtlsCertificate()`](https://gitlab.com/openid/conformance-suite/-/blob/23353b36957d6466010de767c812d2c91ed37638/src/main/java/net/openid/conformance/fapi2spfinal/AbstractFAPI2SPFinalClientTest.java)
continues after a certificate mismatch. These failed instances remain separate
from the nine normal outcomes. The report always keeps
`coverage_complete = false` and `mtls_resource_denial_not_established` visible.
The [independent Python resource check](../conformance/README.md) separately
requires per-token certificate matching and real HTTP 401 denial. It leaves
this suite's outcomes and incomplete coverage status intact.

Run the separate OAuth-only mTLS client-authentication selection:

```sh
Rscript integration/openid/run-tests.R --profile fapi-oauth-mtls-auth --transport sync
Rscript integration/openid/run-tests.R --profile fapi-oauth-mtls-auth --transport mirai
```

This resolves the same nine modules with the suite's `client_auth_type = mtls`
variant, which advertises `tls_client_auth`. Registration contains the public
client certificate and omits shared secrets and JWT client keys. PAR and token
requests must carry `client_id`, omit JWT assertions and shared secrets, and
present the registered certificate on the actual TLS connection. The resource
still uses mTLS token binding through the public connection API.

Without endpoint aliases, this variant advertises literal mTLS URLs for both
PAR and token. The gate requires the suite's PAR fallback event and verifies
that both requests reach the mTLS listener. The private-key-JWT variant retains
its ordinary TLS PAR fallback. All nine normal modules require `PASSED`;
the separate resource attacker controls retain their expected `FAILED` verdicts.

The pinned suite registers one exact certificate and compares it with the TLS
peer. This selection does not establish the PKI chain and subject-name validation
described by [RFC 8705 section 2.1](https://www.rfc-editor.org/rfc/rfc8705.html#section-2.1),
or rejection of invalid client-authentication credentials. The checker forces
`suite_exact_certificate_registration_only` and
`mtls_client_authentication_denial_not_tested` into the coverage limits, even if
the manifest omits them. Resource denial remains limited as described above.
The [independent Python PKI fixture](../conformance/README.md) separately checks
client-authentication denial, trusted subject matching and untrusted-CA
rejection. It leaves this suite's outcomes and coverage limits intact.
Run the OIDC variants with ID-token and UserInfo validation:

```sh
Rscript integration/openid/run-tests.R --profile fapi-mtls --transport sync
Rscript integration/openid/run-tests.R --profile fapi-mtls --transport mirai
Rscript integration/openid/run-tests.R --profile fapi-mtls-auth --transport sync
Rscript integration/openid/run-tests.R --profile fapi-mtls-auth --transport mirai
```

`fapi-mtls` uses private-key-JWT authentication; `fapi-mtls-auth` uses the
suite's mTLS authentication variant. Both select OIDC discovery, the client's
`fapi2` ID-token profile, reference state and mTLS token binding. Each resolves
all 21 applicable modules: five successful resource exchanges, eleven ID-token
rejections, four callback rejections and one discovery rejection. Every module
requires `PASSED`, with no warning or skipped nonce cases.

The gate observes the returned ID token and checks the selected issuer,
audience, expiry or algorithm mutation, alongside nonce matching, mismatch or
absence. The installed client validates the actual signature and claims.
Invalid ID tokens must stop before UserInfo and resource requests. Successful
cases require both, including the same issued Bearer token and the registered
actual TLS peer. Without aliases, UserInfo must use its advertised literal mTLS
URL; the suite's corresponding setup event is required. Token values, ID tokens,
nonces and certificates do not enter the sanitized reports.

These OIDC gates retain the three separate resource attacker controls and the
forced resource-denial coverage limit. These controls target the accounts
endpoint. UserInfo's attacker-denial behavior remains outside them. The mTLS
authentication variant also retains its exact-certificate registration and
authentication-denial limits.
mTLS-bound refresh remains separate work.

## FAPI Message Signing

```sh
Rscript integration/openid/run-tests.R --profile fapi-message-signing --transport sync
Rscript integration/openid/run-tests.R --profile fapi-message-signing --transport mirai
```

This selection uses the pinned `fapi2-message-signing-final-client-test-plan`:
OIDC, private-key-JWT authentication, DPoP, signed requests through PAR and
signed query responses, with grant management disabled. The suite advertises
[`response_mode=jwt`](https://github.com/openid-certification/conformance-suite/blob/23353b36957d6466010de767c812d2c91ed37638/src/main/java/net/openid/conformance/condition/as/AddJARMResponseModeToServerConfiguration.java),
which the client sends and handles through its query JARM transport. No suite
assertions or discovery metadata are patched.

The API must resolve exactly 29 modules: seven successful authenticated resource
exchanges, eleven ID-token rejections, two state rejections, eight JARM
rejections and one discovery rejection. JARM tests cover missing and invalid
issuer/audience, missing and expired expiry, an invalid signature and `alg=none`.
The two plain-response issuer tests do not apply to this JARM variant. Every
module requires `PASSED`; warnings and skips fail the gate.

The collector verifies ES256 signatures on the actual PAR Request Objects,
their issuer, audience, redirect, scope, nonce, state and PKCE binding, and the
suite's request-validation events. It checks the actual JARM redirect, its
selected claim or signature mutation, and redemption of that response's code.
Signature inspection uses the registered client key or the suite's public
signing key and does not depend on JWT expiry validation. The installed client
performs its own verification. Rejected callbacks require a browser-observed
HTTP 400 with the expected error category, no identity, and zero token,
UserInfo or resource requests. Successful cases require validated ID tokens,
UserInfo and DPoP-protected resource use through the public connection API.
Raw JWTs, codes, nonces, keys and error text stay out of the reports.

`coverage_complete=true` describes this one resolved variant. Other client
authentication methods, mTLS, algorithms, encrypted messages, Form Post,
refresh and grant management remain outside this selection. Callback rejection
runs before the Shiny callback session in the main process; mirai evidence
does not claim worker execution of that rejection. Current contexts require
the [opaque error continuation proof](assessment.md#rejected-callback-cleanup);
historical reports retain their query-retention limit. Final-URL cleanup does
not establish erasure from browser history or operator logs.

The [independent Python fixture](../conformance/README.md) also exercises signed
JAR/PAR/JARM exchanges using RS256 and RS384, including the combined PAR/JARM
case. Its scope omits OIDC discovery, ID tokens and browser login, so its result
is a separate cryptographic and protocol comparison.

The discovery helper reads unsigned JSON metadata over verified TLS. Signed
metadata, refresh, other FAPI variants and certification remain separate. Resource
requests still run in the Shiny process. Rejected HTTP callbacks have the
cleanup and deployment boundaries described above.

The [workflow](../../.github/workflows/openid-conformance.yml) runs preflight,
API checks and smoke on pull requests affecting the package or this harness.
Manual dispatch offers `smoke`, `basic`, `config`, `form-post`, `refresh`,
`auth-post`, `auth-secret-jwt`, `auth-private-jwt`, `shared-pool`, `fapi-dpop`,
`fapi-dpop-full`, `fapi-oauth-dpop`, `fapi-oauth-dpop-reference`,
`fapi-oauth-mtls`, `fapi-oauth-mtls-auth`, `fapi-mtls`, `fapi-mtls-auth` and
`fapi-message-signing`;
larger selections remain manual while CI tiering is reviewed; observed runner
timings are recorded in the [release review](release-review.md).
Manual transport choices are `sync`, `mirai` and the limited `future` parity
selection. `shared-pool` requires mirai. Pull requests keep synchronous smoke.
The workflow needs no external
account or provider credentials and uploads only explicit sanitized report paths.

The [profile manifest](profiles.json) freezes each plan's variants and module
selections. The manifest remains schema 2; client evidence is now schema 4,
which adds source and installation identity to worker/transport and cleanup evidence. Prior reports
retain their original version. The evidence validator binds each result to its
run, attempt, checkout, source revision, plan, instance and variants, then
requires both a completed allowed suite verdict and the expected app outcome.
Revalidation also requires all three image references to match the local suite
lock and the expected run context. Each image must have a `cached` or `pulled`
acquisition entry matching that context, and the checkout dirty flag must be a
Boolean with its original value. The shared-pool report and its four client
selections carry these fields individually. Missing or substituted metadata
fails the gate, including in serialized reports. Load the manifest through
`openid_profiles()` so it includes the independently read lock, and use a trusted
run context when rechecking evidence; a report cannot establish its own origin.
The [source identity checks](source-identity.md) record the checkout and actual
installation input, verify both remain unchanged during execution, and require
clean committed input for release evidence. Dirty development runs remain
allowed for scenario checks. Complete release aggregation remains SA08 work.
Older shared-pool reports without per-selection provenance remain historical
records and require a new run to pass the current validator.
Missing results, app failures, unrecognized suite warnings, unexpected skips and timeouts fail.
The evidence regression checks also require zero warnings and skips.
A passing smoke selection keeps `coverage_complete = false`; a passing Basic
selection reports `coverage_complete = true` for the pinned Basic plan with
static registration, the selected sync/mirai transport, code flow, query callbacks and
`client_secret_basic`. This is local test evidence. OpenID certification needs
its separate submission and review, and other profiles remain pending.
Configuration's cache limitation keeps its coverage flag false even if the
manifest accidentally labels that profile complete.

Check the Shiny app plumbing separately:

```sh
Rscript integration/openid/run-fixture-checks.R
```

This command also needs `shiny`, `callr`, `webfakes`, the package's development
dependencies, and Python 3 (`py` on Windows or `python3` elsewhere). It reuses
the existing standard-library loopback TLS proxy. The command installs the
checkout into a fresh private R library, checks which installation the child
app loads, and drives the normal login button in Chrome against synthetic HTTPS
metadata. It checks code/S256/nonce/state/scope fields, rejects a mismatched
discovery issuer, and checks that the synthetic client secret stays out of the
DOM and private app logs. It does not issue tokens or establish RP conformance.

The fixture's provider configuration stays in the child R process. Its page
exposes only an opaque run ID, status flags, allowlisted error classes, reason
codes, claim names and operation counters. It uses public shinyOAuth discovery, UI and module
APIs with their validation enabled. A loopback TLS proxy preserves the original
Host header; the callback resolver checks that host and the loopback peer before
reconstructing the fixed public origin, without trusting forwarded headers.

The [lock](suite-lock.json) pins OIDF source
`23353b36957d6466010de767c812d2c91ed37638`, its unmodified server image, the
upstream proxy image and MongoDB 6.0.13. The server image's `git.properties`
records the exact clean commit; `/api/server` independently reports its short
revision. Dependency changes need a separate reviewed lock update.

Only proxy HTTPS ports bind to host loopback. MongoDB and the suite's internal
HTTP listener have no host ports. The suite's local `dev` Spring profile
injects its documented developer identity, so API calls need no account or
token. This deployment is for local testing. Hosted API credentials and hosted
version reporting will use a separate path.

Each run generates a temporary two-day certificate. R verifies its certificate
and hostname against that explicit trust anchor. Chrome accepts only that
certificate's SHA-256 SPKI pin through a dedicated browser process; preflight
also proves a different pin fails. This avoids editing system trust stores or
globally ignoring certificate errors. Browser evidence records pinning, not
installation of a trusted CA; this run does not test a public certificate chain.

The local [proxy configuration](nginx.conf) supplies mapped ports and TLS
metadata in the form expected by upstream. Suite assertions and provider
responses remain unchanged. Both the proxy and suite build identities appear
in sanitized `.artifacts/<run>/evidence.json`. Raw logs, certificate keys and future
suite exports stay under ignored `.artifacts/` and must not be uploaded by a
broad artifact glob. Preflight writes `evidence.json` there even on failure.

Validation includes repeated smoke passes on Windows 11 using Docker Desktop
4.48.0 with Linux containers, R 4.5.1 and Chrome through chromote 0.5.1.
Preflight, API checks and smoke also pass as a non-root Linux user with R 4.5.0
and Chromium 156. Complete Basic runs pass on both platforms, with thirteen
`PASSED` verdicts and the documented unsigned-token `SKIPPED` verdict. The module
loops took about 90 seconds on Windows and 78 seconds on Linux, excluding suite
and package setup. Hosted results are recorded in the
[release review](release-review.md) and [source validation](source-identity.md).
Configuration selections also pass on both platforms: five `PASSED` verdicts
and the documented unsigned-token `SKIPPED`. Their module loops took about
38 seconds on Windows and 30 seconds on Linux, with the cache limitation above.
Form Post Basic also passes all fourteen expected module outcomes on both
platforms, including its POST/303/binding evidence. Its module loops took about
103 seconds on Windows and 82 seconds on Linux.
All three refresh modules pass on both platforms, with the original login,
identity continuity and credential-retirement checks above. Their module loops
took about 26 seconds on Windows and 23 seconds on Linux.
Mirai runs also pass Basic, Configuration, Form Post Basic and refresh on both
platforms, with worker/package/TLS and process-cleanup evidence. Future smoke
and refresh parity selections pass on both as well. The implementation plan
records their runtimes and report paths. Configuration retains its cache gap.
The full FAPI OIDC/private-key-JWT/DPoP selection also passes all twenty-three
modules in sync and mirai on both platforms: 92 `PASSED` outcomes, with matching
app/request evidence and verified cleanup. This covers the configured variant;
the OAuth-only variant and other FAPI profiles have separate gates.
The eleven-module OAuth-only selection also runs in sync and mirai on both
platforms. Each run records eight `PASSED` outcomes and the three state-length
`WARNING` outcomes described above, with verified cleanup and incomplete
coverage. The implementation plan records those reports and the compact-state
follow-up.
The [implementation plan](../../.github/protocol-quality-implementation-plan.md)
records execution evidence and the remaining profile and CI work.
