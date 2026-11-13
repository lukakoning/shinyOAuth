**OpenID Foundation client conformance environment**

Run from the repository root with Docker Engine using Linux containers,
Compose v2, Git, Chrome/Chromium, and R packages `httr2`, `jsonlite`, `processx`,
`openssl`, `withr`, `chromote`, `httpuv` and `testthat` installed:

```sh
Rscript integration/openid/run-preflight.R
```

Preflight pulls digest-pinned images, checks the full source revision embedded
in the server jar, starts a disposable suite, verifies the reported revision
and required client plans, and checks HTTPS from R and Chrome. It removes its
own containers, network and database volume before recording a pass. Missing
prerequisites, changed versions and unavailable services fail the command.
It does not perform client login or establish conformance.

Exercise the suite API and evidence validator:

```sh
Rscript integration/openid/run-tests.R --check-api
```

This checks the pinned Basic plan's complete module/variant list, creates a
private static registration, waits for a live module, checks its exported
issuer, rejects an unknown instance and confirms cancellation. The command
also runs the evidence validator's regression checks with zero skips. Its report keeps
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

Pools stay private to each module case and are reused within that case. A
single shared pool across different issuers and the additional client-auth
variants remain C09 follow-ups. Async Configuration runs preserve the main
app's cache template; workers receive serialized copies per dispatch. Reports
record that scope. The suite's no-store policy still prevents a warm-cache
claim, and Configuration coverage remains incomplete in both transports.

The [workflow](../../.github/workflows/openid-conformance.yml) runs preflight,
API checks and smoke on pull requests affecting the package or this harness.
Manual dispatch offers `smoke`, `basic`, `config`, `form-post` or `refresh`;
larger selections remain manual while GitHub runner timings are unmeasured.
Manual transport choices are `sync`, `mirai` and the limited `future` parity
selection. Pull requests keep synchronous smoke. The workflow needs no external
account or provider credentials and uploads only explicit sanitized report paths.

The [profile manifest](profiles.json) freezes each plan's variants and module
selections. The manifest remains schema 2; client evidence is now schema 3,
which requires worker/transport and process-cleanup evidence. Prior reports
retain their original version. The evidence validator binds each result to its
run, attempt, checkout, source revision, plan, instance and variants, then
requires both a completed allowed suite verdict and the expected app outcome.
Missing results, app failures, suite warnings, unexpected skips and timeouts fail.
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
`410812ef6bc72a84723c1685725edce3558e31e3`, its unmodified server image, the
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
and package setup. The Ubuntu GitHub workflow has not run yet.
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
The [implementation plan](../../.github/protocol-quality-implementation-plan.md)
records execution evidence and the remaining profile and CI work.
