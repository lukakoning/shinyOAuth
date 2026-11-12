**OpenID Foundation client conformance environment**

Run from the repository root with Docker Engine using Linux containers,
Compose v2, Chrome/Chromium, and R packages `httr2`, `jsonlite`, `processx`,
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
exposes only an opaque run ID, status flags, allowlisted error classes/claim
names and operation counters. It uses public shinyOAuth discovery, UI and module
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

Initial validation on Windows 11 used Docker Desktop 4.48.0 with Linux
containers, R 4.5.1 and Chrome through chromote 0.5.1. Linux CI remains a
separate validation target. The [implementation plan](../../.github/protocol-quality-implementation-plan.md)
tracks the later application, profile and CI commits.
