# oidc-provider interoperability

This environment runs the published, unmodified `oidc-provider` 9.14.0 package
with Node 24.22.3. The [runtime lock](provider-lock.json) pins the official Node
container by digest; [package-lock.json](package-lock.json) fixes the npm tree
and package integrity. `npm ci` verifies the dependency bytes during image
build. Each run records the built image ID and hashes of the fixture inputs.

Run from the repository root with Docker Linux containers, R and its package
dependencies, Chrome, Python 3 and the OpenSSL CLI installed:

```sh
Rscript integration/oidc-provider/run-tests.R --transport sync
Rscript integration/oidc-provider/run-tests.R --transport mirai
```

On Windows, the runner also looks for Git's bundled OpenSSL. Set
`SHINYOAUTH_OPENSSL` to choose another executable. Node runs in the pinned
container; a host Node installation is unnecessary. A failed build, startup,
runtime check or discovery capability check fails the gate.

The four [cases](profiles.json) cover public clients (`none`) and confidential
clients (`client_secret_basic`), each with query and Form Post callbacks. Every
case uses S256 and finishes browser login, validated ID-token/UserInfo exchange,
and refresh through the public connection API. A fresh container, temporary
signing key, registration and Chrome profile isolate each case. Temporary TLS
certificates cover loopback hosts; R and both mirai workers verify the CA and
reject a wrong hostname. Chrome uses the test certificate's SPKI allowlist.

The fixture supplies a fixed test account and explicit login/consent buttons
through the provider's public interaction API. The provider handles discovery,
authorization, PKCE, token issuance, ID-token signing, UserInfo and refresh.
Development interactions are disabled. PKCE is mandatory for both registrations,
and refresh rotation is enabled. No protocol validation handler is patched.
The implementation follows the pinned upstream
[interaction API example](https://github.com/panva/node-oidc-provider/blob/v9.14.0/example/routes/koa.js)
and [configuration reference](https://github.com/panva/node-oidc-provider/blob/v9.14.0/docs/README.md).

Sanitized provider events establish the actual S256 verifier/challenge match,
code redemption, client authentication and use of the currently issued token
at UserInfo. Refresh must rotate its credential and preserve issuer, subject
and the existing connection. Both UserInfo calls must succeed with the current
access token. A request without PKCE must fail before code issuance. An app-stop
canary confirms that an incomplete browser flow cannot pass.

The report validator also rejects 64 altered copies of the real successful
report: missing cases or provider evidence, incorrect PKCE/authentication/code
binding, stale UserInfo tokens, failed identity/refresh checks, missing worker
evidence, a missing Form Post bridge, and incomplete cleanup. These are report
validation controls; the missing-PKCE request is a live provider rejection.

Evidence is written to `.artifacts/basic-*/evidence.json`. Only these JSON files
are eligible for workflow upload. They contain comparisons, counts and event
categories, excluding tokens, codes, nonces, credentials and raw error text.
Private logs, temporary keys, configuration files and package installations stay
under the ignored artifacts directory. The shared Shiny/browser/worker helpers
are reused from [the OIDF harness](../openid/README.md).

This establishes interoperability for the four selected cases, not OpenID
certification or every advertised provider feature. `coverage_complete` stays
false. JAR, PAR, sender-constrained tokens, JARM, signed UserInfo, resource
indicators and retained connections across navigation remain C14 work. The
[independent Python fixture](../conformance/README.md) remains a separate
protocol oracle. The [workflow](../../.github/workflows/oidc-provider.yml) runs
sync on relevant pull requests and offers sync/mirai through manual dispatch.
