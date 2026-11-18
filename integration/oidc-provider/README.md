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
Rscript integration/oidc-provider/run-advanced.R --transport sync
Rscript integration/oidc-provider/run-advanced.R --transport mirai
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

The [advanced selection](advanced-profiles.json) adds six confidential Basic-auth
cases: JAR + DPoP, JAR + mTLS token binding, and JAR + signed JARM, each directly
and through PAR. All use RS256 Request Objects, ID tokens and signed UserInfo;
JARM uses RS256 and DPoP uses ES256. PAR cases send only the client identifier
and request URI through the browser. Each case must log in, refresh and use
the resulting credential through `connection$request()` at native UserInfo.
Public introspection must report an active token with the expected client and
subject, then revocation must make it inactive and unusable at UserInfo.

The provider independently observes the actual Request Object and signed
responses, verifies their signatures and records the selected claims as
booleans. Its native Request Object claim/signature validation remains enabled.
Client signing keys and certificate private keys stay outside the provider's
mounted directories; registration contains only a public JWK and certificate
fingerprint. DPoP grant binding must match the key thumbprint in the signed
request. mTLS binding must match the actual TLS peer certificate.

Live DPoP probes require HTTP 401 for Bearer fallback, a different proof key
and a replayed proof; the first use of that proof must return 200. Live mTLS
probes require 401 with no certificate, a different certificate, and a different
certificate carrying a forged certificate header. Both certificates have the
same subject. Two further browser cases alter a real JARM signature and require
HTTP 400 before any token exchange. Each advanced report also runs the app-stop
canary and rejects altered copies of its evidence, including missing sender,
signature, refresh, resource, lifecycle, worker or cleanup observations.

mTLS uses a separate HTTPS listener and normal discovery endpoint aliases for
token, UserInfo, introspection, revocation and PAR. The browser-facing listener
does not request a client certificate. This tests certificate-bound tokens
with Basic client authentication and self-signed peers; it does not test PKI
client authentication. Tokens are opaque, so local observation of a `cnf` claim
is not required. The provider checks binding and denies the live misuse probes.

Evidence for advanced runs is `.artifacts/advanced-*/evidence.json`. Token
exchange, refresh and validated UserInfo use the selected sync/mirai transport.
The explicit connection resource request, misuse probes, introspection and
revocation run in the Shiny main process; reports identify that boundary. Invalid
JARM is rejected at the HTTP callback boundary before a replacement Shiny session.

These selections establish scoped interoperability, not OpenID certification,
FAPI compliance or every advertised provider feature. `coverage_complete` stays
false. RFC 8707 resource indicators and retained connections across navigation
remain C14 work. Native UserInfo is the only resource used in this selection.
Other algorithms, client authentication methods, encryption and combined
JAR + DPoP + JARM are outside its scope. The
[independent Python fixture](../conformance/README.md) remains a separate
protocol oracle. The [workflow](../../.github/workflows/oidc-provider.yml) runs
basic sync on relevant pull requests and offers basic/advanced with sync/mirai
through manual dispatch.
