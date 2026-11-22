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
Rscript integration/oidc-provider/run-resources.R --transport sync
Rscript integration/oidc-provider/run-resources.R --transport mirai
Rscript integration/oidc-provider/run-retention.R --transport sync
Rscript integration/oidc-provider/run-retention.R --transport mirai
Rscript integration/oidc-provider/run-jwks-rotation.R
```

On Windows, the runner also looks for Git's bundled OpenSSL. Set
`SHINYOAUTH_OPENSSL` to choose another executable. Node runs in the pinned
container; a host Node installation is unnecessary. A failed build, startup,
runtime check or discovery capability check fails the gate.

The separate [warm JWKS rotation selection](jwks-rotation.md) retains one
default client cache across real provider logins and an owned provider restart.
It requires an observed cache hit before one unknown-key refresh, with native
request counts and rogue-signature controls. This headless sync selection has
no browser-cookie or shared-worker-cache claim and records absent origin
freshness headers rather than inventing a provider max-age.

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

The report validator rejects 68 altered copies of the real successful report.
The controls cover missing cases or provider evidence, incorrect PKCE,
authentication or code binding, stale UserInfo tokens, failed identity or
refresh checks, missing worker evidence, a missing Form Post bridge, incomplete
cleanup and source or installation mismatches. The missing-PKCE request is a
separate live provider rejection.

Schema-2 baseline reports record the source snapshot and private installed
package before and after the browser cases. Clean runs install from a canonical
Git archive. The runner uses the [OpenID source identity helpers](../openid/source-identity.md)
and requires the source and installation evidence to match the run context.
Historical schema-1 reports retain their existing interoperability checks.

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

The [resource selection](resource-profiles.json) exercises
[RFC 8707](https://www.rfc-editor.org/rfc/rfc8707.html) with two
API audiences and a rejected unknown resource. It uses confidential Basic
authentication, direct query requests and S256. Chrome must observe the exact
resource parameter in the outgoing request; native provider events must observe
it at authorization, code exchange and refresh. Both API targets must produce
their own audience and the resource-specific `api.read` scope. PAR is explicitly
disabled for this selection.

Each positive case validates its ID token, calls the API through
`connection$request()`, refreshes the original connection and calls the API
again. Native introspection must confirm the current token's audience and
scope before and after refresh. The original validated identity must survive
refresh, including the provider's response without a replacement ID token.
Native UserInfo is disabled because an API-audience token cannot access it.
The scope policy stays enabled: the package can warn that the API access-token
scope omits the original OIDC/offline scopes. The harness requires the native
API scope and validated ID-token identity separately.

The resource server is a development fixture on two HTTPS paths. It uses the
provider's public AccessToken/Grant model API to check validity, audience and
scope; it is not a separate third-party resource-server implementation or a
JWT access-token verifier. Native provider handlers validate resource indicators
and issue the audience-bound tokens. A valid token for the other API, missing
credentials and an invalid token must receive HTTP 401. A connection request
that escapes its approved resource base must fail locally without an extra
resource-server request. The unknown resource must yield native `invalid_target`
and a matching client callback error before code or token issuance.

Resource evidence is `.artifacts/resources-*/evidence.json`. Exchange and refresh
use the selected sync/mirai transport; API requests, raw misuse controls and
introspection run in the main Shiny process. The gate checks the complete
selection, app-stop failure, worker execution, cleanup, serialized reports and
altered evidence. Other auth methods, callback modes, multiple requested
resources, JWT access tokens and resource indicators combined with JAR/PAR or
sender constraints remain outside this selection.

The [retention selection](retention-profiles.json) uses
`oauth_connections_server()` with browser retention for query and Form Post
callbacks. A single manager and encrypted memory store live outside the Shiny
server function. Each case completes one native OIDC login, then navigates to
a second page and back through full document loads. The new Shiny sessions must
restore the same connection ID and validated identity in the same R process.
Each session obtains its own connection reference. Four public connection
requests must succeed, including before/after refresh and after both navigations.
The public `identity()` API supplies verified ID-token/UserInfo comparisons;
reports retain identity digests, not claim values.

A separate Chrome profile must start empty and receive the package's typed
unavailable-connection error when given the first browser's ID. Local logout
uses `revoke = FALSE`: it must make the old R reference unusable and block raw
token export. A full reload must establish an empty owner that cannot recover
the old connection ID. These checks establish local retirement; upstream
revocation is covered by the separate advanced selection. Cookie evidence
requires one Secure, HttpOnly, SameSite=Lax owner cookie at `/`, hidden from
JavaScript, and excludes its value.

The retention report is `.artifacts/retention-*/evidence.json`. It requires
actual session changes, identity/ID continuity, exact provider events, native
PKCE/code/client-authentication checks, refresh rotation, worker execution and
cleanup. Form Post uses a real Chrome POST and the HTTP 303 bridge. Exchange,
refresh and validated UserInfo use the selected sync/mirai transport; explicit
resource reads and owner/store operations run in the main process. Provider
and app use HTTPS localhost on different ports. Cross-site cookie deployments,
account retention, owner expiry, multiple clients and process restarts are
outside this selection; the existing synthetic retention tests remain separate.

These selections establish scoped interoperability, not OpenID certification,
FAPI compliance or every advertised provider feature. `coverage_complete` stays
false. The selected C13-C14 scenarios are implemented. Native UserInfo
is the resource used by the advanced/retention selections; the resource selection uses
the separate fixture API paths described above.
Other algorithms, client authentication methods, encryption and combined
JAR + DPoP + JARM are outside its scope. The
[independent Python fixture](../conformance/README.md) remains a separate
protocol oracle. The [workflow](../../.github/workflows/oidc-provider.yml) runs
basic sync on relevant pull requests and offers basic/advanced/resources/retention with sync/mirai
through manual dispatch.
