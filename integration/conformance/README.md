# Independent protocol fixture

Run from the repository root:

```sh
python -m pip install -r integration/conformance/requirements.txt
Rscript integration/conformance/run-tests.R
```

Install the package's R dependencies and test dependencies first. The current
OpenSSL requirement is available from the
[maintainer's R-universe repository](https://jeroen.r-universe.dev/openssl),
which CI already uses. The runner installs this checkout in a private library
under `.artifacts/` and uses that installation in the main process and mirai
workers. It requires zero test failures, errors, warnings or skips.

Each run writes a sanitized `evidence.json` with its checkout revision, dirty
flag, dependency versions, package-installation check and assertion counts.
CI uploads only those JSON files. Libraries and installation logs stay private.
Set `SHINYOAUTH_CONFORMANCE_ARTIFACTS` to move local artifacts, for example when
a deeply nested Windows checkout would exceed path limits. Reports keep
`coverage_complete = false`: these fixtures do not establish OpenID certification.

The fixture uses Python cryptography, independent of shinyOAuth and R's jose,
to enforce RS256 and RS384 Request Object signatures, issuer, audience, expiry, replay,
and mandatory signing. It completes JAR+DPoP (with and without PAR), JAR+mTLS
(with and without PAR), and JAR+signed-JARM authorization-code exchanges over
local TLS. DPoP proofs are verified against the signed Request Object's key
thumbprint; mTLS authenticates an actual TLS peer certificate. PKCE is checked
before issuing an access token. All keys and certificates are temporary.

Authorization requests must include an outer `client_id` matching the registered
client and signed Request Object, as required by
[RFC 9101 sections 5 and 6.3](https://www.rfc-editor.org/rfc/rfc9101.html#section-5)
and [RFC 9126 section 4](https://www.rfc-editor.org/rfc/rfc9126.html#section-4).
Fresh valid requests test missing, empty and mismatched outer IDs over both GET
and POST, with direct JAR and PAR references. Invalid outer IDs do not consume a
PAR handle; a subsequent correctly bound request succeeds and replay is rejected.

The same independent fixture verifies RS256 and RS384 client assertions for both legacy
endpoint-audience/`JWT` and issuer-audience/`client-authentication+jwt` profiles.
Each profile completes code and refresh exchanges, introspection and revocation,
with and without PAR; PAR retains its issuer-audience behavior in both profiles.
Assertions must have fresh IDs and valid signatures, lifetimes and client
identifiers, with no competing client authentication. The newer configuration
passes `check_oauth21()`'s mandatory configuration checks before exchange; the
legacy profile remains usable while its audience receives a draft finding.
Requests explicitly select the default TLS 1.2 minimum and use a local custom CA.

`test-mtls-resource.R` adds a protected resource that binds each opaque token
to the actual TLS certificate observed at issuance. Two certificates have valid
chains and identical subject names, and both may obtain their own tokens. Each
token still requires its particular certificate at the resource, independent
of forwarded certificate headers and any client-visible `cnf` field.

The resource tests complete 32 bound grants across RS256/RS384, direct JAR/PAR,
sync/mirai callbacks, returned/omitted `cnf` confirmation, and both certificates.
They use private-key-JWT client authentication, reference state and the public
module and connection APIs. Audit checks require exactly one token exchange
in the expected process, loaded from the same private package installation.
Authorization/PAR setup and resource requests run in the main process; mirai
coverage here applies to the token callback. Shiny sessions are driven in
process, without a browser or an interactive provider login.

Attacker requests bypass the client's local binding checks and reach the actual
TLS server. Wrong certificates, missing certificates, forged certificate
headers, unknown tokens and unbound tokens must receive HTTP 401 with
`invalid_token`, a Bearer challenge and no resource content. This follows
[RFC 8705 section 3](https://www.rfc-editor.org/rfc/rfc8705.html#section-3).
The tests require 162 denial responses and verify that the rightful holder can
still use the public connection afterward. They also confirm that a misleading
certificate header cannot prevent access by the matching TLS peer. The bound
resource profile does not implement refresh.

For omitted confirmation, the client explicitly selects
`mtls_require_observed_cnf = FALSE`; the resource still checks its server-side
issuance record. This complements the
[OIDF mTLS selection](../openid/README.md), whose pinned provider detects a
certificate mismatch but continues to return its resource body. The independent
check does not alter that provider or its incomplete coverage status.

Each algorithm runs the full flow matrix with a separately pinned server
registration. JARM responses and the server's public JWKS use the selected
algorithm too, exercising Python signing followed by shinyOAuth verification.
Every successful combination runs with both GET and explicitly selected POST
authorization. POST uses `prepare_authorization_request()` and real form-encoded
HTTP over TLS; the independent server reports the received method and verifies
the same signatures and transaction claims. Browser form submission itself is
covered by the [SMART and ordinary OAuth browser gates](../smart/authorization-post.md).

`test-rs384-interop.R` adds cross-language cryptographic checks using a separate
Python process and temporary 2048- and 3072-bit RSA keys:

- Client assertions, Request Objects and DPoP proofs must verify as SHA-384 with
  PKCS#1 v1.5 padding and match Python's signature bytes over the original JWS
  signing input. SHA-256, SHA-512, PSS padding, different keys, and modified
  headers, payloads and signatures must fail verification.
- Python independently generates ID tokens and public JWKs. shinyOAuth must
  accept the valid RS384 token and reject signatures using a different digest,
  padding or key, changed signed content, and changed or truncated signatures.
  Only JWKS retrieval is substituted; key selection and validation run normally.
- OIDC `at_hash` uses the left half of SHA-384, while DPoP `ath` still uses
  SHA-256. A correctly signed ID token containing a SHA-256 `at_hash` is rejected.

These expectations follow [RFC 7518 section 3.3](https://www.rfc-editor.org/rfc/rfc7518.html#section-3.3),
[OIDC Core section 3.1.3.6](https://openid.net/specs/openid-connect-core-1_0.html#CodeIDToken),
and [RFC 9449 section 4.2](https://www.rfc-editor.org/rfc/rfc9449.html#section-4.2).
Python cryptography and R's bindings may share OpenSSL as their underlying
cryptographic backend. The runner requires zero skips and CI already runs this
directory. Set `SHINYOAUTH_TEST_PYTHON` to a Python executable if it is not on `PATH`.

These are focused protocol tests, not OpenID certification or evidence that a
third-party server enforces these policies. The live AS fixture omits user login, ID
tokens, consent and discovery; its resource endpoint covers only the mTLS token
binding profile above. Keycloak's separate tests
record its actual capabilities and known claim-validation gaps. Its rejection
canaries must not be counted as successful combination interoperability.

For SMART App Launch P4/P5, the [Inferno STU2.2 Client gate](../smart/inferno.md)
adds independent client-request verification, including RS384 and ES384 profiles.
That gate is implemented with two explicit simulator corrections and unchanged
upstream verification tests. It complements these cryptographic tests and the
[Launcher v2 sandbox](../smart/sandbox.md); it is not an unmodified vendor pass.
