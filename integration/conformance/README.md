# Independent protocol fixture

Run from the repository root:

```sh
python -m pip install -r integration/conformance/requirements.txt
Rscript integration/conformance/run-tests.R
```

The fixture uses Python cryptography, independent of shinyOAuth and R's jose,
to enforce RS256 and RS384 Request Object signatures, issuer, audience, expiry, replay,
and mandatory signing. It completes JAR+DPoP (with and without PAR), JAR+mTLS
(with and without PAR), and JAR+signed-JARM authorization-code exchanges over
local TLS. DPoP proofs are verified against the signed Request Object's key
thumbprint; mTLS authenticates an actual TLS peer certificate. PKCE is checked
before issuing an access token. All keys and certificates are temporary.

The same independent fixture verifies RS256 and RS384 client assertions for both legacy
endpoint-audience/`JWT` and issuer-audience/`client-authentication+jwt` profiles.
Each profile completes code and refresh exchanges, introspection and revocation,
with and without PAR; PAR retains its issuer-audience behavior in both profiles.
Assertions must have fresh IDs and valid signatures, lifetimes and client
identifiers, with no competing client authentication. The newer configuration
passes `check_oauth21()`'s mandatory configuration checks before exchange; the
legacy profile remains usable while its audience receives a draft finding.
Requests select the optional TLS 1.2 minimum and use a local custom CA.

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
tokens, consent, discovery and resource endpoints. Keycloak's separate tests
record its actual capabilities and known claim-validation gaps. Its rejection
canaries must not be counted as successful combination interoperability.

For SMART App Launch P4/P5, the [Inferno STU2.2 Client gate](../smart/inferno.md)
adds independent client-request verification, including RS384 and ES384 profiles.
That gate is implemented with two explicit simulator corrections and unchanged
upstream verification tests. It complements these cryptographic tests and the
[Launcher v2 sandbox](../smart/sandbox.md); it is not an unmodified vendor pass.
